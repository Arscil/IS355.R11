// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "./BillOfLadingNFT.sol";

/**
 * @title TradeFinanceLC
 * @dev Decentralized Letter of Credit (L/C) management contract for 4-party Trade Finance.
 *
 * Constraint techniques:
 *  - Role-based access control (AccessControl) + per-L/C party assignment checks.
 *  - Finite state machine enforced by the `inState` modifier.
 *  - Token escrow: funds can only leave the contract to the Exporter (payment) or back to the Importer (refund).
 *  - Time constraints: presentation deadline and a 5-day document examination period (UCP 600, Art. 14(b)).
 *  - On-chain document matching: SHA-256 hashes re-computed by the Advising Bank must equal the presented hashes;
 *    the invoice amount must equal the L/C amount.
 *  - ReentrancyGuard + SafeERC20 on every function that moves value.
 */
contract TradeFinanceLC is AccessControl, ReentrancyGuard, IERC721Receiver {
    using SafeERC20 for IERC20;

    // -------------------------------------------------------------
    // ROLES & CONSTANTS
    // -------------------------------------------------------------
    bytes32 public constant IMPORTER_ROLE = keccak256("IMPORTER_ROLE");
    bytes32 public constant ISSUING_BANK_ROLE = keccak256("ISSUING_BANK_ROLE");
    bytes32 public constant EXPORTER_ROLE = keccak256("EXPORTER_ROLE");
    bytes32 public constant ADVISING_BANK_ROLE = keccak256("ADVISING_BANK_ROLE");

    /// @notice Time the Advising Bank has to examine presented documents (UCP 600: max. 5 banking days).
    uint256 public constant EXAMINATION_PERIOD = 5 days;

    uint8 public constant DOC_BILL_OF_LADING = 0;
    uint8 public constant DOC_COMMERCIAL_INVOICE = 1;
    uint8 public constant DOC_CERTIFICATE_OF_ORIGIN = 2;

    // -------------------------------------------------------------
    // ENUMS & STRUCTS
    // -------------------------------------------------------------
    enum LCState {
        Created,    // 0: Importer opened L/C, awaiting Issuing Bank approval
        Issued,     // 1: Issuing Bank approved and funds escrowed
        Shipped,    // 2: Exporter presented documents and eBL NFT minted into escrow
        Paid,       // 3: Documents honoured, payment released and title transferred
        Closed,     // 4: Finalized L/C lifecycle
        Rejected,   // 5: Issuing Bank rejected application
        Cancelled   // 6: Importer cancelled expired L/C with refunded funds
    }

    struct LetterOfCredit {
        uint256 id;
        address importer;
        address issuingBank;
        address exporter;
        address advisingBank;
        uint256 amount;
        uint256 deadline;          // Latest date for document presentation
        LCState state;
        string encryptedTerms;     // AES-GCM ciphertext (or hash) of confidential L/C terms
        string[3] docCIDs;         // IPFS CIDs: [0]=Bill of Lading, [1]=Commercial Invoice, [2]=Certificate of Origin
        bytes32[3] docHashes;      // SHA-256 hashes of the original (plaintext) files
        uint256 invoiceAmount;     // Amount stated on the commercial invoice
        uint256 submittedAt;       // Timestamp of the latest presentation (starts the examination period)
        uint256 blNftId;           // Token ID of the eBL NFT (0 = none)
        uint256 discrepancyCount;  // Number of times documents were refused
        string rejectReason;       // Reason if rejected by Issuing Bank
        string discrepancyNote;    // Latest discrepancy note from Advising Bank
    }

    // -------------------------------------------------------------
    // STATE VARIABLES
    // -------------------------------------------------------------
    IERC20 public immutable stableToken;
    BillOfLadingNFT public immutable blNFT;

    uint256 private _lcCounter;
    mapping(uint256 => LetterOfCredit) private _lcs;
    mapping(address => uint256[]) private _partyLCs;

    // -------------------------------------------------------------
    // EVENTS
    // -------------------------------------------------------------
    event LCOpened(
        uint256 indexed lcId,
        address indexed importer,
        address indexed exporter,
        address issuingBank,
        address advisingBank,
        uint256 amount,
        uint256 deadline
    );

    event LCIssued(uint256 indexed lcId, address indexed issuingBank, uint256 escrowedAmount);

    event LCRejected(uint256 indexed lcId, address indexed issuingBank, string reason);

    event LCDocumentsSubmitted(
        uint256 indexed lcId,
        address indexed exporter,
        uint256 blNftId,
        string[3] docCIDs,
        bytes32[3] docHashes,
        uint256 invoiceAmount
    );

    event LCDiscrepancyReported(
        uint256 indexed lcId,
        address indexed advisingBank,
        string note,
        uint256 discrepancyCount
    );

    event LCPaymentExecuted(
        uint256 indexed lcId,
        address indexed triggeredBy,
        address indexed exporter,
        uint256 amount,
        uint256 blNftId,
        address importer
    );

    event LCCancelled(uint256 indexed lcId, address indexed importer, uint256 refundedAmount);

    event LCClosed(uint256 indexed lcId);

    // -------------------------------------------------------------
    // MODIFIERS
    // -------------------------------------------------------------
    modifier inState(uint256 lcId, LCState expectedState) {
        require(_lcs[lcId].id != 0, "LC does not exist");
        require(_lcs[lcId].state == expectedState, "Invalid LC state for this action");
        _;
    }

    modifier beforeDeadline(uint256 lcId) {
        require(block.timestamp <= _lcs[lcId].deadline, "LC deadline has expired");
        _;
    }

    modifier afterDeadline(uint256 lcId) {
        require(block.timestamp > _lcs[lcId].deadline, "LC deadline has not expired yet");
        _;
    }

    // -------------------------------------------------------------
    // CONSTRUCTOR
    // -------------------------------------------------------------
    constructor(address _stableTokenAddress, address _blNFTAddress) {
        require(_stableTokenAddress != address(0), "Invalid stableToken address");
        require(_blNFTAddress != address(0), "Invalid blNFT address");

        stableToken = IERC20(_stableTokenAddress);
        blNFT = BillOfLadingNFT(_blNFTAddress);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    // -------------------------------------------------------------
    // BUSINESS LOGIC FUNCTIONS
    // -------------------------------------------------------------

    /**
     * @dev Step 1: Importer creates a new Letter of Credit request.
     * @param issuingBank Designated Issuing Bank address.
     * @param exporter Designated Exporter address.
     * @param advisingBank Designated Advising Bank address.
     * @param amount Token amount to be escrowed and paid upon complying presentation.
     * @param deadline Unix timestamp for document presentation deadline.
     * @param encryptedTerms AES-GCM ciphertext representing confidential agreement terms.
     */
    function openLC(
        address issuingBank,
        address exporter,
        address advisingBank,
        uint256 amount,
        uint256 deadline,
        string calldata encryptedTerms
    ) external onlyRole(IMPORTER_ROLE) returns (uint256) {
        require(amount > 0, "LC amount must be greater than zero");
        require(deadline > block.timestamp, "Deadline must be in the future");
        require(issuingBank != address(0), "Invalid issuing bank");
        require(exporter != address(0), "Invalid exporter");
        require(advisingBank != address(0), "Invalid advising bank");
        require(exporter != msg.sender, "Importer and Exporter must differ");
        require(hasRole(ISSUING_BANK_ROLE, issuingBank), "Target is not an Issuing Bank");
        require(hasRole(EXPORTER_ROLE, exporter), "Target is not an Exporter");
        require(hasRole(ADVISING_BANK_ROLE, advisingBank), "Target is not an Advising Bank");
        require(bytes(encryptedTerms).length > 0, "Encrypted terms required");

        uint256 lcId = ++_lcCounter;

        LetterOfCredit storage lc = _lcs[lcId];
        lc.id = lcId;
        lc.importer = msg.sender;
        lc.issuingBank = issuingBank;
        lc.exporter = exporter;
        lc.advisingBank = advisingBank;
        lc.amount = amount;
        lc.deadline = deadline;
        lc.state = LCState.Created;
        lc.encryptedTerms = encryptedTerms;

        _partyLCs[msg.sender].push(lcId);
        _partyLCs[issuingBank].push(lcId);
        _partyLCs[exporter].push(lcId);
        if (advisingBank != issuingBank) {
            _partyLCs[advisingBank].push(lcId);
        }

        emit LCOpened(lcId, msg.sender, exporter, issuingBank, advisingBank, amount, deadline);

        return lcId;
    }

    /**
     * @dev Step 2a: Issuing Bank approves the L/C, locking Importer's funds into escrow.
     * Importer must have pre-approved this contract to transfer `lc.amount` of stableToken.
     */
    function approveLC(uint256 lcId)
        external
        onlyRole(ISSUING_BANK_ROLE)
        inState(lcId, LCState.Created)
        nonReentrant
    {
        LetterOfCredit storage lc = _lcs[lcId];
        require(lc.issuingBank == msg.sender, "Caller is not assigned Issuing Bank for this LC");
        require(block.timestamp <= lc.deadline, "LC deadline has expired");
        require(stableToken.balanceOf(lc.importer) >= lc.amount, "Importer balance insufficient");
        require(
            stableToken.allowance(lc.importer, address(this)) >= lc.amount,
            "Importer allowance insufficient"
        );

        lc.state = LCState.Issued;

        // Escrow funds: pull stableToken from Importer into this contract
        stableToken.safeTransferFrom(lc.importer, address(this), lc.amount);

        emit LCIssued(lcId, msg.sender, lc.amount);
    }

    /**
     * @dev Step 2b: Issuing Bank rejects the L/C application.
     */
    function rejectLC(uint256 lcId, string calldata reason)
        external
        onlyRole(ISSUING_BANK_ROLE)
        inState(lcId, LCState.Created)
    {
        LetterOfCredit storage lc = _lcs[lcId];
        require(lc.issuingBank == msg.sender, "Caller is not assigned Issuing Bank for this LC");
        require(bytes(reason).length > 0, "Reject reason required");

        lc.state = LCState.Rejected;
        lc.rejectReason = reason;

        emit LCRejected(lcId, msg.sender, reason);
    }

    /**
     * @dev Step 3: Exporter ships goods, uploads 3 documents to IPFS, and presents CIDs and hashes.
     * A Bill of Lading NFT is minted into escrow (held by this contract).
     * @param docCIDs IPFS CIDs [0]=B/L, [1]=Invoice, [2]=C/O.
     * @param docHashes SHA-256 hashes of the original (plaintext) documents.
     * @param invoiceAmount Amount on the commercial invoice; must equal the L/C amount.
     * @param blTokenURI IPFS URI containing metadata for the eBL NFT.
     */
    function submitDocuments(
        uint256 lcId,
        string[3] calldata docCIDs,
        bytes32[3] calldata docHashes,
        uint256 invoiceAmount,
        string calldata blTokenURI
    )
        external
        onlyRole(EXPORTER_ROLE)
        inState(lcId, LCState.Issued)
        beforeDeadline(lcId)
        nonReentrant
    {
        LetterOfCredit storage lc = _lcs[lcId];
        require(lc.exporter == msg.sender, "Caller is not assigned Exporter for this LC");

        require(bytes(docCIDs[0]).length > 0, "Missing B/L CID");
        require(bytes(docCIDs[1]).length > 0, "Missing Invoice CID");
        require(bytes(docCIDs[2]).length > 0, "Missing C/O CID");

        require(docHashes[0] != bytes32(0), "Missing B/L hash");
        require(docHashes[1] != bytes32(0), "Missing Invoice hash");
        require(docHashes[2] != bytes32(0), "Missing C/O hash");

        require(invoiceAmount == lc.amount, "Invoice amount does not match LC amount");
        require(bytes(blTokenURI).length > 0, "Missing eBL metadata URI");

        for (uint256 i = 0; i < 3; i++) {
            lc.docCIDs[i] = docCIDs[i];
            lc.docHashes[i] = docHashes[i];
        }
        lc.invoiceAmount = invoiceAmount;
        lc.submittedAt = block.timestamp;
        lc.state = LCState.Shipped;

        // Mint Bill of Lading NFT to this contract as escrow custodian
        uint256 tokenId = blNFT.mintBL(address(this), blTokenURI);
        lc.blNftId = tokenId;

        emit LCDocumentsSubmitted(lcId, msg.sender, tokenId, docCIDs, docHashes, invoiceAmount);
    }

    /**
     * @dev Step 4a: Advising Bank re-computes SHA-256 of the files retrieved from IPFS and submits them.
     * Payment is released only if every hash matches the presented hash (complying presentation).
     * Releases escrowed tokens to Exporter and transfers eBL NFT ownership to Importer (Title Transfer).
     * @param verifiedHashes Hashes computed by the Advising Bank from the decrypted IPFS files.
     */
    function executePayment(uint256 lcId, bytes32[3] calldata verifiedHashes)
        external
        onlyRole(ADVISING_BANK_ROLE)
        inState(lcId, LCState.Shipped)
        nonReentrant
    {
        LetterOfCredit storage lc = _lcs[lcId];
        require(lc.advisingBank == msg.sender, "Caller is not assigned Advising Bank for this LC");

        require(verifiedHashes[0] == lc.docHashes[0], "B/L hash mismatch");
        require(verifiedHashes[1] == lc.docHashes[1], "Invoice hash mismatch");
        require(verifiedHashes[2] == lc.docHashes[2], "C/O hash mismatch");

        _settle(lc);
    }

    /**
     * @dev Step 4b: Advising Bank refuses the presentation because of discrepancies.
     * Must be done within the examination period. The escrowed eBL is burned, the L/C returns to `Issued`
     * and the Exporter may re-present corrected documents before the deadline.
     * @param note Description of the discrepancies found.
     */
    function reportDiscrepancy(uint256 lcId, string calldata note)
        external
        onlyRole(ADVISING_BANK_ROLE)
        inState(lcId, LCState.Shipped)
        nonReentrant
    {
        LetterOfCredit storage lc = _lcs[lcId];
        require(lc.advisingBank == msg.sender, "Caller is not assigned Advising Bank for this LC");
        require(bytes(note).length > 0, "Discrepancy note required");
        require(
            block.timestamp <= lc.submittedAt + EXAMINATION_PERIOD,
            "Examination period has ended"
        );

        uint256 tokenId = lc.blNftId;

        lc.state = LCState.Issued;
        lc.discrepancyCount += 1;
        lc.discrepancyNote = note;
        lc.blNftId = 0;
        lc.invoiceAmount = 0;
        lc.submittedAt = 0;
        for (uint256 i = 0; i < 3; i++) {
            delete lc.docCIDs[i];
            delete lc.docHashes[i];
        }

        blNFT.burnBL(tokenId);

        emit LCDiscrepancyReported(lcId, msg.sender, note, lc.discrepancyCount);
    }

    /**
     * @dev Step 4c: If the Advising Bank neither pays nor refuses within the examination period,
     * the bank is precluded from claiming discrepancies (UCP 600, Art. 16(f)) and the Exporter may
     * claim payment. Prevents funds from being locked forever in escrow.
     */
    function claimPaymentAfterExamination(uint256 lcId)
        external
        onlyRole(EXPORTER_ROLE)
        inState(lcId, LCState.Shipped)
        nonReentrant
    {
        LetterOfCredit storage lc = _lcs[lcId];
        require(lc.exporter == msg.sender, "Caller is not assigned Exporter for this LC");
        require(
            block.timestamp > lc.submittedAt + EXAMINATION_PERIOD,
            "Examination period not ended"
        );

        _settle(lc);
    }

    /**
     * @dev Fallback branch: Importer cancels L/C if Exporter failed to present complying documents
     * before the deadline. Escrowed tokens are refunded to Importer.
     */
    function cancelLC(uint256 lcId)
        external
        onlyRole(IMPORTER_ROLE)
        inState(lcId, LCState.Issued)
        afterDeadline(lcId)
        nonReentrant
    {
        LetterOfCredit storage lc = _lcs[lcId];
        require(lc.importer == msg.sender, "Caller is not the Importer of this LC");

        lc.state = LCState.Cancelled;

        stableToken.safeTransfer(lc.importer, lc.amount);

        emit LCCancelled(lcId, msg.sender, lc.amount);
    }

    /**
     * @dev Step 5: Close L/C after settlement. Any party of the L/C or the admin may close it.
     */
    function closeLC(uint256 lcId) external inState(lcId, LCState.Paid) {
        LetterOfCredit storage lc = _lcs[lcId];
        require(
            _isParty(lc, msg.sender) || hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "Not authorized to close LC"
        );

        lc.state = LCState.Closed;

        emit LCClosed(lcId);
    }

    // -------------------------------------------------------------
    // INTERNAL
    // -------------------------------------------------------------
    function _settle(LetterOfCredit storage lc) private {
        lc.state = LCState.Paid;

        // 1. Release token payment to Exporter
        stableToken.safeTransfer(lc.exporter, lc.amount);

        // 2. Transfer eBL NFT title to Importer
        blNFT.safeTransferFrom(address(this), lc.importer, lc.blNftId);

        emit LCPaymentExecuted(lc.id, msg.sender, lc.exporter, lc.amount, lc.blNftId, lc.importer);
    }

    function _isParty(LetterOfCredit storage lc, address account) private view returns (bool) {
        return account == lc.importer ||
            account == lc.issuingBank ||
            account == lc.exporter ||
            account == lc.advisingBank;
    }

    // -------------------------------------------------------------
    // VIEW FUNCTIONS
    // -------------------------------------------------------------

    /// @dev Retrieve all fields of a specific L/C.
    function getLC(uint256 lcId) external view returns (LetterOfCredit memory) {
        require(_lcs[lcId].id != 0, "LC does not exist");
        return _lcs[lcId];
    }

    /// @dev Retrieve presented document CIDs and hashes.
    function getLCDocuments(uint256 lcId)
        external
        view
        returns (string[3] memory docCIDs, bytes32[3] memory docHashes)
    {
        require(_lcs[lcId].id != 0, "LC does not exist");
        return (_lcs[lcId].docCIDs, _lcs[lcId].docHashes);
    }

    /// @dev IDs of all L/Cs in which `party` is Importer, Exporter, Issuing Bank or Advising Bank.
    function getLCsByParty(address party) external view returns (uint256[] memory) {
        return _partyLCs[party];
    }

    /// @dev Whether `account` is one of the four parties of the L/C (used for IPFS RBAC off-chain).
    function isParty(uint256 lcId, address account) external view returns (bool) {
        require(_lcs[lcId].id != 0, "LC does not exist");
        return _isParty(_lcs[lcId], account);
    }

    /// @dev Timestamp after which the examination period of the current presentation ends (0 if none).
    function examinationDeadline(uint256 lcId) external view returns (uint256) {
        require(_lcs[lcId].id != 0, "LC does not exist");
        uint256 submittedAt = _lcs[lcId].submittedAt;
        return submittedAt == 0 ? 0 : submittedAt + EXAMINATION_PERIOD;
    }

    /// @dev Total number of L/Cs created.
    function getLCCount() external view returns (uint256) {
        return _lcCounter;
    }

    /// @dev Only accept eBL NFTs minted by the configured BillOfLadingNFT contract.
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external view override returns (bytes4) {
        require(msg.sender == address(blNFT), "Unsupported NFT");
        return this.onERC721Received.selector;
    }
}
