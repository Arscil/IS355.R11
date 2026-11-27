const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

const State = {
  Created: 0,
  Issued: 1,
  Shipped: 2,
  Paid: 3,
  Closed: 4,
  Rejected: 5,
  Cancelled: 6,
};

const DAY = 24 * 3600;

describe("Trade Finance L/C System - Complete Lifecycle & Security Tests", function () {
  let stableToken, blNFT, tradeFinanceLC, lcAddress;
  let admin, importer, issuingBank, exporter, advisingBank, unauthorizedUser;

  const IMPORTER_ROLE = ethers.id("IMPORTER_ROLE");
  const ISSUING_BANK_ROLE = ethers.id("ISSUING_BANK_ROLE");
  const EXPORTER_ROLE = ethers.id("EXPORTER_ROLE");
  const ADVISING_BANK_ROLE = ethers.id("ADVISING_BANK_ROLE");
  const MINTER_ROLE = ethers.id("MINTER_ROLE");

  const LC_AMOUNT = ethers.parseEther("50000"); // 50,000 TFUSD
  const INITIAL_IMPORTER_BALANCE = ethers.parseEther("100000");

  const sampleDocCIDs = [
    "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco", // Bill of Lading
    "QmZ4tDuvesekSs4qM5ZBKpXiZGun7S2CYtEZRB3DYXkjGx", // Commercial Invoice
    "QmPZ9qBzzyAtRaQQQUZrJ2D1GvF2XjV3VzC5K6L9P2M4A1", // Certificate of Origin
  ];

  // SHA-256 of the original (plaintext) files, as the off-chain app computes them
  const sampleDocHashes = [
    ethers.sha256(ethers.toUtf8Bytes("BILL_OF_LADING_PDF_CONTENT")),
    ethers.sha256(ethers.toUtf8Bytes("COMMERCIAL_INVOICE_PDF_CONTENT")),
    ethers.sha256(ethers.toUtf8Bytes("CERTIFICATE_OF_ORIGIN_PDF_CONTENT")),
  ];

  const blTokenURI = "ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG/bl_metadata.json";
  const encryptedTerms = "AES_GCM_ENCRYPTED_PAYLOAD_TERMS_AND_SPECIFICATIONS_DEMO";

  // ---------------------------------------------------------------- helpers
  async function openLC(deadlineOffset = 7 * DAY, amount = LC_AMOUNT) {
    const deadline = (await time.latest()) + deadlineOffset;
    await tradeFinanceLC
      .connect(importer)
      .openLC(issuingBank.address, exporter.address, advisingBank.address, amount, deadline, encryptedTerms);
    return { id: await tradeFinanceLC.getLCCount(), deadline };
  }

  async function openAndIssue(deadlineOffset) {
    const lc = await openLC(deadlineOffset);
    await tradeFinanceLC.connect(issuingBank).approveLC(lc.id);
    return lc;
  }

  async function openIssueAndShip(deadlineOffset) {
    const lc = await openAndIssue(deadlineOffset);
    await tradeFinanceLC
      .connect(exporter)
      .submitDocuments(lc.id, sampleDocCIDs, sampleDocHashes, LC_AMOUNT, blTokenURI);
    return lc;
  }

  beforeEach(async function () {
    [admin, importer, issuingBank, exporter, advisingBank, unauthorizedUser] = await ethers.getSigners();

    stableToken = await (await ethers.getContractFactory("StableToken")).deploy();
    blNFT = await (await ethers.getContractFactory("BillOfLadingNFT")).deploy();
    tradeFinanceLC = await (await ethers.getContractFactory("TradeFinanceLC")).deploy(
      await stableToken.getAddress(),
      await blNFT.getAddress()
    );
    lcAddress = await tradeFinanceLC.getAddress();

    // Only the L/C contract may mint/burn eBL NFTs
    await blNFT.grantRole(MINTER_ROLE, lcAddress);
    await blNFT.revokeRole(MINTER_ROLE, admin.address);

    await tradeFinanceLC.grantRole(IMPORTER_ROLE, importer.address);
    await tradeFinanceLC.grantRole(ISSUING_BANK_ROLE, issuingBank.address);
    await tradeFinanceLC.grantRole(EXPORTER_ROLE, exporter.address);
    await tradeFinanceLC.grantRole(ADVISING_BANK_ROLE, advisingBank.address);

    await stableToken.mint(importer.address, INITIAL_IMPORTER_BALANCE);
    await stableToken.connect(importer).approve(lcAddress, ethers.MaxUint256);
  });

  // ======================================================================
  describe("1. Deployment & Roles Configuration", function () {
    it("should set correct token addresses and initial admin", async function () {
      expect(await tradeFinanceLC.stableToken()).to.equal(await stableToken.getAddress());
      expect(await tradeFinanceLC.blNFT()).to.equal(await blNFT.getAddress());
      expect(await tradeFinanceLC.hasRole(await tradeFinanceLC.DEFAULT_ADMIN_ROLE(), admin.address)).to.be.true;
      expect(await tradeFinanceLC.EXAMINATION_PERIOD()).to.equal(5 * DAY);
    });

    it("should grant appropriate operational roles to parties", async function () {
      expect(await tradeFinanceLC.hasRole(IMPORTER_ROLE, importer.address)).to.be.true;
      expect(await tradeFinanceLC.hasRole(ISSUING_BANK_ROLE, issuingBank.address)).to.be.true;
      expect(await tradeFinanceLC.hasRole(EXPORTER_ROLE, exporter.address)).to.be.true;
      expect(await tradeFinanceLC.hasRole(ADVISING_BANK_ROLE, advisingBank.address)).to.be.true;
      expect(await tradeFinanceLC.hasRole(IMPORTER_ROLE, unauthorizedUser.address)).to.be.false;
    });

    it("should give MINTER_ROLE of the eBL NFT only to the L/C contract", async function () {
      expect(await blNFT.hasRole(MINTER_ROLE, lcAddress)).to.be.true;
      expect(await blNFT.hasRole(MINTER_ROLE, admin.address)).to.be.false;
      await expect(blNFT.mintBL(admin.address, "ipfs://fake")).to.be.revertedWithCustomError(
        blNFT,
        "AccessControlUnauthorizedAccount"
      );
    });

    it("should reject zero addresses in the constructor", async function () {
      const F = await ethers.getContractFactory("TradeFinanceLC");
      await expect(F.deploy(ethers.ZeroAddress, await blNFT.getAddress())).to.be.revertedWith(
        "Invalid stableToken address"
      );
      await expect(F.deploy(await stableToken.getAddress(), ethers.ZeroAddress)).to.be.revertedWith(
        "Invalid blNFT address"
      );
    });

    it("should support ERC721 / AccessControl interfaces on the NFT", async function () {
      expect(await blNFT.supportsInterface("0x80ac58cd")).to.be.true; // ERC721
      expect(await blNFT.supportsInterface("0x7965db0b")).to.be.true; // AccessControl
    });
  });

  // ======================================================================
  describe("2. Happy Path - Complete L/C Lifecycle", function () {
    it("should execute full lifecycle: open -> approve -> present docs -> verify & pay -> close", async function () {
      const deadline = (await time.latest()) + 7 * DAY;

      // Step 1: Open L/C
      await expect(
        tradeFinanceLC
          .connect(importer)
          .openLC(issuingBank.address, exporter.address, advisingBank.address, LC_AMOUNT, deadline, encryptedTerms)
      )
        .to.emit(tradeFinanceLC, "LCOpened")
        .withArgs(1, importer.address, exporter.address, issuingBank.address, advisingBank.address, LC_AMOUNT, deadline);

      let lc = await tradeFinanceLC.getLC(1);
      expect(lc.state).to.equal(State.Created);
      expect(lc.encryptedTerms).to.equal(encryptedTerms);

      // Step 2: Issuing Bank approves -> tokens escrowed
      await expect(tradeFinanceLC.connect(issuingBank).approveLC(1))
        .to.emit(tradeFinanceLC, "LCIssued")
        .withArgs(1, issuingBank.address, LC_AMOUNT);
      expect(await stableToken.balanceOf(lcAddress)).to.equal(LC_AMOUNT);
      expect(await stableToken.balanceOf(importer.address)).to.equal(INITIAL_IMPORTER_BALANCE - LC_AMOUNT);
      expect((await tradeFinanceLC.getLC(1)).state).to.equal(State.Issued);

      // Step 3: Exporter presents 3 documents -> eBL minted into escrow
      await expect(
        tradeFinanceLC.connect(exporter).submitDocuments(1, sampleDocCIDs, sampleDocHashes, LC_AMOUNT, blTokenURI)
      )
        .to.emit(tradeFinanceLC, "LCDocumentsSubmitted")
        .withArgs(1, exporter.address, 1, sampleDocCIDs, sampleDocHashes, LC_AMOUNT);

      lc = await tradeFinanceLC.getLC(1);
      expect(lc.state).to.equal(State.Shipped);
      expect(lc.blNftId).to.equal(1);
      expect(lc.invoiceAmount).to.equal(LC_AMOUNT);
      expect(await tradeFinanceLC.examinationDeadline(1)).to.equal(lc.submittedAt + BigInt(5 * DAY));
      expect(await blNFT.ownerOf(1)).to.equal(lcAddress);
      expect(await blNFT.tokenURI(1)).to.equal(blTokenURI);

      const [storedCIDs, storedHashes] = await tradeFinanceLC.getLCDocuments(1);
      expect(storedCIDs).to.deep.equal(sampleDocCIDs);
      expect(storedHashes).to.deep.equal(sampleDocHashes);

      // Step 4: Advising Bank re-computes hashes from IPFS files and settles
      await expect(tradeFinanceLC.connect(advisingBank).executePayment(1, sampleDocHashes))
        .to.emit(tradeFinanceLC, "LCPaymentExecuted")
        .withArgs(1, advisingBank.address, exporter.address, LC_AMOUNT, 1, importer.address);

      expect(await stableToken.balanceOf(exporter.address)).to.equal(LC_AMOUNT);
      expect(await stableToken.balanceOf(lcAddress)).to.equal(0);
      expect(await blNFT.ownerOf(1)).to.equal(importer.address); // Title transfer
      expect((await tradeFinanceLC.getLC(1)).state).to.equal(State.Paid);

      // Step 5: Close
      await expect(tradeFinanceLC.connect(importer).closeLC(1)).to.emit(tradeFinanceLC, "LCClosed").withArgs(1);
      expect((await tradeFinanceLC.getLC(1)).state).to.equal(State.Closed);
    });

    it("should index L/Cs by party for dashboards", async function () {
      await openLC();
      await openLC();
      expect(await tradeFinanceLC.getLCsByParty(importer.address)).to.deep.equal([1n, 2n]);
      expect(await tradeFinanceLC.getLCsByParty(issuingBank.address)).to.deep.equal([1n, 2n]);
      expect(await tradeFinanceLC.getLCsByParty(exporter.address)).to.deep.equal([1n, 2n]);
      expect(await tradeFinanceLC.getLCsByParty(advisingBank.address)).to.deep.equal([1n, 2n]);
      expect(await tradeFinanceLC.getLCsByParty(unauthorizedUser.address)).to.deep.equal([]);

      expect(await tradeFinanceLC.isParty(1, exporter.address)).to.be.true;
      expect(await tradeFinanceLC.isParty(1, unauthorizedUser.address)).to.be.false;
      expect(await tradeFinanceLC.examinationDeadline(1)).to.equal(0);
    });

    it("should not duplicate the index when one bank is both issuing and advising", async function () {
      await tradeFinanceLC.grantRole(ADVISING_BANK_ROLE, issuingBank.address);
      const deadline = (await time.latest()) + DAY;
      await tradeFinanceLC
        .connect(importer)
        .openLC(issuingBank.address, exporter.address, issuingBank.address, LC_AMOUNT, deadline, encryptedTerms);
      expect(await tradeFinanceLC.getLCsByParty(issuingBank.address)).to.deep.equal([1n]);
    });

    it("should allow any party or admin to close a paid L/C, but not outsiders", async function () {
      const { id } = await openIssueAndShip();
      await tradeFinanceLC.connect(advisingBank).executePayment(id, sampleDocHashes);

      await expect(tradeFinanceLC.connect(unauthorizedUser).closeLC(id)).to.be.revertedWith(
        "Not authorized to close LC"
      );
      await expect(tradeFinanceLC.connect(admin).closeLC(id)).to.emit(tradeFinanceLC, "LCClosed");
    });
  });

  // ======================================================================
  describe("3. Rejection Workflow", function () {
    it("should allow Issuing Bank to reject L/C with reason", async function () {
      const { id } = await openLC();
      const reason = "Credit limit exceeded for the applicant.";

      await expect(tradeFinanceLC.connect(issuingBank).rejectLC(id, reason))
        .to.emit(tradeFinanceLC, "LCRejected")
        .withArgs(id, issuingBank.address, reason);

      const lc = await tradeFinanceLC.getLC(id);
      expect(lc.state).to.equal(State.Rejected);
      expect(lc.rejectReason).to.equal(reason);
      expect(await stableToken.balanceOf(lcAddress)).to.equal(0);

      await expect(tradeFinanceLC.connect(issuingBank).approveLC(id)).to.be.revertedWith(
        "Invalid LC state for this action"
      );
    });

    it("should require a non-empty reject reason and the assigned bank", async function () {
      const { id } = await openLC();
      await expect(tradeFinanceLC.connect(issuingBank).rejectLC(id, "")).to.be.revertedWith("Reject reason required");

      await tradeFinanceLC.grantRole(ISSUING_BANK_ROLE, unauthorizedUser.address);
      await expect(tradeFinanceLC.connect(unauthorizedUser).rejectLC(id, "x")).to.be.revertedWith(
        "Caller is not assigned Issuing Bank for this LC"
      );
    });
  });
});
