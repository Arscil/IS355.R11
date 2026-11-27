// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title BillOfLadingNFT
 * @dev ERC-721 token representing electronic Bill of Lading (eBL) for Title Transfer.
 */
contract BillOfLadingNFT is ERC721URIStorage, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    uint256 private _nextTokenId;

    constructor() ERC721("Digital Bill of Lading", "eBL") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
    }

    /**
     * @dev Mint a new eBL NFT tied to IPFS metadata.
     * @param to Owner address (or escrow contract during shipment).
     * @param uri IPFS metadata URI pointing to document proofs.
     */
    function mintBL(address to, string memory uri) external onlyRole(MINTER_ROLE) returns (uint256) {
        uint256 tokenId = ++_nextTokenId;
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, uri);
        return tokenId;
    }

    /**
     * @dev Burn an eBL NFT (used when documents are rejected for discrepancies and must be re-presented).
     * Only callable by MINTER_ROLE, and only for tokens the caller itself holds (the escrowed eBL).
     * A minter can never burn an eBL that has already been transferred to an Importer.
     * @param tokenId Token to burn.
     */
    function burnBL(uint256 tokenId) external onlyRole(MINTER_ROLE) {
        require(ownerOf(tokenId) == msg.sender, "Caller does not hold this eBL");
        _burn(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC721URIStorage, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}

