// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IComplianceDocument
 * @dev Interface for the ComplianceDocument contract
 */
interface IComplianceDocument {
    struct Document {
        string fileHash;
        string localPath;
        uint256 documentType;
        uint256 uploadedAt;
        uint256 fileSize;
        address uploadedBy;
    }
    
    struct AccessRecord {
        address accessor;
        uint8 accessType;
        uint48 timestamp;
    }
    
    function mintDocument(
        string memory fileHash,
        string memory localPath,
        uint256 documentType,
        uint256 fileSize
    ) external returns (uint256);
    
    function getDocument(uint256 tokenId) external returns (Document memory);
    
    function viewDocument(uint256 tokenId) external view returns (Document memory);
    
    function recordDocumentAccess(uint256 tokenId, address accessor) external;
    
    function getAccessHistory(uint256 tokenId) external view returns (AccessRecord[] memory);
    
    function canAccessDocument(uint256 tokenId, address accessor) external view returns (bool);
    
    function getDocumentsByOwner(address owner) external view returns (uint256[] memory);
    
    function getDocumentsByOwnerAndType(address owner, uint256 documentType) external view returns (uint256[] memory);
    
    function getMostRecentDocumentByOwnerAndType(address owner, uint256 documentType) external view returns (uint256 tokenId, bool found);
}