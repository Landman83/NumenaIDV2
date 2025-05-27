// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IClaimTypeRegistry
 * @dev Interface for the ClaimTypeRegistry contract that manages claim type metadata
 */
interface IClaimTypeRegistry {
    // Claim type metadata structure
    struct ClaimType {
        string title;
        uint256[] requiredDocumentTypes;
        string dataType;
        bool active;
    }
    
    /**
     * @dev Adds a new claim type to the registry
     */
    function addClaimType(
        uint256 claimTypeId,
        string calldata title,
        uint256[] calldata requiredDocumentTypes,
        string calldata dataType
    ) external;
    
    /**
     * @dev Removes a claim type (marks as inactive)
     */
    function removeClaimType(uint256 claimTypeId) external;
    
    /**
     * @dev Updates metadata for an existing claim type
     */
    function updateClaimType(
        uint256 claimTypeId,
        string calldata title,
        uint256[] calldata requiredDocumentTypes,
        string calldata dataType
    ) external;
    
    /**
     * @dev Returns metadata for a specific claim type
     */
    function getClaimType(uint256 claimTypeId) external view returns (
        string memory title,
        uint256[] memory requiredDocumentTypes,
        string memory dataType,
        bool active
    );
    
    /**
     * @dev Returns required document types for a claim
     */
    function getRequiredDocuments(uint256 claimTypeId) external view returns (uint256[] memory);
    
    /**
     * @dev Returns all registered claim type IDs
     */
    function getAllClaimTypes() external view returns (uint256[] memory);
    
    /**
     * @dev Checks if a claim type ID is registered and active
     */
    function isValidClaimType(uint256 claimTypeId) external view returns (bool);
}