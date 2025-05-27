// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title ISignerRegistry
 * @dev Interface for the SignerRegistry contract that manages authorized claim signers
 */
interface ISignerRegistry {
    // Signer information structure
    struct SignerInfo {
        bool active;
        uint256[] allowedClaimTypes;
        uint256 addedAt;
        uint256 totalClaims;
        uint256 revokedClaims;
        string name;
    }
    
    /**
     * @dev Adds a new authorized signer with specific claim type permissions
     */
    function addSigner(
        address signer,
        uint256[] calldata allowedClaimTypes,
        string calldata name
    ) external;
    
    /**
     * @dev Removes a signer's authorization
     */
    function removeSigner(address signer) external;
    
    /**
     * @dev Returns all active signer addresses
     */
    function getSigners() external view returns (address[] memory);
    
    /**
     * @dev Returns all signers authorized for a specific claim type
     */
    function getSignersForClaim(uint256 claimType) external view returns (address[] memory);
    
    /**
     * @dev Returns the total count of active signers
     */
    function getSignerCount() external view returns (uint256);
    
    /**
     * @dev Checks if an address is an active signer
     */
    function isValidSigner(address signer) external view returns (bool);
    
    /**
     * @dev Checks if a signer can create a specific claim type
     */
    function canSignClaimType(address signer, uint256 claimType) external view returns (bool);
    
    /**
     * @dev Updates the allowed claim types for an existing signer
     */
    function updateSignerClaimTypes(
        address signer,
        uint256[] calldata newAllowedClaimTypes
    ) external;
    
    /**
     * @dev Increments claim count for a signer
     */
    function incrementClaimCount(address signer) external;
    
    /**
     * @dev Returns detailed information about a signer
     */
    function getSignerInfo(address signer) external view returns (SignerInfo memory);
}