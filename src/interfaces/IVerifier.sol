// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./IIdentityRegistry.sol";
import "./ISignerRegistry.sol";

/**
 * @title IVerifier
 * @dev Interface for the Verifier utility contract that provides claim verification helpers
 */
interface IVerifier {
    /**
     * @dev Checks if an address is a valid active signer
     */
    function isValidSigner(address signer) external view returns (bool);
    
    /**
     * @dev Checks if a user has a valid (non-revoked, non-expired) claim
     */
    function hasValidClaim(address user, uint256 claimType) external view returns (bool);
    
    /**
     * @dev Returns the signer address who created a specific claim
     */
    function getClaimSigner(address user, uint256 claimType) external view returns (address);
    
    /**
     * @dev Returns the document IDs for a user's claim
     */
    function getClaimDocumentIds(address user, uint256 claimType) external view returns (uint256[] memory);
    
    /**
     * @dev Returns the raw data of a user's claim
     */
    function getClaimData(address user, uint256 claimType) external view returns (bytes memory);
    
    /**
     * @dev Checks if a user has all required claims for a given array
     */
    function hasAllClaims(address user, uint256[] calldata requiredClaims) external view returns (bool);
    
    /**
     * @dev Returns detailed claim information
     */
    function getClaimDetails(address user, uint256 claimType) external view returns (
        address signer,
        uint256[] memory documentIds,
        bytes memory data,
        uint256 timestamp,
        uint256 expiresAt,
        bool revoked
    );
    
    /**
     * @dev Verifies claim signature is valid and matches signer
     */
    function verifyClaimSignature(address user, uint256 claimType) external view returns (bool);
    
    /**
     * @dev Helper to recover signer from signature
     */
    function recoverSigner(bytes32 messageHash, bytes memory signature) external pure returns (address);
    
    /**
     * @dev Returns the identity registry address
     */
    function identityRegistry() external view returns (IIdentityRegistry);
    
    /**
     * @dev Returns the signer registry address
     */
    function signerRegistry() external view returns (ISignerRegistry);
}