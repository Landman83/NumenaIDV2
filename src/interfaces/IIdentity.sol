// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IIdentity
 * @dev Interface for Identity contracts that store user claims.
 * Each user has their own Identity contract deployed through IdentityFactory.
 * Claims are cryptographically signed attestations about the user.
 */
interface IIdentity {
    // Claim structure
    struct Claim {
        uint256 claimType;      // Type of claim (KYC_AML, ACCREDITED, etc.)
        address signer;         // Address who signed this claim
        uint256[] documentIds;  // Array of document NFT token IDs
        bytes signature;        // Cryptographic signature
        bytes data;             // Flexible claim data
        uint256 timestamp;      // Creation timestamp
        uint256 expiresAt;      // Expiration timestamp
        bool revoked;           // Revocation status
    }
    
    // Events
    event ClaimAdded(uint256 indexed claimType, address indexed signer, address docRef);
    event ClaimRevoked(uint256 indexed claimType);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    /**
     * @dev Returns the owner of this identity
     */
    function owner() external view returns (address);
    
    /**
     * @dev Returns the signer registry address
     */
    function signerRegistry() external view returns (address);
    
    /**
     * @dev Adds a new claim with signature verification
     */
    function addClaim(
        uint256 claimType,
        uint256[] calldata documentIds,
        uint256 expiresAt,
        bytes calldata data,
        bytes calldata signature
    ) external;
    
    /**
     * @dev Revokes an existing claim
     */
    function revokeClaim(uint256 claimType) external;
    
    /**
     * @dev Returns a specific claim
     */
    function getClaim(uint256 claimType) external view returns (Claim memory);
    
    /**
     * @dev Checks if identity has a valid claim
     */
    function hasValidClaim(uint256 claimType) external view returns (bool);
    
    /**
     * @dev Transfers ownership to a new address
     */
    function transferOwnership(address newOwner) external;
    
    /**
     * @dev Gets documents owned by this identity of a specific type
     */
    function getDocumentsByType(uint256 documentType) external view returns (uint256[] memory);
    
    /**
     * @dev Gets the most recent document of a specific type
     */
    function getMostRecentDocumentByType(uint256 documentType) external view returns (uint256);
    
    /**
     * @dev Returns the current nonce for a signer
     */
    function nonces(address signer) external view returns (uint256);
}