// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IIdentity.sol";
import "../interfaces/ISignerRegistry.sol";
import "../interfaces/IComplianceDocument.sol";
import "../interfaces/INumenaID.sol";
import "../libraries/Errors.sol";
import "../libraries/Events.sol";
import "../utils/Signatures.sol";

/**
 * @title Identity
 * @dev Individual identity contract that stores verified claims about a user.
 * Claims are cryptographically signed by authorized signers from the SignerRegistry.
 * Each user has their own identity contract deployed through IdentityFactory.
 */
contract Identity is IIdentity, ReentrancyGuard {
    // State variables
    address public owner;
    address public immutable signerRegistry;
    address public numenaID; // Router contract that knows all module addresses
    mapping(uint256 => Claim) public claims;
    mapping(address => uint256) public nonces; // For signature replay protection
    bytes32 private immutable DOMAIN_SEPARATOR; // EIP-712 domain separator
    
    // Rate limiting
    mapping(address => uint256) public lastActionTimestamp;
    uint256 public constant RATE_LIMIT_WINDOW = 60; // 60 seconds between claims per signer
    
    // Modifiers
    modifier onlyOwner() {
        if (msg.sender != owner) revert Errors.OnlyOwner();
        _;
    }
    
    modifier onlyAuthorizedSigner() {
        if (!ISignerRegistry(signerRegistry).isValidSigner(msg.sender)) {
            revert Errors.NotAuthorizedSigner();
        }
        _;
    }
    
    /**
     * @dev Constructor sets the identity owner and signer registry
     * @param _owner The wallet address that will own this identity
     * @param _signerRegistry Address of the SignerRegistry contract
     * @param _numenaID Address of the NumenaID router contract
     */
    constructor(address _owner, address _signerRegistry, address _numenaID) {
        if (_owner == address(0)) revert Errors.ZeroAddress();
        if (_signerRegistry == address(0)) revert Errors.ZeroAddress();
        if (_numenaID == address(0)) revert Errors.ZeroAddress();
        
        owner = _owner;
        signerRegistry = _signerRegistry;
        numenaID = _numenaID;
        
        // Initialize EIP-712 domain separator
        DOMAIN_SEPARATOR = Signatures.computeDomainSeparator("NumenaID", "1.0.0");
    }
    
    /**
     * @dev Adds a new claim to the identity with signature verification
     * @param claimType The type of claim being added
     * @param documentIds Array of document NFT token IDs that support this claim
     * @param expiresAt Timestamp when claim expires (0 for no expiration)
     * @param data Encoded claim data specific to the claim type
     * @param signature Cryptographic signature of the claim data by the signer
     */
    function addClaim(
        uint256 claimType,
        uint256[] calldata documentIds,
        uint256 expiresAt,
        bytes calldata data,
        bytes calldata signature
    ) external onlyAuthorizedSigner nonReentrant {
        // Validate inputs
        if (expiresAt != 0 && expiresAt <= block.timestamp) revert Errors.InvalidData();
        if (data.length == 0) revert Errors.InvalidData();
        if (signature.length == 0) revert Errors.InvalidSignature();
        
        // Rate limiting check
        if (block.timestamp < lastActionTimestamp[msg.sender] + RATE_LIMIT_WINDOW) {
            revert Errors.RateLimitExceeded();
        }
        
        // Check if signer can sign this claim type
        if (!ISignerRegistry(signerRegistry).canSignClaimType(msg.sender, claimType)) {
            revert Errors.SignerNotAuthorizedForClaimType();
        }
        
        // Get current nonce for replay protection
        uint256 currentNonce = nonces[msg.sender];
        
        // Create EIP-712 compliant message digest
        bytes32 digest = Signatures.createClaimDigest(
            address(this),
            claimType,
            documentIds,
            keccak256(data),
            expiresAt,
            currentNonce,
            DOMAIN_SEPARATOR
        );
        
        // Verify signature
        if (!Signatures.verifySignature(digest, signature, msg.sender)) {
            revert Errors.InvalidSignature();
        }
        
        // CHECKS-EFFECTS-INTERACTIONS pattern
        // Effects: Update state before any external calls
        nonces[msg.sender]++; // Increment nonce to prevent replay
        lastActionTimestamp[msg.sender] = block.timestamp; // Update rate limit timestamp
        
        claims[claimType] = Claim({
            claimType: claimType,
            signer: msg.sender,
            documentIds: documentIds,
            signature: signature,
            data: data,
            timestamp: block.timestamp,
            expiresAt: expiresAt,
            revoked: false
        });
        
        emit Events.ClaimAdded(address(this), claimType, msg.sender, address(0), expiresAt);
        
        // Interactions: External calls come last
        // Increment signer's claim count in registry
        ISignerRegistry(signerRegistry).incrementClaimCount(msg.sender);
    }
    
    /**
     * @dev Revokes an existing claim
     * @param claimType The type of claim to revoke
     */
    function revokeClaim(uint256 claimType) external nonReentrant {
        Claim storage claim = claims[claimType];
        
        // Check claim exists
        if (claim.signer == address(0)) revert Errors.ClaimNotFound();
        
        // Only signer or owner can revoke
        if (msg.sender != claim.signer && msg.sender != owner) {
            revert Errors.Unauthorized();
        }
        
        claim.revoked = true;
        emit Events.ClaimRevoked(address(this), claimType, msg.sender);
    }
    
    /**
     * @dev Returns full claim data for a given claim type
     * @param claimType The type of claim to retrieve
     * @return The complete Claim struct
     */
    function getClaim(uint256 claimType) external view returns (Claim memory) {
        return claims[claimType];
    }
    
    /**
     * @dev Checks if identity has a valid (non-revoked, non-expired) claim
     * @param claimType The type of claim to check
     * @return bool True if claim exists and is valid
     */
    function hasValidClaim(uint256 claimType) external view returns (bool) {
        Claim memory claim = claims[claimType];
        
        return claim.signer != address(0) && 
               !claim.revoked && 
               (claim.expiresAt == 0 || claim.expiresAt > block.timestamp);
    }
    
    /**
     * @dev Allows owner to transfer identity ownership
     * @param newOwner The new owner's wallet address
     */
    function transferOwnership(address newOwner) external onlyOwner nonReentrant {
        if (newOwner == address(0)) revert Errors.ZeroAddress();
        
        address previousOwner = owner;
        owner = newOwner;
        
        emit Events.OwnershipTransferred(address(this), previousOwner, newOwner);
    }
    
    /**
     * @dev Gets documents owned by this identity of a specific type
     * @param documentType The type of documents to retrieve
     * @return Array of document token IDs
     */
    function getDocumentsByType(uint256 documentType) external view returns (uint256[] memory) {
        // Get ComplianceDocument address from NumenaID router
        address complianceDoc = INumenaID(numenaID).complianceDocument();
        return IComplianceDocument(complianceDoc).getDocumentsByOwnerAndType(address(this), documentType);
    }
    
    /**
     * @dev Gets the most recent document of a specific type
     * @param documentType The type of document to retrieve
     * @return Token ID of the most recent document
     */
    function getMostRecentDocumentByType(uint256 documentType) external view returns (uint256) {
        // Get ComplianceDocument address from NumenaID router
        address complianceDoc = INumenaID(numenaID).complianceDocument();
        (uint256 tokenId, bool found) = IComplianceDocument(complianceDoc).getMostRecentDocumentByOwnerAndType(address(this), documentType);
        if (!found) revert Errors.DocumentNotFound();
        return tokenId;
    }
}