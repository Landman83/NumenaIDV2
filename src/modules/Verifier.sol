// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IVerifier.sol";
import "../interfaces/IIdentityRegistry.sol";
import "../interfaces/ISignerRegistry.sol";
import "../interfaces/IIdentity.sol";
import "../interfaces/IComplianceDocument.sol";
import "../interfaces/IClaimTypeRegistry.sol";
import "../interfaces/INumenaID.sol";
import "../libraries/Errors.sol";
import "../libraries/Events.sol";
import "../utils/Signatures.sol";

/**
 * @title Verifier
 * @dev Utility contract that provides helper functions for claim verification.
 * Used by token contracts and other systems to check user compliance.
 * Abstracts the complexity of querying identity contracts and validating claims.
 */
contract Verifier is IVerifier, ReentrancyGuard {
    // Constants
    uint256 public constant MAX_CLAIMS_PER_CHECK = 50;
    uint256 public constant MAX_DOCUMENTS_PER_CLAIM = 20;
    
    // State variables
    IIdentityRegistry public immutable identityRegistry;
    ISignerRegistry public immutable signerRegistry;
    address public numenaID; // Router contract for accessing other modules
    bytes32 private immutable DOMAIN_SEPARATOR; // EIP-712 domain separator
    
    /**
     * @dev Constructor sets the registry contracts
     * @param _identityRegistry Address of the IdentityRegistry contract
     * @param _signerRegistry Address of the SignerRegistry contract
     */
    constructor(address _identityRegistry, address _signerRegistry, address _numenaID) {
        if (_identityRegistry == address(0)) revert Errors.ZeroAddress();
        if (_signerRegistry == address(0)) revert Errors.ZeroAddress();
        if (_numenaID == address(0)) revert Errors.ZeroAddress();
        
        identityRegistry = IIdentityRegistry(_identityRegistry);
        signerRegistry = ISignerRegistry(_signerRegistry);
        numenaID = _numenaID;
        
        // Initialize EIP-712 domain separator
        DOMAIN_SEPARATOR = Signatures.computeDomainSeparator("NumenaID", "1.0.0");
    }
    
    /**
     * @dev Checks if an address is a valid active signer
     * @param signer Address to check
     * @return True if signer is active in SignerRegistry
     */
    function isValidSigner(address signer) external view returns (bool) {
        return signerRegistry.isValidSigner(signer);
    }
    
    /**
     * @dev Checks if a user has a valid (non-revoked, non-expired) claim
     * @param user The user's wallet address
     * @param claimType The type of claim to check
     * @return True if user has valid claim of specified type
     */
    function hasValidClaim(address user, uint256 claimType) external view returns (bool) {
        address identityContract = identityRegistry.getIdentity(user);
        if (identityContract == address(0)) return false;
        
        IIdentity identity = IIdentity(identityContract);
        IIdentity.Claim memory claim = identity.getClaim(claimType);
        
        bool valid = claim.signer != address(0) && 
                    !claim.revoked && 
                    (claim.expiresAt == 0 || claim.expiresAt > block.timestamp);
        
        return valid;
    }
    
    /**
     * @dev Returns the signer address who created a specific claim
     * @param user The user's wallet address
     * @param claimType The type of claim to query
     * @return The signer address (zero if claim doesn't exist or signature invalid)
     */
    function getClaimSigner(address user, uint256 claimType) external view returns (address) {
        address identityContract = identityRegistry.getIdentity(user);
        if (identityContract == address(0)) return address(0);
        
        IIdentity identity = IIdentity(identityContract);
        IIdentity.Claim memory claim = identity.getClaim(claimType);
        
        if (claim.signer == address(0)) return address(0);
        
        // Verify signature using EIP-712 (consistent with Identity.sol)
        // Get nonce for the signer from identity contract
        uint256 nonce = identity.nonces(claim.signer);
        
        // Reconstruct EIP-712 digest (note: nonce should be nonce-1 since it was incremented after signing)
        bytes32 digest = Signatures.createClaimDigest(
            identityContract,
            claim.claimType,
            claim.documentIds,
            keccak256(claim.data),
            claim.expiresAt,
            nonce > 0 ? nonce - 1 : 0,  // Use the nonce at time of signing
            DOMAIN_SEPARATOR
        );
        
        address recoveredSigner = Signatures.recoverSigner(digest, claim.signature);
        
        // Return signer only if signature is valid
        return (recoveredSigner == claim.signer) ? claim.signer : address(0);
    }
    
    /**
     * @dev Returns the document IDs for a user's claim
     * @param user The user's wallet address
     * @param claimType The type of claim to query
     * @return Array of document NFT token IDs
     */
    function getClaimDocumentIds(address user, uint256 claimType) external view returns (uint256[] memory) {
        address identityContract = identityRegistry.getIdentity(user);
        if (identityContract == address(0)) return new uint256[](0);
        
        IIdentity identity = IIdentity(identityContract);
        IIdentity.Claim memory claim = identity.getClaim(claimType);
        
        return claim.documentIds;
    }
    
    /**
     * @dev Returns the raw data of a user's claim
     * @param user The user's wallet address
     * @param claimType The type of claim to query
     * @return The encoded claim data
     */
    function getClaimData(address user, uint256 claimType) external view returns (bytes memory) {
        address identityContract = identityRegistry.getIdentity(user);
        if (identityContract == address(0)) revert Errors.IdentityNotFound();
        
        IIdentity identity = IIdentity(identityContract);
        return identity.getClaim(claimType).data;
    }
    
    /**
     * @dev Checks if a user has all required claims for a given array
     * @param user The user's wallet address
     * @param requiredClaims Array of claim types to check
     * @return True if user has all required claims
     */
    function hasAllClaims(address user, uint256[] calldata requiredClaims) external view returns (bool) {
        if (requiredClaims.length == 0) return true;
        if (requiredClaims.length > MAX_CLAIMS_PER_CHECK) revert Errors.BatchSizeTooLarge();
        
        address identityContract = identityRegistry.getIdentity(user);
        if (identityContract == address(0)) return false;
        
        IIdentity identity = IIdentity(identityContract);
        
        for (uint256 i = 0; i < requiredClaims.length; i++) {
            if (!identity.hasValidClaim(requiredClaims[i])) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * @dev Returns detailed claim information
     * @param user The user's wallet address
     * @param claimType The type of claim to query
     * @return signer The address who signed the claim
     * @return documentIds Array of document NFT token IDs
     * @return data The claim data
     * @return timestamp When claim was created
     * @return expiresAt When claim expires
     * @return revoked Whether claim is revoked
     */
    function getClaimDetails(address user, uint256 claimType) external view returns (
        address signer,
        uint256[] memory documentIds,
        bytes memory data,
        uint256 timestamp,
        uint256 expiresAt,
        bool revoked
    ) {
        address identityContract = identityRegistry.getIdentity(user);
        if (identityContract == address(0)) revert Errors.IdentityNotFound();
        
        IIdentity identity = IIdentity(identityContract);
        IIdentity.Claim memory claim = identity.getClaim(claimType);
        
        return (
            claim.signer,
            claim.documentIds,
            claim.data,
            claim.timestamp,
            claim.expiresAt,
            claim.revoked
        );
    }
    
    /**
     * @dev Verifies claim signature is valid and matches signer
     * @param user The user's wallet address
     * @param claimType The type of claim to verify
     * @return True if signature is valid
     */
    function verifyClaimSignature(address user, uint256 claimType) external view returns (bool) {
        address identityContract = identityRegistry.getIdentity(user);
        if (identityContract == address(0)) return false;
        
        IIdentity identity = IIdentity(identityContract);
        IIdentity.Claim memory claim = identity.getClaim(claimType);
        
        if (claim.signer == address(0)) return false;
        
        // Get nonce for the signer from identity contract
        uint256 nonce = identity.nonces(claim.signer);
        
        // Reconstruct EIP-712 digest (note: nonce should be nonce-1 since it was incremented after signing)
        bytes32 digest = Signatures.createClaimDigest(
            identityContract,
            claim.claimType,
            claim.documentIds,
            keccak256(claim.data),
            claim.expiresAt,
            nonce > 0 ? nonce - 1 : 0,  // Use the nonce at time of signing
            DOMAIN_SEPARATOR
        );
        
        return Signatures.verifySignature(digest, claim.signature, claim.signer);
    }
    
    /**
     * @dev Creates a new claim with automatic document retrieval
     * @param user The user's wallet address
     * @param claimType The type of claim to create
     * @param data Encoded claim data
     * @param expiresAt Expiration timestamp (0 for no expiration)
     * @param signature Cryptographic signature
     */
    function createClaimWithDocuments(
        address user,
        uint256 claimType,
        bytes calldata data,
        uint256 expiresAt,
        bytes calldata signature
    ) external nonReentrant {
        // CHECKS
        // Get required document types from ClaimTypeRegistry
        address claimTypeRegistry = INumenaID(numenaID).claimTypeRegistry();
        uint256[] memory requiredDocTypes = IClaimTypeRegistry(claimTypeRegistry).getRequiredDocuments(claimType);
        
        // Validate document count
        if (requiredDocTypes.length > MAX_DOCUMENTS_PER_CLAIM) revert Errors.BatchSizeTooLarge();
        
        // Get user's identity contract
        address identityContract = identityRegistry.getIdentity(user);
        if (identityContract == address(0)) revert Errors.IdentityNotFound();
        
        IIdentity identity = IIdentity(identityContract);
        
        // Collect the most recent documents for each required type
        uint256[] memory documentIds = new uint256[](requiredDocTypes.length);
        address complianceDoc = INumenaID(numenaID).complianceDocument();
        
        for (uint256 i = 0; i < requiredDocTypes.length; i++) {
            uint256 docId = identity.getMostRecentDocumentByType(requiredDocTypes[i]);
            documentIds[i] = docId;
        }
        
        // EFFECTS (none in this function - state changes happen in external contracts)
        
        // INTERACTIONS
        // First add claim to identity (this will update state in Identity contract)
        identity.addClaim(claimType, documentIds, expiresAt, data, signature);
        
        // Then record document access (separate loop to follow checks-effects-interactions)
        for (uint256 i = 0; i < documentIds.length; i++) {
            IComplianceDocument(complianceDoc).recordDocumentAccess(documentIds[i], msg.sender);
        }
    }
    
    /**
     * @dev Verifies that a claim has all required documents
     * @param user The user's wallet address
     * @param claimType The type of claim to verify
     * @return True if claim has all required documents
     */
    function verifyClaimDocuments(address user, uint256 claimType) external view returns (bool) {
        // Get required document types
        address claimTypeRegistry = INumenaID(numenaID).claimTypeRegistry();
        uint256[] memory requiredDocTypes = IClaimTypeRegistry(claimTypeRegistry).getRequiredDocuments(claimType);
        
        // Get claim's document IDs
        uint256[] memory claimDocIds = this.getClaimDocumentIds(user, claimType);
        
        if (claimDocIds.length != requiredDocTypes.length) return false;
        
        // Verify each document exists and is of correct type
        address complianceDoc = INumenaID(numenaID).complianceDocument();
        for (uint256 i = 0; i < claimDocIds.length; i++) {
            IComplianceDocument.Document memory doc = IComplianceDocument(complianceDoc).viewDocument(claimDocIds[i]);
            
            // Check if document type matches required type
            bool typeFound = false;
            for (uint256 j = 0; j < requiredDocTypes.length; j++) {
                if (doc.documentType == requiredDocTypes[j]) {
                    typeFound = true;
                    break;
                }
            }
            if (!typeFound) return false;
        }
        
        return true;
    }
    
    /**
     * @dev Helper to recover signer from signature
     * @param messageHash The hash of the message that was signed
     * @param signature The signature bytes
     * @return The recovered signer address
     */
    function recoverSigner(bytes32 messageHash, bytes memory signature) external pure returns (address) {
        return Signatures.recoverSigner(messageHash, signature);
    }
    
}