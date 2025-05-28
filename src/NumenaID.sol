// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./interfaces/INumenaID.sol";
import "./interfaces/IIdentityFactory.sol";
import "./interfaces/IIdentityRegistry.sol";
import "./interfaces/ISignerRegistry.sol";
import "./interfaces/IClaimTypeRegistry.sol";
import "./interfaces/IVerifier.sol";
import "./libraries/Errors.sol";

/**
 * @title NumenaID
 * @dev Router contract implementing hub-and-spoke pattern for the NumenaID identity system.
 * Delegates all functionality to specialized modules while providing a unified interface.
 * All state is stored in modules; this contract only routes calls.
 */
contract NumenaID is INumenaID {
    // Constants for batch operations
    uint256 public constant MAX_BATCH_SIZE = 100;
    
    // Module addresses
    address public immutable identityRegistry;
    address public immutable identityFactory;
    address public immutable signerRegistry;
    address public immutable claimTypeRegistry;
    address public immutable verifier;
    address public immutable complianceDocument;
    
    /**
     * @dev Constructor initializes the router with module addresses
     * @param _identityRegistry Address of IdentityRegistry module
     * @param _identityFactory Address of IdentityFactory module
     * @param _signerRegistry Address of SignerRegistry module
     * @param _claimTypeRegistry Address of ClaimTypeRegistry module
     * @param _verifier Address of Verifier module
     * @param _complianceDocument Address of ComplianceDocument module
     */
    constructor(
        address _identityRegistry,
        address _identityFactory,
        address _signerRegistry,
        address _claimTypeRegistry,
        address _verifier,
        address _complianceDocument
    ) {
        if (_identityRegistry == address(0)) revert Errors.ZeroAddress();
        if (_identityFactory == address(0)) revert Errors.ZeroAddress();
        if (_signerRegistry == address(0)) revert Errors.ZeroAddress();
        if (_claimTypeRegistry == address(0)) revert Errors.ZeroAddress();
        if (_verifier == address(0)) revert Errors.ZeroAddress();
        if (_complianceDocument == address(0)) revert Errors.ZeroAddress();
        
        identityRegistry = _identityRegistry;
        identityFactory = _identityFactory;
        signerRegistry = _signerRegistry;
        claimTypeRegistry = _claimTypeRegistry;
        verifier = _verifier;
        complianceDocument = _complianceDocument;
    }
    
    // ===== Identity Management Functions (delegates to IdentityFactory/Registry) =====
    
    /**
     * @dev Step 1 of secure identity creation: Commit to creating an identity
     * @param commitment Hash of user's address and a secret nonce
     */
    function commitIdentity(bytes32 commitment) external {
        IIdentityFactory(identityFactory).commitIdentityFor(msg.sender, commitment);
    }
    
    /**
     * @dev Step 2 of secure identity creation: Reveal and deploy identity
     * @param nonce The secret nonce used in the commitment
     * @return identity Address of deployed identity contract
     */
    function revealAndCreateIdentity(uint256 nonce) external returns (address identity) {
        return IIdentityFactory(identityFactory).revealAndDeployIdentityFor(msg.sender, nonce);
    }
    
    /**
     * @dev Legacy identity deployment (less secure, susceptible to front-running)
     * @return identity Address of deployed identity contract
     */
    function createIdentity() external returns (address identity) {
        // Call factory directly as the user, not as NumenaID
        // This requires the factory to have a deployIdentityFor function
        return IIdentityFactory(identityFactory).deployIdentityFor(msg.sender);
    }
    
    /**
     * @dev Gets identity contract for a wallet
     * @param wallet Address to query
     * @return Identity contract address
     */
    function getIdentity(address wallet) external view returns (address) {
        return IIdentityRegistry(identityRegistry).getIdentity(wallet);
    }
    
    /**
     * @dev Checks if a wallet has an identity
     * @param wallet Address to check
     * @return True if wallet has identity
     */
    function hasIdentity(address wallet) external view returns (bool) {
        return IIdentityRegistry(identityRegistry).hasIdentity(wallet);
    }
    
    // ===== Claim Verification Functions (delegates to Verifier) =====
    
    /**
     * @dev Checks if user has a valid claim
     * @param user User wallet address
     * @param claimType Type of claim to check
     * @return True if claim is valid
     */
    function hasValidClaim(address user, uint256 claimType) external view returns (bool) {
        return IVerifier(verifier).hasValidClaim(user, claimType);
    }
    
    /**
     * @dev Checks if user has all required claims
     * @param user User wallet address
     * @param requiredClaims Array of required claim types
     * @return True if user has all claims
     */
    function hasAllClaims(address user, uint256[] calldata requiredClaims) external view returns (bool) {
        return IVerifier(verifier).hasAllClaims(user, requiredClaims);
    }
    
    /**
     * @dev Gets claim details for a user
     * @param user User wallet address
     * @param claimType Type of claim to query
     * @return signer Who signed the claim
     * @return documentIds Array of document NFT token IDs
     * @return data Claim data
     * @return timestamp Creation time
     * @return expiresAt Expiration time
     * @return revoked Revocation status
     */
    function getClaimDetails(address user, uint256 claimType) external view returns (
        address signer,
        uint256[] memory documentIds,
        bytes memory data,
        uint256 timestamp,
        uint256 expiresAt,
        bool revoked
    ) {
        return IVerifier(verifier).getClaimDetails(user, claimType);
    }
    
    // ===== Signer Management Functions (delegates to SignerRegistry) =====
    
    /**
     * @dev Checks if address is valid signer
     * @param signer Address to check
     * @return True if valid signer
     */
    function isValidSigner(address signer) external view returns (bool) {
        return ISignerRegistry(signerRegistry).isValidSigner(signer);
    }
    
    /**
     * @dev Gets all active signers
     * @return Array of signer addresses
     */
    function getSigners() external view returns (address[] memory) {
        return ISignerRegistry(signerRegistry).getSigners();
    }
    
    /**
     * @dev Gets signers for specific claim type
     * @param claimType The claim type
     * @return Array of authorized signers
     */
    function getSignersForClaim(uint256 claimType) external view returns (address[] memory) {
        return ISignerRegistry(signerRegistry).getSignersForClaim(claimType);
    }
    
    // ===== Claim Type Functions (delegates to ClaimTypeRegistry) =====
    
    /**
     * @dev Gets human-readable info for claim type
     * @param claimTypeId Numeric claim type ID
     * @return title Human-readable name
     * @return requiredDocumentTypes Array of required document types
     * @return dataType Expected data encoding
     * @return active Whether type is active
     */
    function getClaimType(uint256 claimTypeId) external view returns (
        string memory title,
        uint256[] memory requiredDocumentTypes,
        string memory dataType,
        bool active
    ) {
        return IClaimTypeRegistry(claimTypeRegistry).getClaimType(claimTypeId);
    }
    
    /**
     * @dev Gets all claim type IDs
     * @return Array of claim type IDs
     */
    function getAllClaimTypes() external view returns (uint256[] memory) {
        return IClaimTypeRegistry(claimTypeRegistry).getAllClaimTypes();
    }
    
    // ===== Convenience Functions =====
    
    /**
     * @dev Combined check for multiple users and claims
     * @param users Array of user addresses
     * @param claimType Claim type to check
     * @return Array of booleans indicating validity
     */
    function batchHasValidClaim(
        address[] calldata users,
        uint256 claimType
    ) external view returns (bool[] memory) {
        if (users.length == 0) revert Errors.EmptyArray();
        if (users.length > MAX_BATCH_SIZE) revert Errors.BatchSizeTooLarge();
        
        bool[] memory results = new bool[](users.length);
        for (uint256 i = 0; i < users.length; i++) {
            results[i] = IVerifier(verifier).hasValidClaim(users[i], claimType);
        }
        return results;
    }
    
    /**
     * @dev Returns all module addresses
     */
    function getAllModules() external view returns (
        address _identityRegistry,
        address _identityFactory,
        address _signerRegistry,
        address _claimTypeRegistry,
        address _verifier
    ) {
        return (
            identityRegistry,
            identityFactory,
            signerRegistry,
            claimTypeRegistry,
            verifier
        );
    }
}