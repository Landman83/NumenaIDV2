// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title Errors
 * @dev Library containing all custom errors for the NumenaID system
 * Using custom errors saves gas compared to string error messages
 */
library Errors {
    // ===== Access Control Errors =====
    error Unauthorized();
    error OnlyAdmin();
    error OnlyFactory();
    error OnlyOwner();
    error OnlyVerifier();
    error NotAuthorizedSigner();
    
    // ===== Identity Errors =====
    error IdentityAlreadyExists();
    error IdentityNotFound();
    error InvalidIdentityContract();
    error OwnerMismatch();
    
    // ===== Claim Errors =====
    error ClaimNotFound();
    error ClaimExpired();
    error ClaimRevoked();
    error ClaimAlreadyExists();
    error InvalidClaimType();
    error InvalidSignature();
    error SignerNotAuthorizedForClaimType();
    error DocumentNotFound();
    error DocumentDoesNotExist();
    error UnauthorizedDocumentAccess();
    
    // ===== Signer Errors =====
    error SignerAlreadyActive();
    error SignerNotActive();
    error SignerNotFound();
    error InvalidSigner();
    
    // ===== Factory Errors =====
    error InvalidImplementation();
    error DeploymentFailed();
    error InvalidBytecodeHash();
    error NotFactoryDeployed();
    error InvalidOwner();
    error IdentityFactoryNotSet();
    error FactoryAlreadySet();
    
    // ===== Registry Errors =====
    error AlreadyRegistered();
    error NotRegistered();
    error RegistryLocked();
    
    // ===== Parameter Errors =====
    error ZeroAddress();
    error InvalidAddress();
    error InvalidData();
    error InvalidLength();
    error EmptyArray();
    error BatchSizeTooLarge();
    error InvalidFileHash();
    error InvalidLocalPath();
    error InvalidDocumentType();
    error InvalidFileSize();
    error AccessorNotAuthorized();
    error NotDocumentOwner();
    error CallerNotAuthorizedToRecordAccess();
    
    // ===== State Errors =====
    error ContractPaused();
    error ContractNotPaused();
    error AlreadyInitialized();
    error NotInitialized();
    
    // ===== Rate Limit Errors =====
    error RateLimitExceeded();
    
    // ===== Signature Errors =====
    error InvalidSignatureLength();
    error SignatureExpired();
    error SignatureMismatch();
    error RecoveryFailed();
    
    // ===== Commit-Reveal Errors =====
    error NoCommitmentFound();
    error CommitmentTooRecent();
    error CommitmentExpired();
    error InvalidCommitment();
}