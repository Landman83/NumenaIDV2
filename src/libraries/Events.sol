// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title Events
 * @dev Library containing all events for the NumenaID system
 * Centralizing events helps with consistency and reduces deployment size
 */
library Events {
    // ===== Identity Events =====
    event IdentityCreated(address indexed owner, address indexed identity);
    event IdentityRegistered(address indexed wallet, address indexed identity);
    event IdentityUpdated(address indexed wallet, address indexed oldIdentity, address indexed newIdentity);
    event IdentityRemoved(address indexed wallet, address indexed identity);
    event OwnershipTransferred(address indexed identity, address indexed previousOwner, address indexed newOwner);
    
    // ===== Claim Events =====
    event ClaimAdded(
        address indexed identity,
        uint256 indexed claimType,
        address indexed signer,
        address docRef,
        uint256 expiresAt
    );
    event ClaimRevoked(
        address indexed identity,
        uint256 indexed claimType,
        address indexed revoker
    );
    event ClaimExpired(
        address indexed identity,
        uint256 indexed claimType
    );
    
    // ===== Signer Events =====
    event SignerAdded(
        address indexed signer,
        uint256[] allowedClaimTypes,
        string name
    );
    event SignerRemoved(address indexed signer);
    event SignerUpdated(
        address indexed signer,
        uint256[] allowedClaimTypes
    );
    event SignerStatusChanged(
        address indexed signer,
        bool active
    );
    
    // ===== Factory Events =====
    event IdentityDeployed(
        address indexed owner,
        address indexed identity,
        address indexed deployer
    );
    event CodeHashAdded(bytes32 indexed codeHash);
    event CodeHashRemoved(bytes32 indexed codeHash);
    event IdentityCommitted(
        address indexed user,
        bytes32 indexed commitment,
        uint256 timestamp
    );
    
    // ===== Claim Type Events =====
    event ClaimTypeAdded(
        uint256 indexed claimTypeId,
        string title,
        uint256[] requiredDocumentTypes
    );
    event ClaimTypeRemoved(uint256 indexed claimTypeId);
    event ClaimTypeUpdated(
        uint256 indexed claimTypeId,
        string title,
        uint256[] requiredDocumentTypes
    );
    
    // ===== Verification Events =====
    event ClaimVerified(
        address indexed user,
        uint256 indexed claimType,
        bool valid
    );
    event VerificationRequested(
        address indexed user,
        uint256 indexed claimType,
        address indexed requester
    );
    
    // ===== Admin Events =====
    event RoleGranted(
        bytes32 indexed role,
        address indexed account,
        address indexed sender
    );
    event RoleRevoked(
        bytes32 indexed role,
        address indexed account,
        address indexed sender
    );
    event AdminTransferred(
        address indexed previousAdmin,
        address indexed newAdmin
    );
    
    // ===== System Events =====
    event ModuleUpdated(
        string moduleName,
        address indexed oldModule,
        address indexed newModule
    );
    event SystemPaused(address indexed pauser);
    event SystemUnpaused(address indexed unpauser);
    event EmergencyShutdown(address indexed initiator);
}