// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title Roles
 * @dev Library defining role constants for the NumenaID system
 * User: Has compliance verified
 * Verifier: Has document access and can sign claims  
 * Admin: Can add/remove verifiers
 */
library Roles {
    // Role definitions as bytes32 constants
    bytes32 public constant USER_ROLE = keccak256("USER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE"); 
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    
    // Special roles
    bytes32 public constant FACTORY_ROLE = keccak256("FACTORY_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
}