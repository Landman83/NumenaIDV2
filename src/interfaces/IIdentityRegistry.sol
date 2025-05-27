// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IIdentityRegistry
 * @dev Interface for the IdentityRegistry contract that maps wallets to identity contracts
 */
interface IIdentityRegistry {
    /**
     * @dev Registers a new identity contract for a wallet (factory only)
     */
    function registerIdentity(address identityContract, address owner) external;
    
    /**
     * @dev Removes identity mapping for caller's wallet
     */
    function removeIdentity() external;
    
    /**
     * @dev Returns the identity contract address for a given wallet
     */
    function getIdentity(address wallet) external view returns (address);
    
    /**
     * @dev Returns the total count of registered identities
     */
    function getIdentityCount() external view returns (uint256);
    
    /**
     * @dev Updates caller's identity contract to a new one
     */
    function updateIdentity(address newIdentity) external;
    
    /**
     * @dev Checks if a wallet has a registered identity
     */
    function hasIdentity(address wallet) external view returns (bool);
    
    /**
     * @dev Returns the address of the identity factory
     */
    function identityFactory() external view returns (address);
}