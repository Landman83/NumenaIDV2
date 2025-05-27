// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../interfaces/IIdentityRegistry.sol";
import "../interfaces/IIdentity.sol";
import "../libraries/Errors.sol";
import "../libraries/Events.sol";

/**
 * @title IdentityRegistry
 * @dev Central registry mapping wallet addresses to their identity contracts.
 * Only the IdentityFactory can register new identities to prevent unauthorized contracts.
 * Users can update their identity contract if needed (e.g., for upgrades).
 */
contract IdentityRegistry is IIdentityRegistry {
    // State variables
    address public immutable identityFactory;
    mapping(address => address) public walletToIdentity;
    uint256 public identityCount;
    
    // Modifiers
    modifier onlyFactory() {
        if (msg.sender != identityFactory) revert Errors.OnlyFactory();
        _;
    }
    
    /**
     * @dev Constructor sets the authorized IdentityFactory
     * @param _identityFactory Address of the IdentityFactory contract
     */
    constructor(address _identityFactory) {
        if (_identityFactory == address(0)) revert Errors.ZeroAddress();
        identityFactory = _identityFactory;
    }
    
    /**
     * @dev Registers a new identity contract for a wallet (factory only)
     * @param identityContract Address of the deployed Identity contract
     * @param owner The wallet address that owns this identity
     */
    function registerIdentity(address identityContract, address owner) external onlyFactory {
        if (identityContract == address(0)) revert Errors.ZeroAddress();
        if (owner == address(0)) revert Errors.ZeroAddress();
        
        // Verify identity contract has correct owner
        if (IIdentity(identityContract).owner() != owner) {
            revert Errors.OwnerMismatch();
        }
        
        // Check if wallet already has identity
        if (walletToIdentity[owner] != address(0)) {
            revert Errors.IdentityAlreadyExists();
        }
        
        walletToIdentity[owner] = identityContract;
        identityCount++;
        
        emit Events.IdentityRegistered(owner, identityContract);
    }
    
    /**
     * @dev Removes identity mapping for caller's wallet
     */
    function removeIdentity() external {
        address identity = walletToIdentity[msg.sender];
        if (identity == address(0)) revert Errors.IdentityNotFound();
        
        delete walletToIdentity[msg.sender];
        identityCount--;
        
        emit Events.IdentityRemoved(msg.sender, identity);
    }
    
    /**
     * @dev Returns the identity contract address for a given wallet
     * @param wallet The wallet address to query
     * @return The identity contract address (or zero address if none)
     */
    function getIdentity(address wallet) external view returns (address) {
        return walletToIdentity[wallet];
    }
    
    /**
     * @dev Returns the total count of registered identities
     * @return The number of identities registered
     */
    function getIdentityCount() external view returns (uint256) {
        return identityCount;
    }
    
    /**
     * @dev Updates caller's identity contract to a new one
     * @param newIdentity Address of the new identity contract
     */
    function updateIdentity(address newIdentity) external {
        if (newIdentity == address(0)) revert Errors.ZeroAddress();
        
        address oldIdentity = walletToIdentity[msg.sender];
        if (oldIdentity == address(0)) revert Errors.IdentityNotFound();
        
        // Verify new identity has correct owner
        if (IIdentity(newIdentity).owner() != msg.sender) {
            revert Errors.OwnerMismatch();
        }
        
        walletToIdentity[msg.sender] = newIdentity;
        
        emit Events.IdentityUpdated(msg.sender, oldIdentity, newIdentity);
    }
    
    /**
     * @dev Checks if a wallet has a registered identity
     * @param wallet The wallet address to check
     * @return True if wallet has an identity
     */
    function hasIdentity(address wallet) external view returns (bool) {
        return walletToIdentity[wallet] != address(0);
    }
}

// only the exchange, STO, or registered token addresses can query the identity registry to further enhance privacy