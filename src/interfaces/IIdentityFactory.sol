// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IIdentityFactory
 * @dev Interface for the IdentityFactory contract that deploys identity contracts
 */
interface IIdentityFactory {
    /**
     * @dev Step 1 of secure identity creation: Commit to creating an identity
     */
    function commitIdentity(bytes32 commitment) external;
    
    /**
     * @dev Step 2 of secure identity creation: Reveal and deploy identity
     */
    function revealAndDeployIdentity(uint256 nonce) external returns (address identity);
    
    /**
     * @dev Legacy deployment function (kept for backward compatibility)
     */
    function deployIdentity() external returns (address identity);
    
    /**
     * @dev Adds a new valid bytecode hash for identity contracts
     */
    function addCodeHash(bytes32 codeHash) external;
    
    /**
     * @dev Removes a bytecode hash from valid list
     */
    function removeCodeHash(bytes32 codeHash) external;
    
    /**
     * @dev Verifies if an address is an identity deployed by this factory
     */
    function isFactoryDeployed(address identity) external view returns (bool);
    
    /**
     * @dev Computes the expected bytecode hash for current Identity implementation
     */
    function getExpectedCodeHash() external pure returns (bytes32);
    
    /**
     * @dev Predicts the address where an identity would be deployed for a user
     */
    function predictIdentityAddress(address user) external view returns (address);
    
    /**
     * @dev Returns the identity registry address
     */
    function identityRegistry() external view returns (address);
    
    /**
     * @dev Returns the signer registry address
     */
    function signerRegistry() external view returns (address);
}