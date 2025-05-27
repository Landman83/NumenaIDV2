// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "../interfaces/IIdentityFactory.sol";
import "../interfaces/IIdentityRegistry.sol";
import "../interfaces/ISignerRegistry.sol";
import "./Identity.sol";
import "../libraries/Errors.sol";
import "../libraries/Events.sol";
import "../libraries/Roles.sol";

/**
 * @title IdentityFactory
 * @dev Factory contract that deploys new Identity contracts with verified bytecode.
 * This is the only contract authorized to register identities in the IdentityRegistry.
 * Ensures all identity contracts follow the same implementation and prevents malicious contracts.
 */
contract IdentityFactory is IIdentityFactory, AccessControl {
    // State variables
    IIdentityRegistry private immutable _identityRegistry;
    ISignerRegistry private immutable _signerRegistry;
    address public numenaID; // Set by NumenaID router after deployment
    mapping(bytes32 => bool) public deployedCodeHashes;
    mapping(address => bool) public deployedIdentities;
    
    // Commit-reveal scheme to prevent front-running
    mapping(address => bytes32) public commitments;
    mapping(address => uint256) public commitmentTimestamps;
    uint256 public constant COMMITMENT_DELAY = 1 minutes; // Min time between commit and reveal
    uint256 public constant COMMITMENT_EXPIRY = 1 hours; // Max time to reveal after commit
    
    // Rate limiting for deployment
    mapping(address => uint256) public lastDeploymentTimestamp;
    uint256 public constant DEPLOYMENT_RATE_LIMIT = 300; // 5 minutes between deployments per address
    
    /**
     * @dev Constructor initializes the factory with registry addresses
     * @param identityRegistryAddr Address of the IdentityRegistry contract
     * @param signerRegistryAddr Address of the SignerRegistry contract
     * @param _admin Address that will have admin role
     */
    constructor(
        address identityRegistryAddr, 
        address signerRegistryAddr,
        address _admin
    ) {
        if (identityRegistryAddr == address(0)) revert Errors.ZeroAddress();
        if (signerRegistryAddr == address(0)) revert Errors.ZeroAddress();
        if (_admin == address(0)) revert Errors.ZeroAddress();
        
        _identityRegistry = IIdentityRegistry(identityRegistryAddr);
        _signerRegistry = ISignerRegistry(signerRegistryAddr);
        
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(Roles.ADMIN_ROLE, _admin);
        
        // Add the expected bytecode hash for Identity contracts
        bytes memory bytecode = abi.encodePacked(
            type(Identity).creationCode,
            abi.encode(address(0), address(0), address(0)) // Placeholder constructor args
        );
        bytes32 codeHash = keccak256(bytecode);
        deployedCodeHashes[codeHash] = true;
    }
    
    /**
     * @dev Step 1 of identity creation: Commit to creating an identity
     * @param commitment Hash of user's address and a secret nonce
     */
    function commitIdentity(bytes32 commitment) external {
        // Ensure user doesn't already have an identity
        if (_identityRegistry.getIdentity(msg.sender) != address(0)) {
            revert Errors.IdentityAlreadyExists();
        }
        
        // Store commitment and timestamp
        commitments[msg.sender] = commitment;
        commitmentTimestamps[msg.sender] = block.timestamp;
        
        emit Events.IdentityCommitted(msg.sender, commitment, block.timestamp);
    }
    
    /**
     * @dev Step 2 of identity creation: Reveal and deploy identity
     * @param nonce The secret nonce used in the commitment
     * @return identity The address of the newly deployed Identity contract
     */
    function revealAndDeployIdentity(uint256 nonce) external returns (address identity) {
        // Rate limiting check
        if (block.timestamp < lastDeploymentTimestamp[msg.sender] + DEPLOYMENT_RATE_LIMIT) {
            revert Errors.RateLimitExceeded();
        }
        
        // Check if user already has an identity
        if (_identityRegistry.getIdentity(msg.sender) != address(0)) {
            revert Errors.IdentityAlreadyExists();
        }
        
        // Verify commitment exists
        bytes32 storedCommitment = commitments[msg.sender];
        if (storedCommitment == bytes32(0)) {
            revert Errors.NoCommitmentFound();
        }
        
        // Verify commitment timing
        uint256 commitTime = commitmentTimestamps[msg.sender];
        if (block.timestamp < commitTime + COMMITMENT_DELAY) {
            revert Errors.CommitmentTooRecent();
        }
        if (block.timestamp > commitTime + COMMITMENT_EXPIRY) {
            revert Errors.CommitmentExpired();
        }
        
        // Verify commitment matches
        bytes32 expectedCommitment = keccak256(abi.encodePacked(msg.sender, nonce));
        if (storedCommitment != expectedCommitment) {
            revert Errors.InvalidCommitment();
        }
        
        // Clear commitment
        delete commitments[msg.sender];
        delete commitmentTimestamps[msg.sender];
        
        // Deploy identity contract
        return _deployIdentity(msg.sender, nonce);
    }
    
    /**
     * @dev Legacy deployment function (kept for backward compatibility, but less secure)
     * @return identity The address of the newly deployed Identity contract
     */
    function deployIdentity() external returns (address identity) {
        // Check if user already has an identity
        if (_identityRegistry.getIdentity(msg.sender) != address(0)) {
            revert Errors.IdentityAlreadyExists();
        }
        
        // Use timestamp as nonce for legacy deployment
        return _deployIdentity(msg.sender, block.timestamp);
    }
    
    /**
     * @dev Internal function to deploy identity contract
     * @param user The user address
     * @param nonce Nonce for salt generation
     * @return identity The deployed identity address
     */
    function _deployIdentity(address user, uint256 nonce) private returns (address identity) {
        // Calculate salt for CREATE2 using user address and nonce
        bytes32 salt = keccak256(abi.encodePacked(user, nonce));
        
        // Deploy using CREATE2 for deterministic address
        bytes memory bytecode = abi.encodePacked(
            type(Identity).creationCode,
            abi.encode(user, address(_signerRegistry), numenaID)
        );
        
        assembly {
            identity := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(extcodesize(identity)) {
                revert(0, 0)
            }
        }
        
        // Verify the deployed contract matches expected bytecode hash
        bytes32 deployedCodeHash = getCodeHash(identity);
        bytes32 expectedCodeHash = getExpectedCodeHash();
        
        // Store the expected code hash if first deployment
        if (!deployedCodeHashes[expectedCodeHash]) {
            deployedCodeHashes[expectedCodeHash] = true;
        }
        
        if (!deployedCodeHashes[deployedCodeHash]) {
            revert Errors.InvalidBytecodeHash();
        }
        
        // Track deployment
        deployedIdentities[identity] = true;
        lastDeploymentTimestamp[user] = block.timestamp; // Update rate limit timestamp
        
        // Register in IdentityRegistry (only factory can do this)
        _identityRegistry.registerIdentity(identity, user);
        
        emit Events.IdentityDeployed(user, identity, address(this));
        
        return identity;
    }
    
    /**
     * @dev Adds a new valid bytecode hash for identity contracts (admin only)
     * @param codeHash The keccak256 hash of valid identity contract bytecode
     */
    function addCodeHash(bytes32 codeHash) external onlyRole(Roles.ADMIN_ROLE) {
        if (codeHash == bytes32(0)) revert Errors.InvalidBytecodeHash();
        
        deployedCodeHashes[codeHash] = true;
        emit Events.CodeHashAdded(codeHash);
    }
    
    /**
     * @dev Sets the NumenaID router address (admin only, one-time)
     * @param _numenaID Address of the NumenaID router contract
     */
    function setNumenaID(address _numenaID) external onlyRole(Roles.ADMIN_ROLE) {
        if (_numenaID == address(0)) revert Errors.ZeroAddress();
        if (numenaID != address(0)) revert Errors.AlreadyInitialized();
        
        numenaID = _numenaID;
    }
    
    /**
     * @dev Removes a bytecode hash from valid list (admin only)
     * @param codeHash The bytecode hash to remove
     */
    function removeCodeHash(bytes32 codeHash) external onlyRole(Roles.ADMIN_ROLE) {
        deployedCodeHashes[codeHash] = false;
        emit Events.CodeHashRemoved(codeHash);
    }
    
    /**
     * @dev Verifies if an address is an identity deployed by this factory
     * @param identity The address to check
     * @return bool True if deployed by this factory
     */
    function isFactoryDeployed(address identity) external view returns (bool) {
        return deployedIdentities[identity];
    }
    
    /**
     * @dev Helper function to get runtime code hash of deployed contract
     * @param contractAddress Address of the deployed contract
     * @return hash The keccak256 hash of the runtime bytecode
     */
    function getCodeHash(address contractAddress) public view returns (bytes32 hash) {
        assembly {
            hash := extcodehash(contractAddress)
        }
    }
    
    
    /**
     * @dev Predicts the address where an identity would be deployed for a user
     * @param user The user address
     * @return The predicted identity contract address
     */
    function predictIdentityAddress(address user) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(user));
        bytes memory bytecode = abi.encodePacked(
            type(Identity).creationCode,
            abi.encode(user, address(_signerRegistry), numenaID)
        );
        
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(bytecode)
            )
        );
        
        return address(uint160(uint256(hash)));
    }
    
    /**
     * @dev Computes the expected bytecode hash for current Identity implementation
     * @return The keccak256 hash of the Identity runtime bytecode
     */
    function getExpectedCodeHash() public pure returns (bytes32) {
        // Return a placeholder hash since we can't compute runtime code with immutables
        // This would be set by the deployer after deployment
        return bytes32(0);
    }
    
    /**
     * @dev Returns the identity registry address
     */
    function identityRegistry() external view returns (address) {
        return address(_identityRegistry);
    }
    
    /**
     * @dev Returns the signer registry address
     */
    function signerRegistry() external view returns (address) {
        return address(_signerRegistry);
    }
}