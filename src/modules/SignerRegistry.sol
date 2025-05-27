// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/ISignerRegistry.sol";
import "../interfaces/IIdentityFactory.sol";
import "../libraries/Errors.sol";
import "../libraries/Events.sol";
import "../libraries/Roles.sol";

/**
 * @title SignerRegistry
 * @dev Registry of authorized signers (verifiers) who can create claims on identity contracts.
 * Signers are trusted partners with SEC licenses who verify user documents and create claims.
 * Only admin can add/remove signers. Tracks which claim types each signer is authorized for.
 */
contract SignerRegistry is ISignerRegistry, AccessControl, ReentrancyGuard {
    // State variables
    mapping(address => SignerInfo) public signers;
    address[] public signerList;
    mapping(uint256 => address[]) public claimTypeToSigners;
    address public identityFactory; // Only factory-deployed identities can increment counts
    
    /**
     * @dev Constructor sets up admin role
     * @param _admin Address that will have admin role
     */
    constructor(address _admin) {
        if (_admin == address(0)) revert Errors.ZeroAddress();
        
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(Roles.ADMIN_ROLE, _admin);
    }
    
    /**
     * @dev Adds a new authorized signer with specific claim type permissions
     * @param signer Address of the signer to authorize
     * @param allowedClaimTypes Array of claim type IDs this signer can create
     * @param name Human-readable name of the signer organization
     */
    function addSigner(
        address signer,
        uint256[] calldata allowedClaimTypes,
        string calldata name
    ) external onlyRole(Roles.ADMIN_ROLE) nonReentrant {
        if (signer == address(0)) revert Errors.ZeroAddress();
        if (allowedClaimTypes.length == 0) revert Errors.EmptyArray();
        if (allowedClaimTypes.length > 100) revert Errors.BatchSizeTooLarge(); // Prevent gas exhaustion
        if (bytes(name).length == 0) revert Errors.InvalidData();
        if (signers[signer].active) revert Errors.SignerAlreadyActive();
        
        signers[signer] = SignerInfo({
            active: true,
            allowedClaimTypes: allowedClaimTypes,
            addedAt: block.timestamp,
            totalClaims: 0,
            revokedClaims: 0,
            name: name
        });
        
        signerList.push(signer);
        
        // Update claim type mappings
        for (uint256 i = 0; i < allowedClaimTypes.length; i++) {
            claimTypeToSigners[allowedClaimTypes[i]].push(signer);
        }
        
        emit Events.SignerAdded(signer, allowedClaimTypes, name);
    }
    
    /**
     * @dev Removes a signer's authorization (does not affect existing claims)
     * @param signer Address of the signer to remove
     */
    function removeSigner(address signer) external onlyRole(Roles.ADMIN_ROLE) nonReentrant {
        if (!signers[signer].active) revert Errors.SignerNotActive();
        
        signers[signer].active = false;
        
        // Remove from signerList array
        uint256 length = signerList.length;
        for (uint256 i = 0; i < length; i++) {
            if (signerList[i] == signer) {
                signerList[i] = signerList[length - 1];
                signerList.pop();
                break;
            }
        }
        
        // Remove from claim type mappings
        uint256[] memory allowedTypes = signers[signer].allowedClaimTypes;
        for (uint256 i = 0; i < allowedTypes.length; i++) {
            address[] storage signersForType = claimTypeToSigners[allowedTypes[i]];
            uint256 typeLength = signersForType.length;
            
            for (uint256 j = 0; j < typeLength; j++) {
                if (signersForType[j] == signer) {
                    signersForType[j] = signersForType[typeLength - 1];
                    signersForType.pop();
                    break;
                }
            }
        }
        
        emit Events.SignerRemoved(signer);
    }
    
    /**
     * @dev Returns all active signer addresses
     * @return Array of active signer addresses
     */
    function getSigners() external view returns (address[] memory) {
        uint256 activeCount = 0;
        uint256 length = signerList.length;
        
        // Count active signers
        for (uint256 i = 0; i < length; i++) {
            if (signers[signerList[i]].active) {
                activeCount++;
            }
        }
        
        // Build array of active signers
        address[] memory activeSigners = new address[](activeCount);
        uint256 index = 0;
        
        for (uint256 i = 0; i < length; i++) {
            if (signers[signerList[i]].active) {
                activeSigners[index] = signerList[i];
                index++;
            }
        }
        
        return activeSigners;
    }
    
    /**
     * @dev Returns all signers authorized for a specific claim type
     * @param claimType The claim type to query
     * @return Array of signer addresses authorized for this claim type
     */
    function getSignersForClaim(uint256 claimType) external view returns (address[] memory) {
        address[] memory signersForType = claimTypeToSigners[claimType];
        uint256 length = signersForType.length;
        uint256 activeCount = 0;
        
        // Count active signers for this type
        for (uint256 i = 0; i < length; i++) {
            if (signers[signersForType[i]].active) {
                activeCount++;
            }
        }
        
        // Build array of active signers for this type
        address[] memory activeSigners = new address[](activeCount);
        uint256 index = 0;
        
        for (uint256 i = 0; i < length; i++) {
            if (signers[signersForType[i]].active) {
                activeSigners[index] = signersForType[i];
                index++;
            }
        }
        
        return activeSigners;
    }
    
    /**
     * @dev Returns the total count of active signers
     * @return Number of active signers
     */
    function getSignerCount() external view returns (uint256) {
        uint256 count = 0;
        uint256 length = signerList.length;
        
        for (uint256 i = 0; i < length; i++) {
            if (signers[signerList[i]].active) {
                count++;
            }
        }
        
        return count;
    }
    
    /**
     * @dev Checks if an address is an active signer
     * @param signer Address to check
     * @return True if signer is active
     */
    function isValidSigner(address signer) external view returns (bool) {
        return signers[signer].active;
    }
    
    /**
     * @dev Checks if a signer can create a specific claim type
     * @param signer Address of the signer
     * @param claimType The claim type to check
     * @return True if signer can create this claim type
     */
    function canSignClaimType(address signer, uint256 claimType) external view returns (bool) {
        if (!signers[signer].active) return false;
        
        uint256[] memory allowedTypes = signers[signer].allowedClaimTypes;
        for (uint256 i = 0; i < allowedTypes.length; i++) {
            if (allowedTypes[i] == claimType) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * @dev Updates the allowed claim types for an existing signer
     * @param signer Address of the signer to update
     * @param newAllowedClaimTypes New array of allowed claim types
     */
    function updateSignerClaimTypes(
        address signer,
        uint256[] calldata newAllowedClaimTypes
    ) external onlyRole(Roles.ADMIN_ROLE) nonReentrant {
        if (!signers[signer].active) revert Errors.SignerNotActive();
        if (newAllowedClaimTypes.length == 0) revert Errors.EmptyArray();
        
        // Remove old claim type mappings
        uint256[] memory oldTypes = signers[signer].allowedClaimTypes;
        for (uint256 i = 0; i < oldTypes.length; i++) {
            address[] storage signersForType = claimTypeToSigners[oldTypes[i]];
            uint256 typeLength = signersForType.length;
            
            for (uint256 j = 0; j < typeLength; j++) {
                if (signersForType[j] == signer) {
                    signersForType[j] = signersForType[typeLength - 1];
                    signersForType.pop();
                    break;
                }
            }
        }
        
        // Update allowed claim types
        signers[signer].allowedClaimTypes = newAllowedClaimTypes;
        
        // Add new claim type mappings
        for (uint256 i = 0; i < newAllowedClaimTypes.length; i++) {
            claimTypeToSigners[newAllowedClaimTypes[i]].push(signer);
        }
        
        emit Events.SignerUpdated(signer, newAllowedClaimTypes);
    }
    
    /**
     * @dev Increments claim count for a signer (called by Identity contracts)
     * @param signer Address of the signer who created a claim
     */
    function incrementClaimCount(address signer) external nonReentrant {
        // Only allow calls from factory-deployed Identity contracts
        if (identityFactory == address(0)) revert Errors.IdentityFactoryNotSet();
        if (!IIdentityFactory(identityFactory).isFactoryDeployed(msg.sender)) {
            revert Errors.InvalidIdentityContract();
        }
        
        signers[signer].totalClaims++;
    }
    
    /**
     * @dev Sets the identity factory address (admin only, one-time)
     * @param _identityFactory Address of the IdentityFactory contract
     */
    function setIdentityFactory(address _identityFactory) external onlyRole(Roles.ADMIN_ROLE) {
        if (_identityFactory == address(0)) revert Errors.ZeroAddress();
        if (identityFactory != address(0)) revert Errors.FactoryAlreadySet();
        
        identityFactory = _identityFactory;
    }
    
    /**
     * @dev Returns detailed information about a signer
     * @param signer Address to query
     * @return Complete signer information struct
     */
    function getSignerInfo(address signer) external view returns (SignerInfo memory) {
        return signers[signer];
    }
    
    /**
     * @dev Returns paginated list of active signers
     * @param offset Starting index
     * @param limit Maximum number of signers to return
     * @return activeSigners Array of active signer addresses
     * @return total Total number of active signers
     */
    function getSignersPaginated(
        uint256 offset,
        uint256 limit
    ) external view returns (address[] memory activeSigners, uint256 total) {
        // Count total active signers
        uint256 activeCount = 0;
        uint256 length = signerList.length;
        
        for (uint256 i = 0; i < length; i++) {
            if (signers[signerList[i]].active) {
                activeCount++;
            }
        }
        
        total = activeCount;
        
        // Handle edge cases
        if (offset >= activeCount || limit == 0) {
            return (new address[](0), total);
        }
        
        // Calculate actual limit
        uint256 actualLimit = limit;
        if (offset + limit > activeCount) {
            actualLimit = activeCount - offset;
        }
        
        // Create result array
        activeSigners = new address[](actualLimit);
        uint256 currentIndex = 0;
        uint256 resultIndex = 0;
        
        // Populate paginated results
        for (uint256 i = 0; i < length && resultIndex < actualLimit; i++) {
            if (signers[signerList[i]].active) {
                if (currentIndex >= offset) {
                    activeSigners[resultIndex] = signerList[i];
                    resultIndex++;
                }
                currentIndex++;
            }
        }
    }
    
    /**
     * @dev Returns paginated list of signers authorized for a specific claim type
     * @param claimType The claim type to query
     * @param offset Starting index
     * @param limit Maximum number of signers to return
     * @return activeSigners Array of signer addresses authorized for this claim type
     * @return total Total number of active signers for this claim type
     */
    function getSignersForClaimPaginated(
        uint256 claimType,
        uint256 offset,
        uint256 limit
    ) external view returns (address[] memory activeSigners, uint256 total) {
        address[] memory signersForType = claimTypeToSigners[claimType];
        uint256 length = signersForType.length;
        uint256 activeCount = 0;
        
        // Count active signers for this type
        for (uint256 i = 0; i < length; i++) {
            if (signers[signersForType[i]].active) {
                activeCount++;
            }
        }
        
        total = activeCount;
        
        // Handle edge cases
        if (offset >= activeCount || limit == 0) {
            return (new address[](0), total);
        }
        
        // Calculate actual limit
        uint256 actualLimit = limit;
        if (offset + limit > activeCount) {
            actualLimit = activeCount - offset;
        }
        
        // Create result array
        activeSigners = new address[](actualLimit);
        uint256 currentIndex = 0;
        uint256 resultIndex = 0;
        
        // Populate paginated results
        for (uint256 i = 0; i < length && resultIndex < actualLimit; i++) {
            if (signers[signersForType[i]].active) {
                if (currentIndex >= offset) {
                    activeSigners[resultIndex] = signersForType[i];
                    resultIndex++;
                }
                currentIndex++;
            }
        }
    }
}