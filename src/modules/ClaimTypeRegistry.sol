// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "../interfaces/IClaimTypeRegistry.sol";
import "../libraries/Errors.sol";
import "../libraries/Events.sol";
import "../libraries/Roles.sol";

/**
 * @title ClaimTypeRegistry
 * @dev Registry of claim types mapping numeric IDs to human-readable metadata.
 * Each claim type has a title, legal definition document, and expected data type.
 * This allows frontends to display "Accredited Investor" instead of "2".
 */
contract ClaimTypeRegistry is IClaimTypeRegistry, AccessControl {
    // State variables
    mapping(uint256 => ClaimType) public claimTypes;
    uint256[] public claimTypeIds;
    
    // Predefined claim type constants
    uint256 public constant KYC_AML = 1;
    uint256 public constant ACCREDITED_INVESTOR = 2;
    uint256 public constant INSTITUTIONAL_INVESTOR = 3;
    uint256 public constant INSIDER_STATUS = 4;
    
    // Document type constants
    uint256 public constant PASSPORT = 1;
    uint256 public constant DRIVERS_LICENSE = 2;
    uint256 public constant UTILITY_BILL = 3;
    uint256 public constant BANK_STATEMENT = 4;
    uint256 public constant INCOME_STATEMENT = 5;
    uint256 public constant TAX_RETURN = 6;
    uint256 public constant CORPORATE_DOCS = 7;
    uint256 public constant AUTHORIZATION_LETTER = 8;
    uint256 public constant NET_WORTH_STATEMENT = 9;
    uint256 public constant INVESTMENT_PORTFOLIO = 10;
    
    /**
     * @dev Constructor initializes standard claim types
     * @param _admin Address that will have admin role
     */
    constructor(address _admin) {
        if (_admin == address(0)) revert Errors.ZeroAddress();
        
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(Roles.ADMIN_ROLE, _admin);
        
        // Initialize standard claim types with required documents
        uint256[] memory kycDocs = new uint256[](2);
        kycDocs[0] = PASSPORT;
        kycDocs[1] = UTILITY_BILL;
        _addClaimType(KYC_AML, "KYC/AML Verified", kycDocs, "bool");
        
        uint256[] memory accreditedDocs = new uint256[](2);
        accreditedDocs[0] = INCOME_STATEMENT;
        accreditedDocs[1] = BANK_STATEMENT;
        _addClaimType(ACCREDITED_INVESTOR, "Accredited Investor", accreditedDocs, "bool");
        
        uint256[] memory institutionalDocs = new uint256[](2);
        institutionalDocs[0] = CORPORATE_DOCS;
        institutionalDocs[1] = AUTHORIZATION_LETTER;
        _addClaimType(INSTITUTIONAL_INVESTOR, "Institutional Investor", institutionalDocs, "bool");
        
        uint256[] memory insiderDocs = new uint256[](1);
        insiderDocs[0] = CORPORATE_DOCS;
        _addClaimType(INSIDER_STATUS, "Insider Status", insiderDocs, "bytes");
    }
    
    /**
     * @dev Adds a new claim type to the registry
     * @param claimTypeId Unique numeric ID for this claim type
     * @param title Human-readable name for the claim
     * @param requiredDocumentTypes Array of required document types
     * @param dataType Expected data encoding type
     */
    function addClaimType(
        uint256 claimTypeId,
        string calldata title,
        uint256[] calldata requiredDocumentTypes,
        string calldata dataType
    ) external onlyRole(Roles.ADMIN_ROLE) {
        if (claimTypes[claimTypeId].active) revert Errors.InvalidClaimType();
        if (bytes(title).length == 0) revert Errors.InvalidData();
        if (bytes(dataType).length == 0) revert Errors.InvalidData();
        
        _addClaimType(claimTypeId, title, requiredDocumentTypes, dataType);
    }
    
    /**
     * @dev Removes a claim type (marks as inactive)
     * @param claimTypeId The claim type ID to remove
     */
    function removeClaimType(uint256 claimTypeId) external onlyRole(Roles.ADMIN_ROLE) {
        if (!claimTypes[claimTypeId].active) revert Errors.InvalidClaimType();
        
        claimTypes[claimTypeId].active = false;
        
        // Remove from claimTypeIds array
        uint256 length = claimTypeIds.length;
        for (uint256 i = 0; i < length; i++) {
            if (claimTypeIds[i] == claimTypeId) {
                claimTypeIds[i] = claimTypeIds[length - 1];
                claimTypeIds.pop();
                break;
            }
        }
        
        emit Events.ClaimTypeRemoved(claimTypeId);
    }
    
    /**
     * @dev Updates metadata for an existing claim type
     * @param claimTypeId The claim type ID to update
     * @param title New human-readable title
     * @param requiredDocumentTypes New required document types
     * @param dataType New data type specification
     */
    function updateClaimType(
        uint256 claimTypeId,
        string calldata title,
        uint256[] calldata requiredDocumentTypes,
        string calldata dataType
    ) external onlyRole(Roles.ADMIN_ROLE) {
        if (!claimTypes[claimTypeId].active) revert Errors.InvalidClaimType();
        if (bytes(title).length == 0) revert Errors.InvalidData();
        if (bytes(dataType).length == 0) revert Errors.InvalidData();
        
        ClaimType storage claimType = claimTypes[claimTypeId];
        claimType.title = title;
        claimType.requiredDocumentTypes = requiredDocumentTypes;
        claimType.dataType = dataType;
        
        emit Events.ClaimTypeUpdated(claimTypeId, title, requiredDocumentTypes);
    }
    
    /**
     * @dev Returns metadata for a specific claim type
     * @param claimTypeId The claim type to query
     * @return title Human-readable name
     * @return requiredDocumentTypes Array of required document types
     * @return dataType Expected data encoding
     * @return active Whether claim type is active
     */
    function getClaimType(uint256 claimTypeId) external view returns (
        string memory title,
        uint256[] memory requiredDocumentTypes,
        string memory dataType,
        bool active
    ) {
        ClaimType memory claimType = claimTypes[claimTypeId];
        return (claimType.title, claimType.requiredDocumentTypes, claimType.dataType, claimType.active);
    }
    
    /**
     * @dev Returns all registered claim type IDs
     * @return Array of claim type IDs
     */
    function getAllClaimTypes() external view returns (uint256[] memory) {
        return claimTypeIds;
    }
    
    /**
     * @dev Returns required document types for a claim
     * @param claimTypeId The claim type to query
     * @return Array of required document types
     */
    function getRequiredDocuments(uint256 claimTypeId) external view returns (uint256[] memory) {
        if (!claimTypes[claimTypeId].active) revert Errors.InvalidClaimType();
        return claimTypes[claimTypeId].requiredDocumentTypes;
    }
    
    /**
     * @dev Checks if a claim type ID is registered and active
     * @param claimTypeId The claim type to check
     * @return True if registered and active
     */
    function isValidClaimType(uint256 claimTypeId) external view returns (bool) {
        return claimTypes[claimTypeId].active;
    }
    
    /**
     * @dev Internal function to add claim types
     */
    function _addClaimType(
        uint256 claimTypeId,
        string memory title,
        uint256[] memory requiredDocumentTypes,
        string memory dataType
    ) internal {
        claimTypes[claimTypeId] = ClaimType({
            title: title,
            requiredDocumentTypes: requiredDocumentTypes,
            dataType: dataType,
            active: true
        });
        
        claimTypeIds.push(claimTypeId);
        
        emit Events.ClaimTypeAdded(claimTypeId, title, requiredDocumentTypes);
    }
}