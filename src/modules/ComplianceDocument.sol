// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IComplianceDocument.sol";
import "../interfaces/ISignerRegistry.sol";
import "../libraries/Errors.sol";

/**
 * @title ComplianceDocument
 * @notice NFT-based document ownership and access control for compliance documentation
 * @dev Each NFT represents ownership of an encrypted document stored off-chain
 * 
 * Key features:
 * - Document ownership via ERC721
 * - Access control: owner + authorized signers from SignerRegistry
 * - Complete audit trail of all document access
 * - Metadata storage for document verification
 * - Integration with Identity claims system
 */
contract ComplianceDocument is IComplianceDocument, ERC721, AccessControl, ReentrancyGuard {
    // ============ Constants ============
    
    // Access type constants
    uint8 public constant ACCESS_TYPE_OWNER = 0;
    uint8 public constant ACCESS_TYPE_VERIFIER = 1;
    uint8 public constant ACCESS_TYPE_REGULATOR = 2;
    uint8 public constant ACCESS_TYPE_DELEGATED = 3;
    
    // Operational limits
    uint256 public constant MAX_DOCUMENTS_TO_SCAN = 10000;
    
    // ============ Structs ============
    // Note: Document and AccessRecord structs are defined in IComplianceDocument interface
    
    // ============ State Variables ============
    
    /// @notice Registry of authorized signers who can access documents for verification
    ISignerRegistry public immutable signerRegistry;
    
    /// @notice Mapping from tokenId to document metadata
    mapping(uint256 => Document) public documents;
    
    /// @notice Mapping from tokenId to array of access records (full audit trail)
    mapping(uint256 => AccessRecord[]) public accessHistory;
    
    /// @notice Counter for generating unique token IDs
    uint256 private _tokenIdCounter;
    
    /// @notice Admin role for system configuration
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    
    /// @notice Special role for regulatory access (future use)
    bytes32 public constant REGULATOR_ROLE = keccak256("REGULATOR_ROLE");
    
    // ============ Events ============
    
    /**
     * @notice Emitted when a document is accessed
     * @param tokenId The document NFT that was accessed
     * @param accessor Address that accessed the document
     * @param accessType Type of access (0=Owner, 1=Verifier, etc.)
     */
    event DocumentAccessed(uint256 indexed tokenId, address indexed accessor, uint8 accessType);
    
    /**
     * @notice Emitted when a new document is minted
     * @param tokenId The newly minted token ID
     * @param owner The owner of the document
     * @param documentType Category of the document
     * @param fileHash Hash of the document content
     */
    event DocumentMinted(uint256 indexed tokenId, address indexed owner, uint256 documentType, string fileHash);
    
    // ============ Constructor ============
    
    /**
     * @notice Initialize the ComplianceDocument contract
     * @param _signerRegistry Address of the SignerRegistry contract
     * @param _name Name for the ERC721 token
     * @param _symbol Symbol for the ERC721 token
     */
    constructor(
        address _signerRegistry,
        string memory _name,
        string memory _symbol
    ) ERC721(_name, _symbol) {
        signerRegistry = ISignerRegistry(_signerRegistry);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }
    
    // ============ External Functions ============
    
    /**
     * @notice Mint a new document NFT
     * @dev Only callable by document owner, creates initial access record
     * @param fileHash SHA256 hash of the document content
     * @param localPath Off-chain storage location reference
     * @param documentType Category of document (KYC=1, ACCREDITATION=2, etc.)
     * @param fileSize Size of document in bytes
     * @return tokenId The ID of the newly minted NFT
     */
    function mintDocument(
        string memory fileHash,
        string memory localPath,
        uint256 documentType,
        uint256 fileSize
    ) external nonReentrant returns (uint256) {
        if (bytes(fileHash).length == 0) revert Errors.InvalidFileHash();
        if (bytes(localPath).length == 0) revert Errors.InvalidLocalPath();
        if (documentType == 0) revert Errors.InvalidDocumentType();
        if (fileSize == 0) revert Errors.InvalidFileSize();
        
        uint256 tokenId = _tokenIdCounter++;
        
        documents[tokenId] = Document({
            fileHash: fileHash,
            localPath: localPath,
            documentType: documentType,
            uploadedAt: block.timestamp,
            fileSize: fileSize,
            uploadedBy: msg.sender
        });
        
        _safeMint(msg.sender, tokenId);
        
        _recordAccess(tokenId, msg.sender, 0); // 0 = Owner access
        
        emit DocumentMinted(tokenId, msg.sender, documentType, fileHash);
        
        return tokenId;
    }
    
    /**
     * @notice Retrieve document metadata without recording access
     * @dev View function for read-only access checks
     * @param tokenId The document NFT to retrieve
     * @return Document struct with all metadata
     */
    function viewDocument(uint256 tokenId) external view returns (Document memory) {
        if (_ownerOf(tokenId) == address(0)) revert Errors.DocumentDoesNotExist();
        if (!canAccessDocument(tokenId, msg.sender)) revert Errors.UnauthorizedDocumentAccess();
        return documents[tokenId];
    }
    
    /**
     * @notice Retrieve document metadata with automatic access recording
     * @dev Records access in audit trail and returns document data
     * @param tokenId The document NFT to retrieve
     * @return Document struct with all metadata
     */
    function getDocument(uint256 tokenId) external nonReentrant returns (Document memory) {
        if (_ownerOf(tokenId) == address(0)) revert Errors.DocumentDoesNotExist();
        if (!canAccessDocument(tokenId, msg.sender)) revert Errors.UnauthorizedDocumentAccess();
        
        // Determine access type
        uint8 accessType;
        if (ownerOf(tokenId) == msg.sender) {
            accessType = ACCESS_TYPE_OWNER;
        } else if (signerRegistry.isValidSigner(msg.sender)) {
            accessType = ACCESS_TYPE_VERIFIER;
        } else if (hasRole(REGULATOR_ROLE, msg.sender)) {
            accessType = ACCESS_TYPE_REGULATOR;
        } else {
            accessType = ACCESS_TYPE_DELEGATED;
        }
        
        // Record access before returning data
        _recordAccess(tokenId, msg.sender, accessType);
        
        return documents[tokenId];
    }
    
    /**
     * @notice Record document access for audit trail
     * @dev Must be called separately after getDocument() to maintain audit trail
     * @param tokenId The document that was accessed
     * @param accessor Address that accessed the document
     */
    function recordDocumentAccess(uint256 tokenId, address accessor) external nonReentrant {
        if (_ownerOf(tokenId) == address(0)) revert Errors.DocumentDoesNotExist();
        if (!canAccessDocument(tokenId, accessor)) revert Errors.AccessorNotAuthorized();
        
        // Only authorized contracts can record access
        if (msg.sender != address(this) && 
            !signerRegistry.isValidSigner(msg.sender) &&
            !hasRole(ADMIN_ROLE, msg.sender)) {
            revert Errors.CallerNotAuthorizedToRecordAccess();
        }
        
        uint8 accessType;
        if (ownerOf(tokenId) == accessor) {
            accessType = ACCESS_TYPE_OWNER;
        } else if (signerRegistry.isValidSigner(accessor)) {
            accessType = ACCESS_TYPE_VERIFIER;
        } else if (hasRole(REGULATOR_ROLE, accessor)) {
            accessType = ACCESS_TYPE_REGULATOR;
        } else {
            accessType = ACCESS_TYPE_DELEGATED;
        }
        
        _recordAccess(tokenId, accessor, accessType);
    }
    
    /**
     * @notice Retrieve complete access history for a document
     * @dev Only accessible by document owner
     * @param tokenId The document NFT
     * @return Array of all access records
     */
    function getAccessHistory(uint256 tokenId) external view returns (AccessRecord[] memory) {
        if (_ownerOf(tokenId) == address(0)) revert Errors.DocumentDoesNotExist();
        if (ownerOf(tokenId) != msg.sender && !hasRole(ADMIN_ROLE, msg.sender)) revert Errors.NotDocumentOwner();
        return accessHistory[tokenId];
    }
    
    /**
     * @notice Check if an address can access a document
     * @param tokenId The document NFT
     * @param accessor Address to check
     * @return bool True if accessor can access the document
     */
    function canAccessDocument(uint256 tokenId, address accessor) public view returns (bool) {
        if (_ownerOf(tokenId) == address(0)) return false;
        
        // Owner can always access
        if (ownerOf(tokenId) == accessor) return true;
        
        // Authorized signers can access
        if (signerRegistry.isValidSigner(accessor)) return true;
        
        // Regulators can access
        if (hasRole(REGULATOR_ROLE, accessor)) return true;
        
        return false;
    }
    
    // ============ Admin Functions ============
    
    /**
     * @notice Grant regulator role to an address
     * @dev Only callable by admin
     * @param regulator Address to grant regulator access
     */
    function addRegulator(address regulator) external onlyRole(ADMIN_ROLE) {
        if (regulator == address(0)) revert Errors.ZeroAddress();
        grantRole(REGULATOR_ROLE, regulator);
    }
    
    /**
     * @notice Remove regulator role from an address
     * @dev Only callable by admin
     * @param regulator Address to revoke regulator access
     */
    function removeRegulator(address regulator) external onlyRole(ADMIN_ROLE) {
        if (regulator == address(0)) revert Errors.ZeroAddress();
        revokeRole(REGULATOR_ROLE, regulator);
    }
    
    // ============ Internal Functions ============
    
    /**
     * @notice Internal function to record access
     * @dev Appends new AccessRecord to document's history
     * @param tokenId The document being accessed
     * @param accessor Who is accessing
     * @param accessType Type of access
     */
    function _recordAccess(uint256 tokenId, address accessor, uint8 accessType) private {
        AccessRecord memory record = AccessRecord({
            accessor: accessor,
            accessType: accessType,
            timestamp: uint48(block.timestamp)
        });
        
        accessHistory[tokenId].push(record);
        
        emit DocumentAccessed(tokenId, accessor, accessType);
    }
    
    /**
     * @dev Internal function to get documents by owner with optional type filter
     * @param owner Address to query
     * @param filterByType Whether to filter by document type
     * @param documentType Type of documents to filter (if filterByType is true)
     * @return Array of token IDs matching the criteria
     */
    function _getDocumentsByOwner(
        address owner, 
        bool filterByType, 
        uint256 documentType
    ) internal view returns (uint256[] memory) {
        uint256 balance = balanceOf(owner);
        uint256[] memory tempIds = new uint256[](balance);
        
        // Limit scan to prevent gas exhaustion
        uint256 maxToScan = _tokenIdCounter > MAX_DOCUMENTS_TO_SCAN ? MAX_DOCUMENTS_TO_SCAN : _tokenIdCounter;
        
        uint256 count = 0;
        for (uint256 i = 0; i < maxToScan && count < balance; i++) {
            if (_ownerOf(i) != address(0) && ownerOf(i) == owner) {
                if (!filterByType || documents[i].documentType == documentType) {
                    tempIds[count++] = i;
                }
            }
        }
        
        // Resize array to actual count
        if (count < balance) {
            uint256[] memory result = new uint256[](count);
            for (uint256 i = 0; i < count; i++) {
                result[i] = tempIds[i];
            }
            return result;
        }
        
        return tempIds;
    }
    
    /**
     * @notice Hook that is called on token updates (transfers, mints, burns)
     * @dev Records document access when ownership changes
     */
    function _update(address to, uint256 tokenId, address auth) internal virtual override returns (address) {
        address from = super._update(to, tokenId, auth);
        
        // Record access for new owner on transfers (not mints or burns)
        if (from != address(0) && to != address(0)) {
            _recordAccess(tokenId, to, 0); // New owner access
        }
        
        return from;
    }
    
    // ============ View Functions ============
    
    /**
     * @notice Get total number of documents minted
     * @return Current token counter value
     */
    function totalDocuments() external view returns (uint256) {
        return _tokenIdCounter;
    }
    
    /**
     * @notice Get all document IDs owned by a specific address
     * @param owner Address to query
     * @return Array of token IDs owned by the address
     */
    function getDocumentsByOwner(address owner) external view returns (uint256[] memory) {
        return _getDocumentsByOwner(owner, false, 0);
    }
    
    /**
     * @notice Get all documents of a specific type owned by an address
     * @param owner Address to query
     * @param documentType Type of documents to filter
     * @return Array of token IDs matching the criteria
     */
    function getDocumentsByOwnerAndType(address owner, uint256 documentType) external view returns (uint256[] memory) {
        return _getDocumentsByOwner(owner, true, documentType);
    }
    
    /**
     * @notice Get the most recent document of a specific type owned by an address
     * @param owner Address to query
     * @param documentType Type of document to find
     * @return tokenId The ID of the most recent document (0 if none found)
     * @return found Whether a document was found
     */
    function getMostRecentDocumentByOwnerAndType(address owner, uint256 documentType) external view returns (uint256 tokenId, bool found) {
        uint256[] memory matchingDocs = _getDocumentsByOwner(owner, true, documentType);
        
        if (matchingDocs.length == 0) {
            return (0, false);
        }
        
        // Find the most recent document
        uint256 mostRecentId = matchingDocs[0];
        uint256 mostRecentTime = documents[matchingDocs[0]].uploadedAt;
        
        for (uint256 i = 1; i < matchingDocs.length; i++) {
            if (documents[matchingDocs[i]].uploadedAt > mostRecentTime) {
                mostRecentId = matchingDocs[i];
                mostRecentTime = documents[matchingDocs[i]].uploadedAt;
            }
        }
        
        return (mostRecentId, true);
    }
    
    /**
     * @notice Get access history length for a document
     * @param tokenId The document NFT
     * @return Number of access records
     */
    function getAccessHistoryLength(uint256 tokenId) external view returns (uint256) {
        if (_ownerOf(tokenId) == address(0)) revert Errors.DocumentDoesNotExist();
        return accessHistory[tokenId].length;
    }
    
    /**
     * @notice Get paginated list of documents owned by an address
     * @param owner Address to query
     * @param offset Starting index
     * @param limit Maximum number of documents to return
     * @return tokenIds Array of token IDs owned by the address
     * @return total Total number of documents owned
     */
    function getDocumentsByOwnerPaginated(
        address owner,
        uint256 offset,
        uint256 limit
    ) external view returns (uint256[] memory tokenIds, uint256 total) {
        total = balanceOf(owner);
        
        if (offset >= total || limit == 0) {
            return (new uint256[](0), total);
        }
        
        uint256 actualLimit = limit;
        if (offset + limit > total) {
            actualLimit = total - offset;
        }
        
        tokenIds = new uint256[](actualLimit);
        uint256 index = 0;
        uint256 found = 0;
        
        for (uint256 i = 0; i < _tokenIdCounter && index < actualLimit; i++) {
            if (_ownerOf(i) != address(0) && ownerOf(i) == owner) {
                if (found >= offset) {
                    tokenIds[index++] = i;
                }
                found++;
            }
        }
    }
    
    /**
     * @notice Get paginated list of documents of a specific type owned by an address
     * @param owner Address to query
     * @param documentType Type of documents to filter
     * @param offset Starting index
     * @param limit Maximum number of documents to return
     * @return tokenIds Array of token IDs matching the criteria
     * @return total Total number of matching documents
     */
    function getDocumentsByOwnerAndTypePaginated(
        address owner,
        uint256 documentType,
        uint256 offset,
        uint256 limit
    ) external view returns (uint256[] memory tokenIds, uint256 total) {
        // First, count total matching documents
        uint256 count = 0;
        for (uint256 i = 0; i < _tokenIdCounter; i++) {
            if (_ownerOf(i) != address(0) && ownerOf(i) == owner && documents[i].documentType == documentType) {
                count++;
            }
        }
        
        total = count;
        
        if (offset >= total || limit == 0) {
            return (new uint256[](0), total);
        }
        
        uint256 actualLimit = limit;
        if (offset + limit > total) {
            actualLimit = total - offset;
        }
        
        tokenIds = new uint256[](actualLimit);
        uint256 index = 0;
        uint256 found = 0;
        
        for (uint256 i = 0; i < _tokenIdCounter && index < actualLimit; i++) {
            if (_ownerOf(i) != address(0) && ownerOf(i) == owner && documents[i].documentType == documentType) {
                if (found >= offset) {
                    tokenIds[index++] = i;
                }
                found++;
            }
        }
    }
    
    /**
     * @notice Get paginated access history for a document
     * @param tokenId The document NFT
     * @param offset Starting index
     * @param limit Maximum number of records to return
     * @return records Array of access records
     * @return total Total number of access records
     */
    function getAccessHistoryPaginated(
        uint256 tokenId,
        uint256 offset,
        uint256 limit
    ) external view returns (AccessRecord[] memory records, uint256 total) {
        if (_ownerOf(tokenId) == address(0)) revert Errors.DocumentDoesNotExist();
        if (ownerOf(tokenId) != msg.sender && !hasRole(ADMIN_ROLE, msg.sender)) revert Errors.NotDocumentOwner();
        
        AccessRecord[] memory allRecords = accessHistory[tokenId];
        total = allRecords.length;
        
        if (offset >= total || limit == 0) {
            return (new AccessRecord[](0), total);
        }
        
        uint256 actualLimit = limit;
        if (offset + limit > total) {
            actualLimit = total - offset;
        }
        
        records = new AccessRecord[](actualLimit);
        for (uint256 i = 0; i < actualLimit; i++) {
            records[i] = allRecords[offset + i];
        }
    }
    
    // ============ Required Overrides ============
    
    /**
     * @notice Check if contract supports an interface
     * @dev Override required for ERC721 + AccessControl
     */
    function supportsInterface(bytes4 interfaceId) 
        public 
        view 
        virtual 
        override(ERC721, AccessControl) 
        returns (bool) 
    {
        return ERC721.supportsInterface(interfaceId) || AccessControl.supportsInterface(interfaceId);
    }
}
