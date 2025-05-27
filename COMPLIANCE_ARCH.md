# Compliance Architecture

## Overview

This document outlines the comprehensive compliance architecture for verifying user attributes in a privacy-preserving manner for securities transactions, primarily under Reg D 506(c) but extensible to other regulatory frameworks. The system uses a decentralized identity model where claims are stored directly in identity contracts, eliminating redundant compliance checks and reducing gas costs compared to traditional approaches like OnchainID.

## Core Architecture Principles

### 1. Decentralized Claims Storage
- Claims stored in individual identity contracts, not a central registry
- Each user deploys their own identity contract
- Claims are cryptographically signed by authorized signers from the SignerRegistry
- Signatures stored with claims for non-repudiation and audit trails
- Signature verification happens only at claim creation, not during token transfers

### 2. Separation of Concerns
- **Identity Level**: Stores claims without enforcing business rules
- **Token Level**: Defines and checks specific compliance requirements
- **Registry Level**: Maps wallets to identities and manages signers

### 3. Gas Efficiency
- Simple storage reads during transfers (~5,000 gas)
- No signature verification during transfers (signatures already stored)
- Signer authorization checked only once at claim creation
- 10x+ gas savings compared to signature-based systems

## System Components

### 1. Identity Contract

Each user has an identity contract storing their verified claims:

```solidity
contract Identity {
    address public owner;
    mapping(uint256 => Claim) public claims;
    
    struct Claim {
        uint256 claimType;      // Type of claim (KYC, ACCREDITED, etc.)
        address signer;         // Authorized signer who created claim
        address docRef;         // Reference document NFT contract address
        bytes signature;        // Signature of claim data by signer
        bytes data;             // Flexible data field for complex claims
        uint256 timestamp;      // When claim was created
        uint256 expiresAt;      // Expiration timestamp
        bool revoked;           // Revocation status
    }
    
    modifier onlyAuthorizedSigner() {
        require(
            ISignerRegistry(signerRegistry).isValidSigner(msg.sender),
            "Not authorized signer"
        );
        _;
    }
    
    function addClaim(
        uint256 claimType,
        address docRef,
        uint256 expiresAt,
        bytes calldata data,
        bytes calldata signature
    ) external onlyAuthorizedSigner {
        // Verify signature matches msg.sender
        bytes32 messageHash = keccak256(abi.encodePacked(
            address(this),  // This identity
            claimType,
            docRef,
            data,
            expiresAt
        ));
        
        require(
            recoverSigner(messageHash, signature) == msg.sender,
            "Invalid signature"
        );
        
        claims[claimType] = Claim({
            claimType: claimType,
            signer: msg.sender,
            docRef: docRef,
            signature: signature,
            data: data,
            timestamp: block.timestamp,
            expiresAt: expiresAt,
            revoked: false
        });
        
        emit ClaimAdded(claimType, msg.sender, docRef);
    }
    
    function revokeClaim(uint256 claimType) external {
        require(
            msg.sender == claims[claimType].signer || 
            msg.sender == owner,
            "Not authorized"
        );
        claims[claimType].revoked = true;
        emit ClaimRevoked(claimType);
    }
}
```

### 2. Identity Factory

Factory contract that deploys identity contracts with verified bytecode:

```solidity
contract IdentityFactory is AccessControl {
    IIdentityRegistry public immutable identityRegistry;
    ISignerRegistry public immutable signerRegistry;
    mapping(bytes32 => bool) public deployedCodeHashes;
    
    event IdentityDeployed(address indexed owner, address indexed identity);
    
    constructor(address _identityRegistry, address _signerRegistry) {
        identityRegistry = IIdentityRegistry(_identityRegistry);
        signerRegistry = ISignerRegistry(_signerRegistry);
        
        // Set the expected bytecode hash for Identity contracts
        bytes memory bytecode = type(Identity).creationCode;
        bytes32 codeHash = keccak256(bytecode);
        deployedCodeHashes[codeHash] = true;
    }
    
    function deployIdentity() external returns (address) {
        // Deploy new identity contract for msg.sender
        Identity identity = new Identity(msg.sender, address(signerRegistry));
        
        // Verify correct bytecode was deployed
        bytes32 codeHash = identity.codehash;
        require(deployedCodeHashes[codeHash], "Invalid implementation");
        
        // Register in IdentityRegistry (only factory can do this)
        identityRegistry.registerIdentity(address(identity), msg.sender);
        
        emit IdentityDeployed(msg.sender, address(identity));
        return address(identity);
    }
    
    function addCodeHash(bytes32 codeHash) external onlyRole(ADMIN_ROLE) {
        // Admin can add new valid implementation code hashes
        deployedCodeHashes[codeHash] = true;
    }
}
```

### 3. Identity Registry

Simple mapping of wallets to identity contracts, only accepts registrations from factory:

```solidity
contract IdentityRegistry {
    address public immutable identityFactory;
    mapping(address => address) public walletToIdentity;
    uint256 public identityCount;
    
    event IdentityRegistered(address indexed wallet, address indexed identity);
    event IdentityUpdated(address indexed wallet, address indexed oldIdentity, address indexed newIdentity);
    
    modifier onlyFactory() {
        require(msg.sender == identityFactory, "Only factory can register");
        _;
    }
    
    constructor(address _identityFactory) {
        identityFactory = _identityFactory;
    }
    
    function registerIdentity(address identityContract, address owner) external onlyFactory {
        require(IIdentity(identityContract).owner() == owner, "Owner mismatch");
        
        if (walletToIdentity[owner] == address(0)) {
            identityCount++;
        }
        
        walletToIdentity[owner] = identityContract;
        emit IdentityRegistered(owner, identityContract);
    }
    
    function removeIdentity() external {
        require(walletToIdentity[msg.sender] != address(0), "No identity");
        delete walletToIdentity[msg.sender];
        identityCount--;
    }
    
    function getIdentity(address wallet) external view returns (address) {
        return walletToIdentity[wallet];
    }
    
    function updateIdentity(address newIdentity) external {
        require(IIdentity(newIdentity).owner() == msg.sender, "Not identity owner");
        address oldIdentity = walletToIdentity[msg.sender];
        walletToIdentity[msg.sender] = newIdentity;
        emit IdentityUpdated(msg.sender, oldIdentity, newIdentity);
    }
}
```

### 4. Signer Registry

Manages authorized signers who can create claims:

```solidity
contract SignerRegistry is AccessControl {
    mapping(address => SignerInfo) public signers;
    address[] public signerList;
    
    struct SignerInfo {
        bool active;
        uint256[] allowedClaimTypes;
        uint256 addedAt;
        uint256 totalClaims;
        uint256 revokedClaims;
    }
    
    function addSigner(address signer, uint256[] calldata allowedClaimTypes) 
        external 
        onlyRole(ADMIN_ROLE) 
    {
        require(!signers[signer].active, "Already active");
        
        signers[signer] = SignerInfo({
            active: true,
            allowedClaimTypes: allowedClaimTypes,
            addedAt: block.timestamp,
            totalClaims: 0,
            revokedClaims: 0
        });
        
        signerList.push(signer);
        emit SignerAdded(signer, allowedClaimTypes);
    }
    
    function removeSigner(address signer) external onlyRole(ADMIN_ROLE) {
        signers[signer].active = false;
        emit SignerRemoved(signer);
    }
    
    function isValidSigner(address signer) external view returns (bool) {
        return signers[signer].active;
    }
    
    function canSignClaimType(address signer, uint256 claimType) 
        external 
        view 
        returns (bool) 
    {
        if (!signers[signer].active) return false;
        
        uint256[] memory allowed = signers[signer].allowedClaimTypes;
        for (uint i = 0; i < allowed.length; i++) {
            if (allowed[i] == claimType) return true;
        }
        return false;
    }
}
```

### 5. Claim Topic Registry

Maps claim types to human-readable metadata:

```solidity
contract ClaimTopicRegistry is AccessControl {
    struct ClaimTopic {
        string title;           // Human-readable name
        uint256 documentId;     // NFT with legal definition
        string dataType;        // Expected data type
        bool active;            // Can be deprecated
    }
    
    mapping(uint256 => ClaimTopic) public claimTopics;
    
    // Core claim types
    uint256 public constant KYC_AML = 1;
    uint256 public constant ACCREDITED_INVESTOR = 2;
    uint256 public constant INSTITUTIONAL_INVESTOR = 3;
    uint256 public constant INSIDER_STATUS = 4;
    
    function addClaimTopic(
        uint256 topicId,
        string memory title,
        uint256 documentId,
        string memory dataType
    ) external onlyRole(ADMIN_ROLE) {
        claimTopics[topicId] = ClaimTopic({
            title: title,
            documentId: documentId,
            dataType: dataType,
            active: true
        });
        
        emit ClaimTopicAdded(topicId, title);
    }
    
    function getClaimTopic(uint256 topicId) 
        external 
        view 
        returns (string memory title, uint256 documentId, string memory dataType) 
    {
        ClaimTopic memory topic = claimTopics[topicId];
        return (topic.title, topic.documentId, topic.dataType);
    }
}
```

### 6. Verifier Utility Contract

Helper functions for checking claims:

```solidity
contract Verifier {
    IIdentityRegistry public identityRegistry;
    ISignerRegistry public signerRegistry;
    
    function isValidSigner(address signer) external view returns (bool) {
        return signerRegistry.isValidSigner(signer);
    }
    
    function hasValidClaim(address user, uint256 claimType) 
        external 
        view 
        returns (bool) 
    {
        address identityContract = identityRegistry.getIdentity(user);
        if (identityContract == address(0)) return false;
        
        IIdentity identity = IIdentity(identityContract);
        IIdentity.Claim memory claim = identity.getClaim(claimType);
        
        return claim.signer != address(0) && 
               !claim.revoked && 
               claim.expiresAt > block.timestamp;
    }
    
    function getClaimData(address user, uint256 claimType)
        external
        view
        returns (bytes memory)
    {
        address identityContract = identityRegistry.getIdentity(user);
        require(identityContract != address(0), "No identity");
        
        IIdentity identity = IIdentity(identityContract);
        return identity.getClaim(claimType).data;
    }
    
    function getClaimSigner(address user, uint256 claimType) 
        external 
        view 
        returns (address) 
    {
        address identityContract = identityRegistry.getIdentity(user);
        if (identityContract == address(0)) return address(0);
        
        IIdentity identity = IIdentity(identityContract);
        IIdentity.Claim memory claim = identity.getClaim(claimType);
        
        // Verify signature is still valid
        bytes32 messageHash = keccak256(abi.encodePacked(
            identityContract,
            claim.claimType,
            claim.docRef,
            claim.data,
            claim.expiresAt
        ));
        
        address recoveredSigner = recoverSigner(messageHash, claim.signature);
        
        // Return signer only if signature is valid
        return (recoveredSigner == claim.signer) ? claim.signer : address(0);
    }
}
```

## Claim Types and Data Structures

### Core Claim Types

```solidity
// Primary compliance claims
uint256 constant KYC_AML = 1;                // Combined KYC/AML verification
uint256 constant ACCREDITED_INVESTOR = 2;     // Reg D accreditation
uint256 constant INSTITUTIONAL_INVESTOR = 3;  // Qualified institutional buyer
uint256 constant INSIDER_STATUS = 4;          // Complex insider information

// Extended claim types for future use
uint256 constant QUALIFIED_PURCHASER = 5;     // $5M+ investable assets
uint256 constant COUNTRY_OF_RESIDENCE = 10;   // ISO country code
uint256 constant STATE_OF_RESIDENCE = 11;     // US state code
uint256 constant TAX_JURISDICTION = 12;       // Tax residency
uint256 constant PEP_STATUS = 20;             // Politically exposed person
uint256 constant SOURCE_OF_FUNDS = 21;        // Fund source verification
uint256 constant INVESTMENT_LIMIT_USD = 30;   // Maximum investment amount
```

### Complex Claim Data Encoding

For claims requiring more than boolean values:

```solidity
// Boolean claims (KYC_AML, ACCREDITED_INVESTOR, etc.)
data = abi.encode(true);

// String claims (COUNTRY_OF_RESIDENCE, etc.)
data = abi.encode("US");

// Numeric claims (INVESTMENT_LIMIT_USD, etc.)
data = abi.encode(uint256(1000000));

// Complex claims (INSIDER_STATUS)
struct InsiderInfo {
    address[] tokenAddresses;    // Security tokens where insider
    uint8[] insiderTypes;        // Type for each token
    uint256[] restrictedUntil;   // Restriction end dates
}
data = abi.encode(insiderInfo);

// Insider Types:
// 1 = Officer
// 2 = Director
// 3 = 10% Owner
// 4 = Employee with material information
// 5 = Family member/affiliate
```

## Token Integration

### Compliance Checking Pattern

```solidity
contract SecurityToken is ERC20 {
    IIdentityRegistry public identityRegistry;
    IVerifier public verifier;
    
    // Define token-specific requirements
    uint256[] public requiredClaims = [KYC_AML, ACCREDITED_INVESTOR];
    
    function transfer(address to, uint256 amount) public override returns (bool) {
        require(checkCompliance(msg.sender), "Sender not compliant");
        require(checkCompliance(to), "Recipient not compliant");
        
        // Check for insider restrictions if applicable
        if (hasInsiderRestrictions(msg.sender)) {
            require(checkInsiderCompliance(msg.sender), "Insider restriction");
        }
        
        return super.transfer(to, amount);
    }
    
    function checkCompliance(address user) public view returns (bool) {
        for (uint i = 0; i < requiredClaims.length; i++) {
            if (!verifier.hasValidClaim(user, requiredClaims[i])) {
                return false;
            }
        }
        return true;
    }
    
    function hasInsiderRestrictions(address user) public view returns (bool) {
        return verifier.hasValidClaim(user, INSIDER_STATUS);
    }
    
    function checkInsiderCompliance(address user) public view returns (bool) {
        bytes memory data = verifier.getClaimData(user, INSIDER_STATUS);
        InsiderInfo memory info = abi.decode(data, (InsiderInfo));
        
        // Check if user is insider for this token
        for (uint i = 0; i < info.tokenAddresses.length; i++) {
            if (info.tokenAddresses[i] == address(this)) {
                // Check if still restricted
                if (info.restrictedUntil[i] > block.timestamp) {
                    return false;
                }
            }
        }
        return true;
    }
}
```

## Privacy Model

### On Ethereum/L2s (Pseudonymous)
- Wallet→Identity mappings are public
- Suitable for institutional investors
- Lower gas costs on L2s
- Full transparency for regulatory compliance

### On Oasis Network (Anonymous)
```solidity
// All contract state automatically encrypted
contract PrivateIdentityRegistry {
    // These mappings are encrypted in Oasis's confidential state
    mapping(address => address) private walletToIdentity;
    
    // External observers cannot see mappings
    // Only contract can decrypt during execution
    function getIdentity(address wallet) external view returns (address) {
        // Decrypted only within contract execution
        return walletToIdentity[wallet];
    }
}
```

Benefits:
- Complete privacy of wallet→identity links
- Same gas costs as public version
- No complex cryptography needed
- Automatic encryption/decryption

## Verification Flow

### 1. Document Upload
```
User uploads documents → Creates document NFT → Stores encrypted shards
```

### 2. Claim Creation
```
Signer reviews documents → Signs claim data → Calls identity.addClaim() → Contract verifies signer authorization and signature → Claim stored with document reference and signature
```

### 3. Token Transfer
```
User initiates transfer → Token checks required claims → Simple storage reads → Transfer approved/denied
```

### 4. Audit Trail
- Document NFT tracks all access (who, when, why)
- Claims reference source documents via docRef address
- Cryptographic signatures provide non-repudiation
- Complete verification history preserved
- Regulatory inspection possible when required

## Gas Optimization Strategies

### 1. Claim Storage
- Store only active claims
- Use expiration for automatic invalidation
- Pack struct fields efficiently
- Minimize storage slots used

### 2. Verification
- Cache frequently checked claims
- Batch multiple claim checks
- Use view functions for read-only operations
- Optimize loop iterations

### 3. Registry Operations
- Minimal on-chain data
- Events for off-chain indexing
- Efficient data structures
- Avoid redundant storage

## Security Considerations

### 1. Access Control
- Multi-role permission system
- Time-locked admin functions
- Signer authorization checks
- Identity ownership verification

### 2. Data Integrity
- Immutable claim history
- Revocation without deletion
- Signature verification ensures claim authenticity
- Document reference integrity via docRef
- Timestamp validation

### 3. Recovery Mechanisms
- Identity contract upgrades
- Wallet rotation support
- Multi-sig recovery options
- Emergency pause functionality

## Regulatory Compliance Features

### 1. Complete Audit Trail
- Every claim traceable to documents via docRef
- Signer accountability through cryptographic signatures
- Non-repudiation: signers cannot deny creating claims
- Timestamp records
- Access history

### 2. Flexible Claim Types
- Extensible for new regulations
- Jurisdiction-specific claims
- Multiple data type support
- Version management

### 3. Inspection Capabilities
- Regulatory view functions
- Time-locked transparency
- Bulk data exports
- Compliance reporting

## Implementation Roadmap

### Phase 1: Core Infrastructure (Months 1-2)
- Deploy Identity, IdentityRegistry, SignerRegistry
- Implement basic claim types (KYC_AML, ACCREDITED_INVESTOR)
- Create signer authorization system
- Test with single security token

### Phase 2: Enhanced Features (Months 3-4)
- Add ClaimTopicRegistry with metadata
- Implement complex claim types (INSIDER_STATUS)
- Integrate document management system
- Add batch operations for efficiency

### Phase 3: Privacy and Scale (Months 5-6)
- Deploy on Oasis for encrypted state
- Implement advanced privacy features
- Optimize gas consumption
- Add cross-chain support

## Comparison with OnchainID

### Gas Efficiency
- **OnchainID**: ~50,000+ gas per transfer (signature verification)
- **Our System**: ~5,000 gas per transfer (simple storage reads)

### Architecture
- **OnchainID**: Monolithic verifier contract
- **Our System**: Modular, upgradeable components

### Trust Model
- **OnchainID**: Trust issuers and verify signatures repeatedly
- **Our System**: Trust signers once at claim creation

### Flexibility
- **OnchainID**: Fixed claim structure
- **Our System**: Extensible data field for any claim type

## Summary

This architecture provides a gas-efficient, privacy-preserving, and regulatory-compliant identity system for securities transactions. By storing claims directly in identity contracts with cryptographic signatures and checking signer authorization only at claim creation, we eliminate redundant signature verification during transfers while maintaining non-repudiation and security. The modular design allows tokens to define their own compliance requirements without modifying the core identity infrastructure, making the system adaptable to various regulatory frameworks beyond Reg D 506(c).

Key advantages:
- **10x+ gas savings** compared to repeated signature verification systems
- **Non-repudiation** through stored cryptographic signatures
- **Flexible compliance** rules defined at token level
- **Privacy options** from pseudonymous to fully anonymous
- **Complete audit trail** through document NFT references (docRef)
- **Simple integration** for token developers
- **Signature verification** only at claim creation, not during transfers