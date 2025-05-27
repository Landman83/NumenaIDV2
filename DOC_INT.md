# Document Integration Architecture

## Overview

This document describes the integration between the NumenaID document management system and the compliance/identity infrastructure. The system enables secure document storage, retrieval, and verification while maintaining a complete audit trail for regulatory compliance.

## Core Principles

1. **Identity-Owned Documents**: All documents are owned by Identity contracts, not user EOAs
2. **Type-Based Retrieval**: Documents are tagged by type and automatically retrieved during claim verification
3. **Integrated Verification**: Document access is seamlessly integrated into the claim creation flow
4. **Complete Audit Trail**: Every document access is recorded on-chain with accessor and timestamp
5. **Controlled Access**: Only document owner and authorized signers can access documents

## System Architecture

### Document Ownership Model

- User (EOA) owns Identity contract
- Identity contract owns Document NFTs
- This creates a clean hierarchy: EOA → Identity → Documents
- Enables programmatic access control through Identity contract

### Access Control

**Authorized Accessors**:
1. Identity contract that owns the document
2. Verifier contract (for claim creation)
3. Authorized signers (via SignerRegistry)
4. Regulators (with special role)

**Access Flow**:
- All document access must go through Identity or Verifier contracts
- Direct access to ComplianceDocument contract is restricted
- Access automatically triggers audit record creation

### Document-Claim Type Mapping

**Location**: ClaimTypeRegistry contract
**Purpose**: Define which document types are required for each claim type

**Mapping Structure**:
- Each claim type has an array of required document types
- Example: KYC_AML requires [PASSPORT, UTILITY_BILL]
- Example: ACCREDITED_INVESTOR requires [INCOME_STATEMENT, BANK_STATEMENT]

### Verification Flow

1. Signer initiates claim creation for user and claim type
2. System queries ClaimTypeRegistry for required document types
3. System retrieves the MOST RECENT documents of each required type (by upload timestamp)
4. Each document access is automatically recorded
5. Signer reviews documents off-chain
6. Signer creates claim with references to verified documents
7. Claim stored in Identity contract with document references

## Required Changes to Existing System

### 1. Identity Contract (Identity.sol)

**Current State**:
- Stores claims with single `address docRef`
- Claims created directly by signers

**Required Changes**:
- Change `address docRef` to `uint256[] documentIds` in Claim struct
- Add function to retrieve owned documents by type
- Add function to get most recent document of a specific type
- Add internal document access logic during claim creation
- Ensure only owner (EOA) can call identity functions

### 2. ClaimTypeRegistry (ClaimTypeRegistry.sol)

**Current State**:
- Stores single `uint256 documentId` per claim type
- Basic metadata about claim types

**Required Changes**:
- Change to `uint256[] requiredDocumentTypes` array
- Add function `getRequiredDocuments(uint256 claimType)`
- Add document type constants (PASSPORT = 1, UTILITY_BILL = 2, etc.)
- Allow admin to update document requirements per claim type

### 3. ComplianceDocument (New Contract)

**Key Features**:
- ERC721 for document ownership
- Documents minted to Identity contracts, not EOAs
- Non-view `getDocument()` function that records access
- Whitelist of contracts that can call `recordDocumentAccess()`
- Complete audit trail stored on-chain
- Tracks upload timestamp for each document
- Enables retrieval of most recent documents by type

**Access Control**:
- `onlyIdentityOrVerifier` modifier for document access
- Checks against IdentityRegistry and Verifier address
- No direct user access - must go through Identity contract
- Only addresses in SignerRegistry or verifier contract owner can call functions in verifier

### 4. Verifier Contract (Verifier.sol)

**Current State**:
- Simple claim verification utilities
- Read-only operations

**Required Changes**:
- Add document retrieval logic that selects most recent documents
- Integrate with ComplianceDocument for access recording
- Enhanced claim creation support with document verification
- Automatic selection of most recent documents when multiple exist
- Maintain backward compatibility

### 5. IdentityFactory (IdentityFactory.sol)

**Current State**:
- Deploys Identity contracts for users

**Required Changes**:
- No changes needed
- Identity contracts automatically compatible with document ownership

## Document Types

**Core Document Types** (stored in ClaimTypeRegistry):
```
PASSPORT = 1
DRIVERS_LICENSE = 2
UTILITY_BILL = 3
BANK_STATEMENT = 4
INCOME_STATEMENT = 5
TAX_RETURN = 6
CORPORATE_DOCS = 7
AUTHORIZATION_LETTER = 8
NET_WORTH_STATEMENT = 9
INVESTMENT_PORTFOLIO = 10
```

## Storage Architecture (MVP)

**Local Storage**:
- Documents stored locally with SHA256 hash verification
- Path reference stored in contract
- Future: Migrate to encrypted IPFS storage

**Document Metadata**:
- File hash for integrity verification
- Upload timestamp
- File size for basic validation
- Document type for categorization

## Audit Trail

**AccessRecord Structure**:
- `address accessor`: Who accessed the document
- `uint8 accessType`: 0=Owner, 1=Verifier, 2=Regulator
- `uint48 timestamp`: When access occurred

**Storage**:
- Array of AccessRecord per document
- Append-only for immutability
- No deletion or modification allowed

## Security Considerations

### Access Control
- Documents only accessible through Identity or Verifier contracts
- Whitelist of authorized contracts maintained
- No direct user access to ComplianceDocument functions

### Data Integrity
- SHA256 hash verification for documents
- Immutable audit trail
- No document modification after minting

### Privacy
- Document content stored off-chain
- Only metadata and access records on-chain
- Access restricted to authorized parties

## Integration Points

### Claim Creation
1. Verifier retrieves required document types from ClaimTypeRegistry
2. Verifier accesses documents through user's Identity contract
3. ComplianceDocument records each access
4. Claim created with array of document token IDs

### Document Minting
1. User uploads document off-chain
2. User calls Identity contract to mint document
3. Identity contract mints NFT to itself
4. Document categorized by type for future retrieval

### Access Patterns
- **Owner Access**: User → Identity → ComplianceDocument
- **Verifier Access**: Verifier → Identity → ComplianceDocument
- **Direct Access**: Blocked by access control

## Document Recency Requirements

### Regulatory Compliance (Reg D Rule 506(c))
- Documents must be updated regularly (every three months)
- System automatically selects most recent document of each required type
- Older documents remain accessible for historical reference
- Claims reference the documents that were most recent at time of verification

### Implementation Details
- ComplianceDocument stores `uploadedAt` timestamp for each document
- Identity contract provides function to get most recent document by type
- Verifier automatically selects most recent when multiple documents exist
- Ensures compliance with periodic update requirements

## Migration Notes

### Phase 1 (MVP)
- Implement basic document NFTs with local storage
- Simple type-based categorization
- Manual document selection for claims

### Phase 2
- Automated document discovery
- Encrypted storage migration
- Batch operations for efficiency

### Phase 3
- Zero-knowledge proofs for selective disclosure
- Cross-chain document verification
- Advanced privacy features

## Summary of Key Changes

1. **Identity.sol**: 
   - Support array of document IDs in claims
   - Add function to retrieve most recent document by type
   
2. **ClaimTypeRegistry.sol**: 
   - Map claim types to required document arrays
   
3. **ComplianceDocument.sol**: 
   - New contract for document NFTs with audit trail
   - Track upload timestamps for recency checks
   
4. **Verifier.sol**: 
   - Add document retrieval logic prioritizing most recent documents
   - Automatic document selection based on recency
   
5. **All contracts**: 
   - Ensure proper access control integration
   - Support document recency requirements for Reg D compliance