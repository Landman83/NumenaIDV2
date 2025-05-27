# Document Handling Architecture

## Overview

This document describes the privacy-preserving document management architecture for the NumenaID identity protocol. The system enables users to securely store sensitive documents (KYC, accreditation proofs, etc.) while maintaining complete control and privacy, leveraging Oasis Network's confidential computing capabilities.

## Core Architecture Components

### 1. Document Processing Pipeline

**Step 1: Encryption**
- User's document is encrypted using their identity key
- Encryption algorithm: AES-256-GCM for authenticated encryption
- Key derivation: Direct use of user's identity key (no additional key management)
- Result: Encrypted document blob with authentication tag

**Step 2: Secret Sharing**
- Encrypted document undergoes Shamir's Secret Sharing (SSS) transformation
- Configuration: 2-of-3 threshold scheme
  - 3 shares generated
  - Any 2 shares can reconstruct the document
  - 1 share reveals absolutely nothing
- Each share has the same size as the original encrypted document
- Shares appear as completely random data

**Step 3: Storage Distribution**
- Each share uploaded to different IPFS providers
- Providers selected based on:
  - Geographic distribution
  - Reliability metrics
  - Availability guarantees
- Content-addressed storage ensures integrity
- Share locations (IPFS CIDs) collected for manifest

### 2. NFT-Based Ownership

**NFT Structure on Oasis Sapphire:**
- ERC-721 token representing document ownership
- Metadata stored in confidential contract state:
  - Share 1 location (IPFS CID)
  - Share 2 location (IPFS CID)
  - Share 3 location (IPFS CID)
  - Document metadata (type, hash, timestamp)
  - Verification status and audit trail

**Privacy Guarantees:**
- Oasis Sapphire encrypts all contract state
- Only NFT owner can access share locations
- External observers cannot see:
  - Document existence
  - Share locations
  - Access patterns
  - Document metadata

### 3. Access Control and Audit Trail

**Owner Access:**
- User authenticates with identity key
- Smart contract verifies ownership
- Share locations revealed to owner only
- User retrieves any 2 of 3 shares
- Local reconstruction and decryption

**Delegated Access:**
- Owner can grant temporary access to verifiers
- Time-limited access tokens
- Granular permissions (read-only, specific documents)
- Access revocation capability
- All access events recorded immutably

**Access History Storage:**
Leveraging Oasis's encrypted state storage, every document access is permanently recorded:

**Data Structure:**
- Packed struct for efficiency: `AccessRecord { address accessor; uint8 accessType; uint48 timestamp }`
- Single storage slot per record (27 bytes total)
- Dynamic array with unlimited history: `mapping(uint256 => AccessRecord[]) documentAccessHistory`

**Access Types:**
- 0: Owner access
- 1: Verifier access (for attestations)
- 2: Regulator access (compliance review)
- 3: Delegated access (temporary permissions)

**Recording Process:**
1. Every document access triggers history update
2. New AccessRecord appended to document's history array
3. Events emitted for potential future indexing
4. History queryable by NFT owner only

**Benefits:**
- Complete immutable audit trail
- No external dependencies (indexers, explorers)
- Privacy preserved (only owner sees history)
- Efficient storage on Oasis
- Supports compliance requirements

### 4. Recovery Mechanisms

**Standard Recovery:**
- Need any 2 of 3 shares
- If 1 IPFS provider fails, document still recoverable
- If 2 providers fail, document is lost (acceptable risk)

**Backup Strategies:**
- Optional encrypted backup to user-controlled location
- Social recovery through trusted contacts
- Each contact holds 1 share of recovery key
- M-of-N threshold for recovery initiation

## Security Properties

### Cryptographic Guarantees

**Confidentiality:**
- Document encrypted before sharing
- Each share individually meaningless
- Share locations hidden by Oasis
- No correlation between shares possible

**Integrity:**
- IPFS content addressing ensures tamper-evidence
- AES-GCM provides authenticated encryption
- Smart contract ensures share location immutability
- Verification through hash comparison

**Availability:**
- 2-of-3 redundancy tolerates 1 failure
- Geographic distribution of shares
- Multiple IPFS providers
- Local caching options

### Threat Model

**Protected Against:**
- Single IPFS provider compromise
- Network traffic analysis
- Blockchain analysis
- Unauthorized access attempts
- Single point of failure

**Assumptions:**
- User's identity key remains secure
- Oasis confidential computing not compromised
- At least 2 of 3 IPFS providers remain available
- User maintains secure local environment

## Integration Points

### With Identity System (ERC-725/735)

**Document-Identity Linkage:**
- NFT minted to identity contract address
- Claims can reference document NFTs
- Verification results stored as attestations
- Access permissions tied to identity attributes

**Verification Flow:**
1. Verifier requests document access
2. User grants permission via identity contract
3. Verifier retrieves and verifies document
4. Attestation created referencing document NFT
5. Claim added to user's identity

### With Verification System (EAS)

**Attestation Integration:**
- Document hash included in attestations
- Verification timestamp recorded
- Verifier signature links to document
- Revocable attestations for compliance

**Audit Trail:**
- Each access logged in EAS
- Verification events create attestations
- Chain of custody maintained
- Tamper-evident history

## Implementation Considerations

### Gas Optimization

**Efficient Operations:**
- Minimal on-chain storage (just CIDs)
- Batch operations for multiple documents
- Event-based indexing
- Off-chain computation where possible

**Cost Estimates:**
- NFT minting: ~100k gas
- Access grant: ~50k gas
- Metadata update: ~30k gas
- Access history append: ~40k gas
- Oasis significantly cheaper than Ethereum

### Performance

**Latency Considerations:**
- IPFS retrieval: 1-5 seconds per share
- Parallel share fetching
- Local caching of frequently accessed
- CDN integration for hot documents

**Scalability:**
- Horizontal scaling of IPFS nodes
- Stateless share reconstruction
- No on-chain bottlenecks
- Efficient indexing strategies

## Privacy Enhancements

### Access Pattern Obfuscation

**Techniques:**
- Random delay in share retrieval
- Decoy share fetches
- Tor/VPN for IPFS access
- Rotating IPFS gateways

### Metadata Protection

**What's Hidden:**
- Document types and categories
- Access frequency
- Verification patterns
- User relationships

**What's Visible (to authorized parties only):**
- Document existence
- Basic metadata
- Verification status
- Access permissions

## Future Enhancements

### Advanced Features

**Selective Disclosure:**
- Share specific pages/sections
- Redacted document versions
- Zero-knowledge proofs of content
- Granular access control

**Cross-Chain Compatibility:**
- Bridge documents between chains
- Maintain privacy across bridges
- Universal document identifiers
- Multi-chain verification

### Technology Evolution

**Post-Quantum Readiness:**
- Upgrade encryption algorithms
- Quantum-resistant signatures
- Future-proof architecture
- Smooth migration path

**Decentralized Storage Evolution:**
- Support for new storage networks
- Automated provider selection
- Economic optimization
- Performance improvements

## Conclusion

This architecture provides a robust, privacy-preserving document management system that:
- Maintains user sovereignty over sensitive documents
- Ensures document availability through redundancy
- Protects privacy through multiple layers
- Integrates seamlessly with identity and verification systems
- Scales efficiently for production use

The combination of Oasis confidential computing, Shamir's Secret Sharing, and IPFS creates a unique solution that balances security, privacy, and usability for regulated document management in the decentralized identity ecosystem.