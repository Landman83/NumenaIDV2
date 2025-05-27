# NumenaID Test Suite Plan

## Overview
This document outlines the comprehensive testing strategy for the NumenaID protocol, targeting 100% function coverage and complete integration testing.

## Test Structure

### 1. Unit Tests (Per Contract)

#### 1.1 NumenaID.t.sol
**Router Contract Tests**
- [ ] Constructor validation (zero address checks)
- [ ] Module address getters
- [ ] Delegation tests for each function
- [ ] Gas optimization verification

#### 1.2 Identity.t.sol
**Core Identity Functions**
- [ ] Constructor validation
- [ ] Access control (onlyOwner, onlyAuthorizedSigner)
- [ ] addClaim with signature verification
  - [ ] Valid signature acceptance
  - [ ] Invalid signature rejection
  - [ ] Nonce increment verification
  - [ ] Replay protection testing
  - [ ] Chain ID validation
- [ ] revokeClaim functionality
  - [ ] Owner can revoke
  - [ ] Signer can revoke own claims
  - [ ] Unauthorized cannot revoke
- [ ] getClaim data retrieval
- [ ] hasValidClaim checks
  - [ ] Valid claims return true
  - [ ] Expired claims return false
  - [ ] Revoked claims return false
- [ ] transferOwnership
- [ ] Document management functions
  - [ ] getDocumentsByType
  - [ ] getMostRecentDocumentByType
- [ ] ReentrancyGuard testing

#### 1.3 IdentityFactory.t.sol
**Factory Pattern Tests**
- [ ] Constructor validation
- [ ] deployIdentity function
  - [ ] Successful deployment
  - [ ] Duplicate deployment prevention
  - [ ] Registry integration
  - [ ] Event emission
- [ ] Code hash management
  - [ ] addCodeHash (admin only)
  - [ ] removeCodeHash (admin only)
- [ ] setNumenaID function
- [ ] Access control tests

#### 1.4 IdentityRegistry.t.sol
**Registry Management Tests**
- [ ] Constructor validation
- [ ] registerIdentity (factory only)
  - [ ] Successful registration
  - [ ] Duplicate prevention
  - [ ] Event emission
- [ ] updateIdentity functionality
- [ ] removeIdentity (admin only)
- [ ] Getter functions
  - [ ] getIdentity
  - [ ] hasIdentity
  - [ ] getWallet
  - [ ] getAllIdentities
- [ ] Access control validation

#### 1.5 SignerRegistry.t.sol
**Signer Management Tests**
- [ ] Constructor validation
- [ ] addSigner (admin only)
  - [ ] Valid signer addition
  - [ ] Duplicate prevention
  - [ ] Claim type mapping
  - [ ] Event emission
- [ ] removeSigner (admin only)
  - [ ] Successful removal
  - [ ] Array cleanup
  - [ ] Mapping cleanup
- [ ] updateSignerClaimTypes
- [ ] incrementClaimCount
- [ ] Getter functions
  - [ ] getSigners
  - [ ] getSignersForClaim
  - [ ] getSignerCount
  - [ ] isValidSigner
  - [ ] canSignClaimType
  - [ ] getSignerInfo
- [ ] ReentrancyGuard testing

#### 1.6 ClaimTypeRegistry.t.sol
**Claim Type Management Tests**
- [ ] Constructor with default types
- [ ] addClaimType (admin only)
  - [ ] Valid addition
  - [ ] Duplicate prevention
  - [ ] Document type arrays
- [ ] removeClaimType (admin only)
- [ ] updateClaimType (admin only)
- [ ] Getter functions
  - [ ] getClaimType
  - [ ] getRequiredDocuments
  - [ ] getAllClaimTypes
  - [ ] isValidClaimType

#### 1.7 ComplianceDocument.t.sol
**Document NFT Tests**
- [ ] Constructor validation
- [ ] mintDocument
  - [ ] Valid minting
  - [ ] Metadata storage
  - [ ] Access record creation
  - [ ] Event emission
- [ ] getDocument (access control)
- [ ] recordDocumentAccess
  - [ ] Access type determination
  - [ ] Audit trail creation
- [ ] getAccessHistory (owner only)
- [ ] canAccessDocument logic
- [ ] Document retrieval functions
  - [ ] getDocumentsByOwner
  - [ ] getDocumentsByOwnerAndType
  - [ ] getMostRecentDocumentByOwnerAndType
- [ ] Regulator management
- [ ] Transfer hooks (_update)
- [ ] ReentrancyGuard testing

#### 1.8 Verifier.t.sol
**Verification Utility Tests**
- [ ] Constructor validation
- [ ] hasValidClaim comprehensive testing
- [ ] getClaimSigner with signature verification
- [ ] getClaimDocumentIds
- [ ] getClaimData
- [ ] hasAllClaims (multiple claim verification)
- [ ] getClaimDetails
- [ ] verifyClaimSignature
- [ ] createClaimWithDocuments
  - [ ] Document retrieval
  - [ ] Access recording
  - [ ] Claim creation
- [ ] verifyClaimDocuments
- [ ] setNumenaID function
- [ ] ReentrancyGuard testing

### 2. Integration Tests

#### 2.1 IdentityCreation.t.sol
**End-to-End Identity Creation Flow**
- [ ] User creates identity via NumenaID router
- [ ] Factory deploys identity contract
- [ ] Registry records identity
- [ ] Identity contract initialization verification

#### 2.2 ClaimCreation.t.sol
**Complete Claim Creation Flow**
- [ ] Signer authorization check
- [ ] Document requirement retrieval
- [ ] Document access and recording
- [ ] Claim creation with documents
- [ ] Signature verification
- [ ] Nonce increment verification

#### 2.3 DocumentManagement.t.sol
**Document Lifecycle Tests**
- [ ] Document minting to identity
- [ ] Document retrieval by type
- [ ] Most recent document selection
- [ ] Access control verification
- [ ] Audit trail generation

#### 2.4 ComplianceVerification.t.sol
**Full Compliance Check Flow**
- [ ] Multi-claim verification
- [ ] Document verification
- [ ] Expired claim handling
- [ ] Revoked claim handling

#### 2.5 SignerManagement.t.sol
**Signer Lifecycle Tests**
- [ ] Signer addition and authorization
- [ ] Claim type permissions
- [ ] Signer removal impact
- [ ] Claim count tracking

### 3. Security Tests

#### 3.1 ReentrancyTests.t.sol
- [ ] Reentrancy attack simulations on all protected functions
- [ ] Verify ReentrancyGuard effectiveness

#### 3.2 AccessControlTests.t.sol
- [ ] Role-based access testing
- [ ] Modifier effectiveness
- [ ] Admin function protection

#### 3.3 SignatureTests.t.sol
- [ ] Signature replay attack prevention
- [ ] Cross-chain replay prevention
- [ ] Nonce manipulation attempts
- [ ] Invalid signature handling

### 4. Edge Case Tests

#### 4.1 EdgeCases.t.sol
- [ ] Zero address inputs
- [ ] Empty arrays
- [ ] Maximum array sizes
- [ ] Overflow/underflow scenarios
- [ ] Gas limit stress tests

### 5. Fuzzing Tests

#### 5.1 FuzzTests.t.sol
- [ ] Fuzz testing for all input parameters
- [ ] Property-based testing for invariants
- [ ] Random signature generation
- [ ] Array manipulation fuzzing

## Test Helpers and Utilities

### TestBase.sol
**Common Test Infrastructure**
- Contract deployment helpers
- User/signer setup utilities
- Signature generation helpers
- Time manipulation utilities
- Event assertion helpers
- Common test data structures

### MockContracts.sol
**Testing Support Contracts**
- Malicious reentrancy attacker
- Mock external contracts
- Test token contracts

## Coverage Requirements

### Function Coverage: 100%
- Every public/external function must be called
- All code paths must be executed
- All modifiers must be tested

### Line Coverage: 100%
- Every line of code must be executed
- All conditional branches covered
- Error conditions triggered

### Branch Coverage: 100%
- All if/else branches tested
- All require statements hit (both pass and fail)
- Loop conditions tested (0, 1, many iterations)

## Test Execution Strategy

### Phase 1: Unit Tests
1. Implement TestBase.sol with helpers
2. Create individual test files per contract
3. Test each function in isolation
4. Verify events and state changes

### Phase 2: Integration Tests
1. Test contract interactions
2. Verify end-to-end flows
3. Test permission boundaries
4. Validate data flow between contracts

### Phase 3: Security Tests
1. Attempt common attacks
2. Verify security measures
3. Test edge cases
4. Fuzz testing

### Phase 4: Gas Optimization
1. Measure gas usage
2. Identify optimization opportunities
3. Verify optimizations don't break functionality

## Test Data Scenarios

### User Types
1. Regular users (EOAs)
2. Contract wallets
3. Multi-sig wallets
4. Malicious actors

### Claim Types
1. KYC_AML (type 1)
2. ACCREDITED_INVESTOR (type 2)
3. INSTITUTIONAL_INVESTOR (type 3)
4. INSIDER_STATUS (type 4)
5. Custom claim types

### Document Types
1. PASSPORT (1)
2. UTILITY_BILL (3)
3. INCOME_STATEMENT (5)
4. BANK_STATEMENT (4)
5. Multiple documents per type

### Time Scenarios
1. Before expiration
2. At expiration
3. After expiration
4. No expiration (0)

## Assertion Patterns

### State Assertions
```solidity
assertEq(actualValue, expectedValue, "Error message");
assertTrue(condition, "Condition should be true");
assertFalse(condition, "Condition should be false");
```

### Event Assertions
```solidity
vm.expectEmit(true, true, true, true);
emit ExpectedEvent(param1, param2, param3);
```

### Revert Assertions
```solidity
vm.expectRevert(Errors.SpecificError.selector);
contract.failingFunction();
```

### Access Control Assertions
```solidity
vm.prank(unauthorizedUser);
vm.expectRevert(Errors.OnlyAdmin.selector);
contract.adminFunction();
```

## Success Metrics

1. **Coverage**: 100% function, line, and branch coverage
2. **Security**: All attack vectors tested and mitigated
3. **Gas**: Baseline measurements for all operations
4. **Integration**: All contract interactions verified
5. **Edge Cases**: All boundary conditions handled

## Tools and Commands

### Running Tests
```bash
forge test -vvv                    # Run all tests with verbosity
forge test --match-test testName   # Run specific test
forge test --match-contract Name   # Run specific contract tests
forge coverage                     # Generate coverage report
forge test --gas-report           # Generate gas usage report
```

### Coverage Analysis
```bash
forge coverage --report lcov
genhtml lcov.info -o coverage/
open coverage/index.html
```

This comprehensive test plan ensures complete validation of the NumenaID protocol's functionality, security, and integration.