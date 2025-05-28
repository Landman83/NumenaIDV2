// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./NumenaTestBase.sol";
import "../src/libraries/Errors.sol";
import "../src/libraries/Events.sol";

contract NumenaIDTest is NumenaTestBase {
    function setUp() public override {
        super.setUp();
    }
    
    function test_Constructor() public view {
        assertEq(numenaID.identityRegistry(), address(identityRegistry));
        assertEq(numenaID.identityFactory(), address(identityFactory));
        assertEq(numenaID.signerRegistry(), address(signerRegistry));
        assertEq(numenaID.claimTypeRegistry(), address(claimTypeRegistry));
        assertEq(numenaID.verifier(), address(verifier));
        assertEq(numenaID.complianceDocument(), address(complianceDocument));
    }
    
    function test_Constructor_RevertZeroAddresses() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        new NumenaID(
            address(0),
            address(identityFactory),
            address(signerRegistry),
            address(claimTypeRegistry),
            address(verifier),
            address(complianceDocument)
        );
        
        vm.expectRevert(Errors.ZeroAddress.selector);
        new NumenaID(
            address(identityRegistry),
            address(0),
            address(signerRegistry),
            address(claimTypeRegistry),
            address(verifier),
            address(complianceDocument)
        );
    }
    
    // Test Identity Management Functions
    
    function test_CommitIdentity() public {
        uint256 nonce = 12345;
        bytes32 commitment = keccak256(abi.encodePacked(user2, nonce));
        
        vm.expectEmit(true, true, true, true);
        emit Events.IdentityCommitted(user2, commitment, block.timestamp);
        
        vm.prank(user2);
        numenaID.commitIdentity(commitment);
        
        // Verify commitment is stored in factory
        assertEq(identityFactory.commitments(user2), commitment);
    }
    
    function test_RevealAndCreateIdentity() public {
        uint256 nonce = 12345;
        bytes32 commitment = keccak256(abi.encodePacked(user2, nonce));
        
        // Commit
        vm.prank(user2);
        numenaID.commitIdentity(commitment);
        
        // Wait for delay
        vm.warp(block.timestamp + identityFactory.COMMITMENT_DELAY() + 1);
        
        // Reveal and create
        vm.expectEmit(true, false, true, true);
        emit Events.IdentityDeployed(user2, address(0), address(identityFactory));
        
        vm.prank(user2);
        address identity = numenaID.revealAndCreateIdentity(nonce);
        
        assertTrue(identity != address(0));
        assertEq(numenaID.getIdentity(user2), identity);
    }
    
    function test_CreateIdentity() public {
        // We can't predict the exact address, so we check all parameters except the identity address
        vm.expectEmit(true, false, true, true);
        emit Events.IdentityDeployed(user2, address(0), address(identityFactory));
        
        vm.prank(user2);
        address identity = numenaID.createIdentity();
        
        assertTrue(identity != address(0));
        assertEq(numenaID.getIdentity(user2), identity);
    }
    
    function test_GetIdentity() public {
        // Initially no identity
        assertEq(numenaID.getIdentity(user1), address(0));
        
        // Create identity for user1
        vm.prank(user1);
        address identity = numenaID.createIdentity();
        
        // Now user1 has identity
        assertEq(numenaID.getIdentity(user1), identity);
        assertTrue(identity != address(0));
        
        // user2 still has no identity
        assertEq(numenaID.getIdentity(user2), address(0));
    }
    
    function test_HasIdentity() public {
        // Initially no identities
        assertFalse(numenaID.hasIdentity(user1));
        assertFalse(numenaID.hasIdentity(user2));
        
        // Create identity for user1
        vm.prank(user1);
        numenaID.createIdentity();
        
        // Now user1 has identity, user2 doesn't
        assertTrue(numenaID.hasIdentity(user1));
        assertFalse(numenaID.hasIdentity(user2));
    }
    
    // Test Claim Verification Functions
    
    function test_HasValidClaim() public {
        // Create identity and add claim for user2
        vm.prank(user2);
        address user2Identity = numenaID.createIdentity();
        
        // Create documents
        uint256[] memory docs = new uint256[](1);
        docs[0] = createTestDocument(user2, TEST_DOCUMENT_TYPE);
        
        // Add claim
        bytes memory claimData = abi.encode(true);
        bytes memory signature = createClaimSignature(
            user2Identity,
            TEST_CLAIM_TYPE,
            docs,
            claimData,
            0,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        Identity(user2Identity).addClaim(TEST_CLAIM_TYPE, docs, 0, claimData, signature, signer1);
        
        // Test hasValidClaim
        assertTrue(numenaID.hasValidClaim(user2, TEST_CLAIM_TYPE));
        assertFalse(numenaID.hasValidClaim(user2, 999));
    }
    
    function test_HasAllClaims() public {
        // Create identity and add multiple claims for user2
        vm.prank(user2);
        address user2Identity = numenaID.createIdentity();
        
        // Add claim type permissions
        vm.prank(admin);
        uint256[] memory allowedTypes = new uint256[](2);
        allowedTypes[0] = 1;
        allowedTypes[1] = 2;
        signerRegistry.updateSignerClaimTypes(signer1, allowedTypes);
        
        // Create documents
        uint256[] memory docs = new uint256[](1);
        docs[0] = createTestDocument(user2, TEST_DOCUMENT_TYPE);
        
        // Add first claim
        bytes memory claimData = abi.encode(true);
        bytes memory signature1 = createClaimSignature(
            user2Identity,
            1,
            docs,
            claimData,
            0,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        Identity(user2Identity).addClaim(1, docs, 0, claimData, signature1, signer1);
        
        // Wait for rate limit
        vm.warp(block.timestamp + 61);
        
        // Add second claim
        bytes memory signature2 = createClaimSignature(
            user2Identity,
            2,
            docs,
            claimData,
            0,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        Identity(user2Identity).addClaim(2, docs, 0, claimData, signature2, signer1);
        
        // Test hasAllClaims
        uint256[] memory requiredClaims = new uint256[](2);
        requiredClaims[0] = 1;
        requiredClaims[1] = 2;
        
        assertTrue(numenaID.hasAllClaims(user2, requiredClaims));
        
        // Test with missing claim
        requiredClaims = new uint256[](3);
        requiredClaims[0] = 1;
        requiredClaims[1] = 2;
        requiredClaims[2] = 3;
        
        assertFalse(numenaID.hasAllClaims(user2, requiredClaims));
    }
    
    function test_GetClaimDetails() public {
        // Create identity and add claim
        vm.prank(user2);
        address user2Identity = numenaID.createIdentity();
        
        uint256[] memory docs = new uint256[](1);
        docs[0] = createTestDocument(user2, TEST_DOCUMENT_TYPE);
        
        bytes memory claimData = abi.encode(true);
        uint256 expiresAt = block.timestamp + 365 days;
        
        bytes memory signature = createClaimSignature(
            user2Identity,
            TEST_CLAIM_TYPE,
            docs,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        Identity(user2Identity).addClaim(TEST_CLAIM_TYPE, docs, expiresAt, claimData, signature, signer1);
        
        // Get claim details
        (
            address signer,
            uint256[] memory documentIds,
            bytes memory data,
            uint256 timestamp,
            uint256 expiry,
            bool revoked
        ) = numenaID.getClaimDetails(user2, TEST_CLAIM_TYPE);
        
        assertEq(signer, signer1);
        assertEq(documentIds.length, 1);
        assertEq(documentIds[0], docs[0]);
        assertEq(data, claimData);
        assertEq(timestamp, block.timestamp);
        assertEq(expiry, expiresAt);
        assertFalse(revoked);
    }
    
    // Test Signer Management Functions
    
    function test_IsValidSigner() public view {
        assertTrue(numenaID.isValidSigner(signer1));
        assertTrue(numenaID.isValidSigner(signer2));
        assertFalse(numenaID.isValidSigner(unauthorized));
    }
    
    function test_GetSigners() public view {
        address[] memory signers = numenaID.getSigners();
        assertEq(signers.length, 2);
        
        // Check both signers are present
        bool foundSigner1 = false;
        bool foundSigner2 = false;
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == signer1) foundSigner1 = true;
            if (signers[i] == signer2) foundSigner2 = true;
        }
        assertTrue(foundSigner1 && foundSigner2);
    }
    
    function test_GetSignersForClaim() public {
        // Add a new signer with different claim types
        address newSigner = makeAddr("newSigner");
        uint256[] memory allowedTypes = new uint256[](1);
        allowedTypes[0] = 2; // Different from TEST_CLAIM_TYPE
        
        vm.prank(admin);
        signerRegistry.addSigner(newSigner, allowedTypes, "New Signer");
        
        // Check signers for claim type 1
        address[] memory signersForType1 = numenaID.getSignersForClaim(1);
        assertEq(signersForType1.length, 2); // signer1 and signer2
        
        // Check signers for claim type 2
        address[] memory signersForType2 = numenaID.getSignersForClaim(2);
        assertEq(signersForType2.length, 1); // only newSigner
        assertEq(signersForType2[0], newSigner);
    }
    
    // Test Claim Type Functions
    
    function test_GetClaimType() public view {
        (
            string memory title,
            uint256[] memory requiredDocs,
            string memory dataType,
            bool active
        ) = numenaID.getClaimType(claimTypeRegistry.KYC_AML());
        
        assertEq(title, "KYC/AML Verified");
        assertEq(requiredDocs.length, 2);
        assertEq(dataType, "bool");
        assertTrue(active);
    }
    
    function test_GetAllClaimTypes() public view {
        uint256[] memory allTypes = numenaID.getAllClaimTypes();
        assertEq(allTypes.length, 4); // 4 predefined types
    }
    
    // Test Convenience Functions
    
    function test_BatchHasValidClaim() public {
        // Create identities and claims for multiple users
        address[] memory users = new address[](3);
        users[0] = user1; // Already has identity from setUp
        users[1] = makeAddr("batchUser1");
        users[2] = makeAddr("batchUser2");
        
        // Create identity for batchUser1
        vm.prank(users[1]);
        address identity1 = numenaID.createIdentity();
        
        // Add claim for batchUser1
        uint256[] memory docs = new uint256[](1);
        docs[0] = createTestDocument(users[1], TEST_DOCUMENT_TYPE);
        
        bytes memory claimData = abi.encode(true);
        bytes memory signature = createClaimSignature(
            identity1,
            TEST_CLAIM_TYPE,
            docs,
            claimData,
            0,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        Identity(identity1).addClaim(TEST_CLAIM_TYPE, docs, 0, claimData, signature, signer1);
        
        // Test batch check
        bool[] memory results = numenaID.batchHasValidClaim(users, TEST_CLAIM_TYPE);
        
        assertEq(results.length, 3);
        assertFalse(results[0]); // user1 has no claims
        assertTrue(results[1]); // batchUser1 has claim
        assertFalse(results[2]); // batchUser2 has no identity
    }
    
    function test_BatchHasValidClaim_RevertEmptyArray() public {
        address[] memory emptyUsers = new address[](0);
        
        vm.expectRevert(Errors.EmptyArray.selector);
        numenaID.batchHasValidClaim(emptyUsers, TEST_CLAIM_TYPE);
    }
    
    function test_BatchHasValidClaim_RevertTooLarge() public {
        address[] memory tooManyUsers = new address[](101); // MAX_BATCH_SIZE is 100
        
        vm.expectRevert(Errors.BatchSizeTooLarge.selector);
        numenaID.batchHasValidClaim(tooManyUsers, TEST_CLAIM_TYPE);
    }
    
    function test_GetAllModules() public view {
        (
            address _identityRegistry,
            address _identityFactory,
            address _signerRegistry,
            address _claimTypeRegistry,
            address _verifier
        ) = numenaID.getAllModules();
        
        assertEq(_identityRegistry, address(identityRegistry));
        assertEq(_identityFactory, address(identityFactory));
        assertEq(_signerRegistry, address(signerRegistry));
        assertEq(_claimTypeRegistry, address(claimTypeRegistry));
        assertEq(_verifier, address(verifier));
    }
}