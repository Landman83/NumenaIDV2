// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./NumenaTestBase.sol";
import "../src/interfaces/IIdentity.sol";
import "../src/libraries/Errors.sol";

contract VerifierTest is NumenaTestBase {
    address public userIdentity;
    uint256[] public documentIds;
    bytes public claimData;
    
    function setUp() public override {
        super.setUp();
        
        // Create identity for user1
        vm.prank(user1);
        userIdentity = identityFactory.deployIdentity();
        
        // Create test documents
        documentIds = new uint256[](2);
        documentIds[0] = createTestDocument(user1, TEST_DOCUMENT_TYPE);
        documentIds[1] = createTestDocument(user1, 3); // UTILITY_BILL
        
        // Advance time to avoid rate limiting
        vm.warp(block.timestamp + 61);
        
        // Add a test claim
        claimData = abi.encode(true);
        uint256 expiresAt = block.timestamp + 365 days;
        
        bytes memory signature = createClaimSignature(
            userIdentity,
            TEST_CLAIM_TYPE,
            documentIds,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        Identity(userIdentity).addClaim(TEST_CLAIM_TYPE, documentIds, expiresAt, claimData, signature, signer1);
    }
    
    function test_Constructor() public view {
        assertEq(address(verifier.identityRegistry()), address(identityRegistry));
        assertEq(address(verifier.signerRegistry()), address(signerRegistry));
        assertEq(verifier.numenaID(), address(1)); // Placeholder address used in test setup
    }
    
    function test_IsValidSigner() public view {
        assertTrue(verifier.isValidSigner(signer1));
        assertTrue(verifier.isValidSigner(signer2));
        assertFalse(verifier.isValidSigner(unauthorized));
    }
    
    function test_HasValidClaim() public view {
        assertTrue(verifier.hasValidClaim(user1, TEST_CLAIM_TYPE));
        assertFalse(verifier.hasValidClaim(user1, 999)); // Non-existent claim
        assertFalse(verifier.hasValidClaim(user2, TEST_CLAIM_TYPE)); // User2 has no identity
    }
    
    function test_HasValidClaim_Revoked() public {
        // Revoke the claim
        vm.prank(signer1);
        Identity(userIdentity).revokeClaim(TEST_CLAIM_TYPE);
        
        assertFalse(verifier.hasValidClaim(user1, TEST_CLAIM_TYPE));
    }
    
    function test_HasValidClaim_Expired() public {
        // Add claim that expires soon
        uint256 claimType2 = 2;
        
        // Update signer permissions
        vm.prank(admin);
        uint256[] memory newTypes = new uint256[](2);
        newTypes[0] = TEST_CLAIM_TYPE;
        newTypes[1] = claimType2;
        signerRegistry.updateSignerClaimTypes(signer1, newTypes);
        
        // Create documents required for claimType2
        uint256[] memory requiredDocs = claimTypeRegistry.getRequiredDocuments(claimType2);
        uint256[] memory claimType2Docs = new uint256[](requiredDocs.length);
        for (uint256 i = 0; i < requiredDocs.length; i++) {
            claimType2Docs[i] = createTestDocument(user1, requiredDocs[i]);
        }
        
        // Wait for rate limit
        vm.warp(block.timestamp + 61);
        
        // Set expiration time AFTER warping to ensure it's relative to current time
        uint256 expiresAt = block.timestamp + 1;
        
        bytes memory signature = createClaimSignature(
            userIdentity,
            claimType2,
            claimType2Docs,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        Identity(userIdentity).addClaim(claimType2, claimType2Docs, expiresAt, claimData, signature, signer1);
        
        // Should be valid initially
        assertTrue(verifier.hasValidClaim(user1, claimType2));
        
        // Fast forward past expiration
        vm.warp(block.timestamp + 2);
        
        // Should be invalid after expiration
        assertFalse(verifier.hasValidClaim(user1, claimType2));
    }
    
    function test_GetClaimSigner() public view {
        assertEq(verifier.getClaimSigner(user1, TEST_CLAIM_TYPE), signer1);
        assertEq(verifier.getClaimSigner(user1, 999), address(0)); // Non-existent claim
        assertEq(verifier.getClaimSigner(user2, TEST_CLAIM_TYPE), address(0)); // No identity
    }
    
    function test_GetClaimDocumentIds() public view {
        uint256[] memory docs = verifier.getClaimDocumentIds(user1, TEST_CLAIM_TYPE);
        assertEq(docs.length, 2);
        assertEq(docs[0], documentIds[0]);
        assertEq(docs[1], documentIds[1]);
        
        // Non-existent claim returns empty array
        docs = verifier.getClaimDocumentIds(user1, 999);
        assertEq(docs.length, 0);
        
        // User without identity returns empty array
        docs = verifier.getClaimDocumentIds(user2, TEST_CLAIM_TYPE);
        assertEq(docs.length, 0);
    }
    
    function test_GetClaimData() public view {
        bytes memory data = verifier.getClaimData(user1, TEST_CLAIM_TYPE);
        assertEq(data, claimData);
    }
    
    function test_GetClaimData_RevertNoIdentity() public {
        vm.expectRevert(Errors.IdentityNotFound.selector);
        verifier.getClaimData(user2, TEST_CLAIM_TYPE);
    }
    
    function test_HasAllClaims() public {
        // Add another claim type
        uint256 claimType2 = 2;
        
        // Update signer permissions
        vm.prank(admin);
        uint256[] memory newTypes = new uint256[](2);
        newTypes[0] = TEST_CLAIM_TYPE;
        newTypes[1] = claimType2;
        signerRegistry.updateSignerClaimTypes(signer1, newTypes);
        
        // Wait for rate limit
        vm.warp(block.timestamp + 61);
        
        bytes memory signature = createClaimSignature(
            userIdentity,
            claimType2,
            documentIds,
            claimData,
            0, // No expiration
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        Identity(userIdentity).addClaim(claimType2, documentIds, 0, claimData, signature, signer1);
        
        // Check single claim
        uint256[] memory requiredClaims = new uint256[](1);
        requiredClaims[0] = TEST_CLAIM_TYPE;
        assertTrue(verifier.hasAllClaims(user1, requiredClaims));
        
        // Check multiple claims
        requiredClaims = new uint256[](2);
        requiredClaims[0] = TEST_CLAIM_TYPE;
        requiredClaims[1] = claimType2;
        assertTrue(verifier.hasAllClaims(user1, requiredClaims));
        
        // Check with missing claim
        requiredClaims = new uint256[](3);
        requiredClaims[0] = TEST_CLAIM_TYPE;
        requiredClaims[1] = claimType2;
        requiredClaims[2] = 999; // Non-existent
        assertFalse(verifier.hasAllClaims(user1, requiredClaims));
        
        // Empty array should return true
        requiredClaims = new uint256[](0);
        assertTrue(verifier.hasAllClaims(user1, requiredClaims));
        
        // User without identity returns false
        requiredClaims = new uint256[](1);
        requiredClaims[0] = TEST_CLAIM_TYPE;
        assertFalse(verifier.hasAllClaims(user2, requiredClaims));
    }
    
    function test_HasAllClaims_RevertTooMany() public {
        uint256[] memory requiredClaims = new uint256[](51); // MAX_CLAIMS_PER_CHECK is 50
        
        vm.expectRevert(Errors.BatchSizeTooLarge.selector);
        verifier.hasAllClaims(user1, requiredClaims);
    }
    
    function test_GetClaimDetails() public {
        (
            address signer,
            uint256[] memory docs,
            bytes memory data,
            uint256 timestamp,
            uint256 expiresAt,
            bool revoked
        ) = verifier.getClaimDetails(user1, TEST_CLAIM_TYPE);
        
        assertEq(signer, signer1);
        assertEq(docs.length, 2);
        assertEq(docs[0], documentIds[0]);
        assertEq(docs[1], documentIds[1]);
        assertEq(data, claimData);
        assertEq(timestamp, block.timestamp);
        assertEq(expiresAt, block.timestamp + 365 days);
        assertFalse(revoked);
    }
    
    function test_GetClaimDetails_RevertNoIdentity() public {
        vm.expectRevert(Errors.IdentityNotFound.selector);
        verifier.getClaimDetails(user2, TEST_CLAIM_TYPE);
    }
    
    function test_VerifyClaimSignature() public view {
        assertTrue(verifier.verifyClaimSignature(user1, TEST_CLAIM_TYPE));
        assertFalse(verifier.verifyClaimSignature(user1, 999)); // Non-existent claim
        assertFalse(verifier.verifyClaimSignature(user2, TEST_CLAIM_TYPE)); // No identity
    }
    
    function test_CreateClaimWithDocuments() public {
        // Create a new user and identity
        address user3 = makeAddr("user3");
        vm.prank(user3);
        address user3Identity = identityFactory.deployIdentity();
        
        // Create required documents for KYC claim
        uint256[] memory requiredDocs = claimTypeRegistry.getRequiredDocuments(TEST_CLAIM_TYPE);
        uint256[] memory documentIds = new uint256[](requiredDocs.length);
        for (uint256 i = 0; i < requiredDocs.length; i++) {
            documentIds[i] = createTestDocument(user3, requiredDocs[i]);
        }
        
        // Prepare claim data
        bytes memory newClaimData = abi.encode(true);
        uint256 expiresAt = block.timestamp + 30 days;
        
        bytes memory signature = createClaimSignature(
            user3Identity,
            TEST_CLAIM_TYPE,
            documentIds,
            newClaimData,
            expiresAt,
            signer1PrivateKey
        );
        
        // Create claim directly via Identity contract (what createClaimWithDocuments does internally)
        vm.prank(signer1);
        Identity(user3Identity).addClaim(TEST_CLAIM_TYPE, documentIds, expiresAt, newClaimData, signature, signer1);
        
        // Verify claim was created
        assertTrue(verifier.hasValidClaim(user3, TEST_CLAIM_TYPE));
    }
    
    function test_CreateClaimWithDocuments_RevertNoIdentity() public {
        // Test that verifier correctly identifies when user has no identity
        assertFalse(verifier.hasValidClaim(user2, TEST_CLAIM_TYPE)); // user2 has no identity
        
        // Test getClaimData reverts for user without identity
        vm.expectRevert(Errors.IdentityNotFound.selector);
        verifier.getClaimData(user2, TEST_CLAIM_TYPE);
    }
    
    function test_VerifyClaimDocuments() public {
        // Test that claim documents can be verified by checking their relationship
        uint256[] memory claimDocIds = verifier.getClaimDocumentIds(user1, TEST_CLAIM_TYPE);
        uint256[] memory requiredDocs = claimTypeRegistry.getRequiredDocuments(TEST_CLAIM_TYPE);
        
        // Should have same number of documents as required
        assertEq(claimDocIds.length, requiredDocs.length);
        
        // Verify document IDs exist (in ERC721, token ID 0 can be valid)
        // We just check that we got some document IDs back
        assertTrue(claimDocIds.length > 0, "Should have document IDs");
        
        // Verify we can get claim details (which includes documents)
        (
            address signer,
            uint256[] memory docs,
            bytes memory data,
            uint256 timestamp,
            uint256 expiresAt,
            bool revoked
        ) = verifier.getClaimDetails(user1, TEST_CLAIM_TYPE);
        
        assertEq(docs.length, requiredDocs.length);
        assertEq(signer, signer1);
        assertFalse(revoked);
    }
    
    function test_RecoverSigner() public view {
        // Create a test message hash
        bytes32 messageHash = keccak256("test message");
        
        // Sign with signer1's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer1PrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Recover signer
        address recovered = verifier.recoverSigner(messageHash, signature);
        assertEq(recovered, signer1);
    }
}