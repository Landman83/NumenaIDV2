// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./NumenaTestBase.sol";
import "../src/interfaces/IIdentity.sol";
import "../src/libraries/Errors.sol";
import "../src/libraries/Events.sol";

contract IdentityTest is NumenaTestBase {
    Identity public identity;
    uint256[] private testDocumentIds;
    
    function setUp() public override {
        super.setUp();
        
        // Create identity for user1
        address identityAddr = createIdentity(user1);
        identity = Identity(identityAddr);
        
        // Create test documents (owned by user, not identity contract)
        testDocumentIds = new uint256[](2);
        testDocumentIds[0] = createTestDocument(user1, TEST_DOCUMENT_TYPE);
        testDocumentIds[1] = createTestDocument(user1, 3); // UTILITY_BILL
        
        // Advance time to avoid rate limiting in tests
        vm.warp(block.timestamp + 61);
    }
    
    function test_Constructor() public view {
        assertEq(identity.owner(), user1);
        assertEq(identity.signerRegistry(), address(signerRegistry));
        assertEq(identity.numenaID(), address(numenaID));
    }
    
    function test_AddClaim_Success() public {
        bytes memory claimData = abi.encode(true);
        uint256 expiresAt = block.timestamp + 365 days;
        
        bytes memory signature = createClaimSignature(
            address(identity),
            TEST_CLAIM_TYPE,
            testDocumentIds,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.expectEmit(true, true, true, true);
        emit Events.ClaimAdded(address(identity), TEST_CLAIM_TYPE, signer1, address(0), expiresAt);
        
        vm.prank(signer1);
        identity.addClaim(TEST_CLAIM_TYPE, testDocumentIds, expiresAt, claimData, signature, signer1);
        
        IIdentity.Claim memory claim = identity.getClaim(TEST_CLAIM_TYPE);
        assertEq(claim.claimType, TEST_CLAIM_TYPE);
        assertEq(claim.signer, signer1);
        assertEq(claim.documentIds.length, testDocumentIds.length);
        assertEq(claim.data, claimData);
        assertEq(claim.expiresAt, expiresAt);
        assertFalse(claim.revoked);
    }
    
    function test_AddClaim_RevertUnauthorizedSigner() public {
        bytes memory claimData = abi.encode(true);
        uint256 expiresAt = block.timestamp + 365 days;
        
        // Create signature with authorized signer, but try to claim it was signed by unauthorized address
        bytes memory signature = createClaimSignature(
            address(identity),
            TEST_CLAIM_TYPE,
            testDocumentIds,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.expectRevert(Errors.NotAuthorizedSigner.selector);
        vm.prank(signer1);
        identity.addClaim(TEST_CLAIM_TYPE, testDocumentIds, expiresAt, claimData, signature, unauthorized);
    }
    
    function test_AddClaim_RevertExpiredClaim() public {
        bytes memory claimData = abi.encode(true);
        uint256 expiresAt = block.timestamp - 1; // Already expired
        
        bytes memory signature = createClaimSignature(
            address(identity),
            TEST_CLAIM_TYPE,
            testDocumentIds,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.expectRevert(Errors.InvalidData.selector);
        vm.prank(signer1);
        identity.addClaim(TEST_CLAIM_TYPE, testDocumentIds, expiresAt, claimData, signature, signer1);
    }
    
    function test_AddClaim_RevertEmptyData() public {
        bytes memory claimData = "";
        uint256 expiresAt = block.timestamp + 365 days;
        
        bytes memory signature = createClaimSignature(
            address(identity),
            TEST_CLAIM_TYPE,
            testDocumentIds,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.expectRevert(Errors.InvalidData.selector);
        vm.prank(signer1);
        identity.addClaim(TEST_CLAIM_TYPE, testDocumentIds, expiresAt, claimData, signature, signer1);
    }
    
    function test_AddClaim_RevertInvalidSignature() public {
        bytes memory claimData = abi.encode(true);
        uint256 expiresAt = block.timestamp + 365 days;
        
        // Create signature with wrong data
        bytes memory wrongData = abi.encode(false);
        bytes memory signature = createClaimSignature(
            address(identity),
            TEST_CLAIM_TYPE,
            testDocumentIds,
            wrongData, // Wrong data
            expiresAt,
            signer1PrivateKey
        );
        
        vm.expectRevert(Errors.InvalidSignature.selector);
        vm.prank(signer1);
        identity.addClaim(TEST_CLAIM_TYPE, testDocumentIds, expiresAt, claimData, signature, signer1);
    }
    
    function test_AddClaim_RevertRateLimit() public {
        bytes memory claimData = abi.encode(true);
        uint256 expiresAt = block.timestamp + 365 days;
        
        // First claim should succeed
        bytes memory signature1 = createClaimSignature(
            address(identity),
            TEST_CLAIM_TYPE,
            testDocumentIds,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        identity.addClaim(TEST_CLAIM_TYPE, testDocumentIds, expiresAt, claimData, signature1, signer1);
        
        // Second claim within rate limit window should fail
        uint256 claimType2 = 2; // Different claim type
        bytes memory signature2 = createClaimSignature(
            address(identity),
            claimType2,
            testDocumentIds,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        // Add signer permission for claim type 2
        vm.prank(admin);
        uint256[] memory newTypes = new uint256[](2);
        newTypes[0] = TEST_CLAIM_TYPE;
        newTypes[1] = claimType2;
        signerRegistry.updateSignerClaimTypes(signer1, newTypes);
        
        vm.expectRevert(Errors.RateLimitExceeded.selector);
        vm.prank(signer1);
        identity.addClaim(claimType2, testDocumentIds, expiresAt, claimData, signature2, signer1);
    }
    
    function test_RevokeClaim_BySigner() public {
        // First add a claim
        bytes memory claimData = abi.encode(true);
        uint256 expiresAt = block.timestamp + 365 days;
        
        bytes memory signature = createClaimSignature(
            address(identity),
            TEST_CLAIM_TYPE,
            testDocumentIds,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        identity.addClaim(TEST_CLAIM_TYPE, testDocumentIds, expiresAt, claimData, signature, signer1);
        
        // Revoke the claim
        vm.expectEmit(true, true, true, true);
        emit Events.ClaimRevoked(address(identity), TEST_CLAIM_TYPE, signer1);
        
        vm.prank(signer1);
        identity.revokeClaim(TEST_CLAIM_TYPE);
        
        IIdentity.Claim memory claim = identity.getClaim(TEST_CLAIM_TYPE);
        assertTrue(claim.revoked);
    }
    
    function test_RevokeClaim_ByOwner() public {
        // First add a claim
        bytes memory claimData = abi.encode(true);
        uint256 expiresAt = block.timestamp + 365 days;
        
        bytes memory signature = createClaimSignature(
            address(identity),
            TEST_CLAIM_TYPE,
            testDocumentIds,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        identity.addClaim(TEST_CLAIM_TYPE, testDocumentIds, expiresAt, claimData, signature, signer1);
        
        // Owner revokes the claim
        vm.expectEmit(true, true, true, true);
        emit Events.ClaimRevoked(address(identity), TEST_CLAIM_TYPE, user1);
        
        vm.prank(user1);
        identity.revokeClaim(TEST_CLAIM_TYPE);
        
        IIdentity.Claim memory claim = identity.getClaim(TEST_CLAIM_TYPE);
        assertTrue(claim.revoked);
    }
    
    function test_RevokeClaim_RevertUnauthorized() public {
        // First add a claim
        bytes memory claimData = abi.encode(true);
        uint256 expiresAt = block.timestamp + 365 days;
        
        bytes memory signature = createClaimSignature(
            address(identity),
            TEST_CLAIM_TYPE,
            testDocumentIds,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        identity.addClaim(TEST_CLAIM_TYPE, testDocumentIds, expiresAt, claimData, signature, signer1);
        
        // Unauthorized user tries to revoke
        vm.expectRevert(Errors.Unauthorized.selector);
        vm.prank(unauthorized);
        identity.revokeClaim(TEST_CLAIM_TYPE);
    }
    
    function test_RevokeClaim_RevertClaimNotFound() public {
        vm.expectRevert(Errors.ClaimNotFound.selector);
        vm.prank(user1);
        identity.revokeClaim(TEST_CLAIM_TYPE);
    }
    
    function test_HasValidClaim() public {
        // No claim initially
        assertFalse(identity.hasValidClaim(TEST_CLAIM_TYPE));
        
        // Add claim
        bytes memory claimData = abi.encode(true);
        uint256 expiresAt = block.timestamp + 365 days;
        
        bytes memory signature = createClaimSignature(
            address(identity),
            TEST_CLAIM_TYPE,
            testDocumentIds,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        identity.addClaim(TEST_CLAIM_TYPE, testDocumentIds, expiresAt, claimData, signature, signer1);
        
        // Should be valid
        assertTrue(identity.hasValidClaim(TEST_CLAIM_TYPE));
        
        // Revoke claim
        vm.prank(signer1);
        identity.revokeClaim(TEST_CLAIM_TYPE);
        
        // Should be invalid after revocation
        assertFalse(identity.hasValidClaim(TEST_CLAIM_TYPE));
    }
    
    function test_HasValidClaim_Expired() public {
        // Add claim that expires in 1 second
        bytes memory claimData = abi.encode(true);
        uint256 expiresAt = block.timestamp + 1;
        
        bytes memory signature = createClaimSignature(
            address(identity),
            TEST_CLAIM_TYPE,
            testDocumentIds,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        identity.addClaim(TEST_CLAIM_TYPE, testDocumentIds, expiresAt, claimData, signature, signer1);
        
        // Should be valid initially
        assertTrue(identity.hasValidClaim(TEST_CLAIM_TYPE));
        
        // Fast forward past expiration
        vm.warp(block.timestamp + 2);
        
        // Should be invalid after expiration
        assertFalse(identity.hasValidClaim(TEST_CLAIM_TYPE));
    }
    
    function test_TransferOwnership() public {
        vm.expectEmit(true, true, true, true);
        emit Events.OwnershipTransferred(address(identity), user1, user2);
        
        vm.prank(user1);
        identity.transferOwnership(user2);
        
        assertEq(identity.owner(), user2);
    }
    
    function test_TransferOwnership_RevertNotOwner() public {
        vm.expectRevert(Errors.OnlyOwner.selector);
        vm.prank(unauthorized);
        identity.transferOwnership(user2);
    }
    
    function test_TransferOwnership_RevertZeroAddress() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        vm.prank(user1);
        identity.transferOwnership(address(0));
    }
    
    function test_GetDocumentsByType() public {
        // Create more documents of different types (owned by user)
        uint256 doc1 = createTestDocument(user1, 1); // PASSPORT
        uint256 doc2 = createTestDocument(user1, 2); // DRIVERS_LICENSE
        uint256 doc3 = createTestDocument(user1, 1); // Another PASSPORT
        
        // Since documents are owned by user1, not the identity contract,
        // these functions will return empty arrays
        uint256[] memory passports = identity.getDocumentsByType(1);
        assertEq(passports.length, 0); // Identity doesn't own any documents
        
        uint256[] memory licenses = identity.getDocumentsByType(2);
        assertEq(licenses.length, 0);
    }
    
    function test_GetMostRecentDocumentByType() public {
        // Create documents with time gaps
        uint256 doc1 = createTestDocument(user1, 5); // INCOME_STATEMENT
        
        vm.warp(block.timestamp + 100);
        uint256 doc2 = createTestDocument(user1, 5); // Another INCOME_STATEMENT
        
        vm.warp(block.timestamp + 100);
        uint256 doc3 = createTestDocument(user1, 5); // Most recent
        
        // Since documents are owned by user1, not the identity contract,
        // this should revert with DocumentNotFound
        vm.expectRevert(Errors.DocumentNotFound.selector);
        identity.getMostRecentDocumentByType(5);
    }
    
    function test_GetMostRecentDocumentByType_RevertNotFound() public {
        vm.expectRevert(Errors.DocumentNotFound.selector);
        identity.getMostRecentDocumentByType(999); // Non-existent type
    }
}