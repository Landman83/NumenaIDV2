// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./NumenaTestBase.sol";
import "../src/interfaces/IIdentity.sol";
import "../src/interfaces/IComplianceDocument.sol";
import "../src/libraries/Errors.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

/**
 * @title Integration Tests
 * @dev Tests the complete flow of the NumenaID system
 */
contract IntegrationTest is NumenaTestBase, IERC721Receiver {
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public tokenContract = makeAddr("tokenContract");
    
    function setUp() public override {
        super.setUp();
        
        // Give ETH to test users
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
    }
    
    /**
     * @dev Implements IERC721Receiver to accept ERC721 tokens
     */
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }
    
    /**
     * @dev Test complete KYC flow for a user
     */
    function test_CompleteKYCFlow() public {
        // Step 1: Alice creates an identity using commit-reveal pattern
        uint256 nonce = 12345;
        bytes32 commitment = keccak256(abi.encodePacked(alice, nonce));
        
        vm.prank(alice);
        identityFactory.commitIdentity(commitment);
        
        // Wait for commitment delay
        vm.warp(block.timestamp + identityFactory.COMMITMENT_DELAY() + 1);
        
        vm.prank(alice);
        address aliceIdentity = identityFactory.revealAndDeployIdentity(nonce);
        
        assertTrue(aliceIdentity != address(0));
        assertTrue(numenaID.hasIdentity(alice));
        
        // Step 2: Alice uploads required KYC documents
        uint256[] memory requiredDocs = claimTypeRegistry.getRequiredDocuments(claimTypeRegistry.KYC_AML());
        uint256[] memory uploadedDocs = new uint256[](requiredDocs.length);
        
        for (uint256 i = 0; i < requiredDocs.length; i++) {
            vm.prank(alice); // User owns documents
            uploadedDocs[i] = complianceDocument.mintDocument(
                string(abi.encodePacked("AliceDoc", i)),
                string(abi.encodePacked("/ipfs/AliceDoc", i)),
                requiredDocs[i],
                1024 * (i + 1)
            );
        }
        
        // Verify documents were uploaded
        assertEq(complianceDocument.ownerOf(uploadedDocs[0]), alice);
        assertEq(complianceDocument.ownerOf(uploadedDocs[1]), alice);
        
        // Step 3: Signer verifies documents and creates KYC claim
        bytes memory kycData = abi.encode(true); // KYC passed
        uint256 expiresAt = block.timestamp + 365 days;
        
        bytes memory signature = createClaimSignature(
            aliceIdentity,
            claimTypeRegistry.KYC_AML(),
            uploadedDocs,
            kycData,
            expiresAt,
            signer1PrivateKey
        );
        
        // Signer accesses documents for verification
        vm.startPrank(signer1);
        IComplianceDocument.Document memory doc1 = complianceDocument.getDocument(uploadedDocs[0]);
        IComplianceDocument.Document memory doc2 = complianceDocument.getDocument(uploadedDocs[1]);
        assertEq(doc1.documentType, requiredDocs[0]);
        assertEq(doc2.documentType, requiredDocs[1]);
        
        // Signer adds KYC claim
        Identity(aliceIdentity).addClaim(
            claimTypeRegistry.KYC_AML(),
            uploadedDocs,
            expiresAt,
            kycData,
            signature,
            signer1
        );
        vm.stopPrank();
        
        // Step 4: Verify claim was added successfully
        assertTrue(numenaID.hasValidClaim(alice, claimTypeRegistry.KYC_AML()));
        assertEq(verifier.getClaimSigner(alice, claimTypeRegistry.KYC_AML()), signer1);
        
        // Step 5: Token contract checks KYC status
        vm.prank(tokenContract);
        bool hasKYC = numenaID.hasValidClaim(alice, claimTypeRegistry.KYC_AML());
        assertTrue(hasKYC);
    }
    
    /**
     * @dev Test accredited investor verification flow
     */
    function test_AccreditedInvestorFlow() public {
        // Create identity for Bob
        vm.prank(bob);
        address bobIdentity = numenaID.createIdentity();
        
        // Upload required documents for accredited investor
        uint256[] memory requiredDocs = claimTypeRegistry.getRequiredDocuments(claimTypeRegistry.ACCREDITED_INVESTOR());
        uint256[] memory uploadedDocs = new uint256[](requiredDocs.length);
        
        vm.startPrank(bob);
        for (uint256 i = 0; i < requiredDocs.length; i++) {
            uploadedDocs[i] = complianceDocument.mintDocument(
                string(abi.encodePacked("BobAccreditedDoc", i)),
                string(abi.encodePacked("/ipfs/BobAccreditedDoc", i)),
                requiredDocs[i],
                2048 * (i + 1)
            );
        }
        vm.stopPrank();
        
        // Update signer permissions to include accredited investor claims
        uint256[] memory newTypes = new uint256[](2);
        newTypes[0] = claimTypeRegistry.KYC_AML();
        newTypes[1] = claimTypeRegistry.ACCREDITED_INVESTOR();
        vm.prank(admin);
        signerRegistry.updateSignerClaimTypes(signer1, newTypes);
        
        // Signer creates accredited investor claim
        bytes memory accreditedData = abi.encode(true);
        bytes memory signature = createClaimSignature(
            bobIdentity,
            claimTypeRegistry.ACCREDITED_INVESTOR(),
            uploadedDocs,
            accreditedData,
            0, // No expiration
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        Identity(bobIdentity).addClaim(
            claimTypeRegistry.ACCREDITED_INVESTOR(),
            uploadedDocs,
            0,
            accreditedData,
            signature,
            signer1
        );
        
        // Verify accredited investor status
        assertTrue(numenaID.hasValidClaim(bob, claimTypeRegistry.ACCREDITED_INVESTOR()));
    }
    
    /**
     * @dev Test multiple claims and document access patterns
     */
    function test_MultipleClaimsAndAccessControl() public {
        // Create identity
        vm.prank(alice);
        address aliceIdentity = numenaID.createIdentity();
        
        // Upload various documents
        uint256 passport = createTestDocument(alice, claimTypeRegistry.PASSPORT());
        uint256 bankStatement = createTestDocument(alice, claimTypeRegistry.BANK_STATEMENT());
        uint256 utilityBill = createTestDocument(alice, claimTypeRegistry.UTILITY_BILL());
        
        // Add KYC claim
        uint256[] memory kycDocs = new uint256[](2);
        kycDocs[0] = passport;
        kycDocs[1] = utilityBill;
        
        bytes memory kycData = abi.encode(true);
        bytes memory kycSignature = createClaimSignature(
            aliceIdentity,
            claimTypeRegistry.KYC_AML(),
            kycDocs,
            kycData,
            block.timestamp + 180 days,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        Identity(aliceIdentity).addClaim(
            claimTypeRegistry.KYC_AML(),
            kycDocs,
            block.timestamp + 180 days,
            kycData,
            kycSignature,
            signer1
        );
        
        // Wait for rate limit
        vm.warp(block.timestamp + 61);
        
        // Add accredited investor claim with different signer
        uint256[] memory accreditedDocs = new uint256[](2);
        accreditedDocs[0] = bankStatement;
        accreditedDocs[1] = passport;
        
        // Update signer2 permissions
        uint256[] memory signer2Types = new uint256[](2);
        signer2Types[0] = claimTypeRegistry.KYC_AML();
        signer2Types[1] = claimTypeRegistry.ACCREDITED_INVESTOR();
        vm.prank(admin);
        signerRegistry.updateSignerClaimTypes(signer2, signer2Types);
        
        bytes memory accreditedData = abi.encode(true);
        bytes memory accreditedSignature = createClaimSignature(
            aliceIdentity,
            claimTypeRegistry.ACCREDITED_INVESTOR(),
            accreditedDocs,
            accreditedData,
            0,
            signer2PrivateKey
        );
        
        vm.prank(signer2);
        Identity(aliceIdentity).addClaim(
            claimTypeRegistry.ACCREDITED_INVESTOR(),
            accreditedDocs,
            0,
            accreditedData,
            accreditedSignature,
            signer2
        );
        
        // Verify both claims exist
        uint256[] memory requiredClaims = new uint256[](2);
        requiredClaims[0] = claimTypeRegistry.KYC_AML();
        requiredClaims[1] = claimTypeRegistry.ACCREDITED_INVESTOR();
        
        assertTrue(numenaID.hasAllClaims(alice, requiredClaims));
        
        // Check document access history
        vm.prank(alice); // Only document owner can view access history
        IComplianceDocument.AccessRecord[] memory passportHistory = complianceDocument.getAccessHistory(passport);
        assertEq(passportHistory.length, 1); // Only initial mint access
        assertEq(passportHistory[0].accessor, alice);
        assertEq(passportHistory[0].accessType, 0); // ACCESS_TYPE_OWNER
    }
    
    /**
     * @dev Test claim revocation and expiration
     */
    function test_ClaimRevocationAndExpiration() public {
        // Create identity and add claim
        vm.prank(alice);
        address aliceIdentity = numenaID.createIdentity();
        
        uint256[] memory docs = new uint256[](1);
        docs[0] = createTestDocument(alice, claimTypeRegistry.PASSPORT());
        
        // Add claim that expires in 1 hour
        bytes memory claimData = abi.encode(true);
        uint256 expiresAt = block.timestamp + 1 hours;
        
        bytes memory signature = createClaimSignature(
            aliceIdentity,
            claimTypeRegistry.KYC_AML(),
            docs,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        Identity(aliceIdentity).addClaim(
            claimTypeRegistry.KYC_AML(),
            docs,
            expiresAt,
            claimData,
            signature,
            signer1
        );
        
        // Claim should be valid initially
        assertTrue(numenaID.hasValidClaim(alice, claimTypeRegistry.KYC_AML()));
        
        // Test revocation by signer  
        uint256 kycClaimType = claimTypeRegistry.KYC_AML();
        vm.prank(signer1);
        Identity(aliceIdentity).revokeClaim(kycClaimType);
        
        // Claim should be invalid after revocation
        assertFalse(numenaID.hasValidClaim(alice, claimTypeRegistry.KYC_AML()));
        
        // Add new claim for expiration test
        vm.warp(block.timestamp + 61); // Wait for rate limit
        
        bytes memory signature2 = createClaimSignature(
            aliceIdentity,
            claimTypeRegistry.KYC_AML(),
            docs,
            claimData,
            expiresAt,
            signer1PrivateKey
        );
        
        vm.prank(signer1);
        Identity(aliceIdentity).addClaim(
            claimTypeRegistry.KYC_AML(),
            docs,
            expiresAt,
            claimData,
            signature2,
            signer1
        );
        
        // Fast forward past expiration
        vm.warp(expiresAt + 1);
        
        // Claim should be invalid after expiration
        assertFalse(numenaID.hasValidClaim(alice, claimTypeRegistry.KYC_AML()));
    }
    
    /**
     * @dev Test batch verification for multiple users
     */
    function test_BatchUserVerification() public {
        address[] memory users = new address[](5);
        for (uint256 i = 0; i < 5; i++) {
            users[i] = makeAddr(string(abi.encodePacked("user", i)));
            vm.deal(users[i], 1 ether);
        }
        
        // Create identities and add claims for first 3 users
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(users[i]);
            address identity = numenaID.createIdentity();
            
            uint256[] memory docs = new uint256[](1);
            docs[0] = createTestDocument(users[i], claimTypeRegistry.PASSPORT());
            
            bytes memory claimData = abi.encode(true);
            bytes memory signature = createClaimSignature(
                identity,
                claimTypeRegistry.KYC_AML(),
                docs,
                claimData,
                0,
                signer1PrivateKey
            );
            
            // Wait for rate limit if not first user
            if (i > 0) {
                vm.warp(block.timestamp + 61);
            }
            
            vm.prank(signer1);
            Identity(identity).addClaim(
                claimTypeRegistry.KYC_AML(),
                docs,
                0,
                claimData,
                signature,
                signer1
            );
        }
        
        // Batch check all users
        bool[] memory results = numenaID.batchHasValidClaim(users, claimTypeRegistry.KYC_AML());
        
        assertEq(results.length, 5);
        assertTrue(results[0]); // Has claim
        assertTrue(results[1]); // Has claim
        assertTrue(results[2]); // Has claim
        assertFalse(results[3]); // No identity
        assertFalse(results[4]); // No identity
    }
    
    /**
     * @dev Test document ownership and basic access
     */
    function test_DocumentOwnershipTransfer() public {
        // Alice creates identity and uploads document
        vm.prank(alice);
        address aliceIdentity = numenaID.createIdentity();
        
        uint256 docId = createTestDocument(alice, claimTypeRegistry.PASSPORT());
        
        // Verify alice owns the document
        assertEq(complianceDocument.ownerOf(docId), alice);
        
        // Alice can access document history
        vm.prank(alice);
        IComplianceDocument.AccessRecord[] memory history = complianceDocument.getAccessHistory(docId);
        
        // Should have at least mint access
        assertEq(history.length, 1);
        assertEq(history[0].accessor, alice);
        assertEq(history[0].accessType, 0); // ACCESS_TYPE_OWNER
    }
}