// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./NumenaTestBase.sol";
import "../src/interfaces/ISignerRegistry.sol";
import "../src/libraries/Errors.sol";
import "../src/libraries/Events.sol";
import "../src/libraries/Roles.sol";

contract SignerRegistryTest is NumenaTestBase {
    address public newSigner = makeAddr("newSigner");
    
    function setUp() public override {
        super.setUp();
    }
    
    function test_Constructor() public view {
        assertTrue(signerRegistry.hasRole(Roles.ADMIN_ROLE, admin));
        assertEq(signerRegistry.identityFactory(), address(identityFactory));
    }
    
    function test_AddSigner_Success() public {
        uint256[] memory allowedTypes = new uint256[](2);
        allowedTypes[0] = 1;
        allowedTypes[1] = 2;
        
        vm.expectEmit(true, true, true, true);
        emit Events.SignerAdded(newSigner, allowedTypes, "New Signer");
        
        vm.prank(admin);
        signerRegistry.addSigner(newSigner, allowedTypes, "New Signer");
        
        assertTrue(signerRegistry.isValidSigner(newSigner));
        
        ISignerRegistry.SignerInfo memory info = signerRegistry.getSignerInfo(newSigner);
        assertTrue(info.active);
        assertEq(info.name, "New Signer");
        assertEq(info.allowedClaimTypes.length, 2);
        assertEq(info.allowedClaimTypes[0], 1);
        assertEq(info.allowedClaimTypes[1], 2);
        assertEq(info.totalClaims, 0);
        assertEq(info.revokedClaims, 0);
    }
    
    function test_AddSigner_RevertNotAdmin() public {
        uint256[] memory allowedTypes = new uint256[](1);
        allowedTypes[0] = 1;
        
        vm.expectRevert();
        vm.prank(unauthorized);
        signerRegistry.addSigner(newSigner, allowedTypes, "New Signer");
    }
    
    function test_AddSigner_RevertZeroAddress() public {
        uint256[] memory allowedTypes = new uint256[](1);
        allowedTypes[0] = 1;
        
        vm.expectRevert(Errors.ZeroAddress.selector);
        vm.prank(admin);
        signerRegistry.addSigner(address(0), allowedTypes, "New Signer");
    }
    
    function test_AddSigner_RevertEmptyClaimTypes() public {
        uint256[] memory allowedTypes = new uint256[](0);
        
        vm.expectRevert(Errors.EmptyArray.selector);
        vm.prank(admin);
        signerRegistry.addSigner(newSigner, allowedTypes, "New Signer");
    }
    
    function test_AddSigner_RevertTooManyClaimTypes() public {
        uint256[] memory allowedTypes = new uint256[](101);
        for (uint256 i = 0; i < 101; i++) {
            allowedTypes[i] = i;
        }
        
        vm.expectRevert(Errors.BatchSizeTooLarge.selector);
        vm.prank(admin);
        signerRegistry.addSigner(newSigner, allowedTypes, "New Signer");
    }
    
    function test_AddSigner_RevertEmptyName() public {
        uint256[] memory allowedTypes = new uint256[](1);
        allowedTypes[0] = 1;
        
        vm.expectRevert(Errors.InvalidData.selector);
        vm.prank(admin);
        signerRegistry.addSigner(newSigner, allowedTypes, "");
    }
    
    function test_AddSigner_RevertAlreadyActive() public {
        // signer1 is already active from setUp
        uint256[] memory allowedTypes = new uint256[](1);
        allowedTypes[0] = 1;
        
        vm.expectRevert(Errors.SignerAlreadyActive.selector);
        vm.prank(admin);
        signerRegistry.addSigner(signer1, allowedTypes, "Duplicate Signer");
    }
    
    function test_RemoveSigner_Success() public {
        // Verify signer1 is active
        assertTrue(signerRegistry.isValidSigner(signer1));
        
        vm.expectEmit(true, true, true, true);
        emit Events.SignerRemoved(signer1);
        
        vm.prank(admin);
        signerRegistry.removeSigner(signer1);
        
        assertFalse(signerRegistry.isValidSigner(signer1));
        
        // Signer info should still exist but be inactive
        ISignerRegistry.SignerInfo memory info = signerRegistry.getSignerInfo(signer1);
        assertFalse(info.active);
    }
    
    function test_RemoveSigner_RevertNotAdmin() public {
        vm.expectRevert();
        vm.prank(unauthorized);
        signerRegistry.removeSigner(signer1);
    }
    
    function test_RemoveSigner_RevertNotActive() public {
        vm.expectRevert(Errors.SignerNotActive.selector);
        vm.prank(admin);
        signerRegistry.removeSigner(newSigner); // Never added
    }
    
    function test_GetSigners() public {
        address[] memory signers = signerRegistry.getSigners();
        assertEq(signers.length, 2); // signer1 and signer2 from setUp
        
        // Add new signer
        uint256[] memory allowedTypes = new uint256[](1);
        allowedTypes[0] = 1;
        vm.prank(admin);
        signerRegistry.addSigner(newSigner, allowedTypes, "New Signer");
        
        signers = signerRegistry.getSigners();
        assertEq(signers.length, 3);
        
        // Remove a signer
        vm.prank(admin);
        signerRegistry.removeSigner(signer1);
        
        signers = signerRegistry.getSigners();
        assertEq(signers.length, 2); // Only active signers
    }
    
    function test_GetSignersForClaim() public {
        // Setup signers with different claim types
        uint256[] memory types1 = new uint256[](2);
        types1[0] = 1;
        types1[1] = 2;
        
        uint256[] memory types2 = new uint256[](1);
        types2[0] = 2;
        
        address signer3 = makeAddr("signer3");
        address signer4 = makeAddr("signer4");
        
        vm.startPrank(admin);
        signerRegistry.addSigner(signer3, types1, "Signer 3");
        signerRegistry.addSigner(signer4, types2, "Signer 4");
        vm.stopPrank();
        
        // Check signers for claim type 1
        address[] memory signersForType1 = signerRegistry.getSignersForClaim(1);
        assertEq(signersForType1.length, 3); // signer1, signer2 (from setUp), and signer3
        
        // Check signers for claim type 2
        address[] memory signersForType2 = signerRegistry.getSignersForClaim(2);
        assertEq(signersForType2.length, 2); // signer3 and signer4
    }
    
    function test_GetSignerCount() public view {
        uint256 count = signerRegistry.getSignerCount();
        assertEq(count, 2); // signer1 and signer2 from setUp
    }
    
    function test_CanSignClaimType() public view {
        assertTrue(signerRegistry.canSignClaimType(signer1, TEST_CLAIM_TYPE));
        assertFalse(signerRegistry.canSignClaimType(signer1, 999)); // Non-allowed type
        assertFalse(signerRegistry.canSignClaimType(unauthorized, TEST_CLAIM_TYPE)); // Not a signer
    }
    
    function test_UpdateSignerClaimTypes_Success() public {
        uint256[] memory newTypes = new uint256[](3);
        newTypes[0] = 1;
        newTypes[1] = 2;
        newTypes[2] = 3;
        
        vm.expectEmit(true, true, true, true);
        emit Events.SignerUpdated(signer1, newTypes);
        
        vm.prank(admin);
        signerRegistry.updateSignerClaimTypes(signer1, newTypes);
        
        ISignerRegistry.SignerInfo memory info = signerRegistry.getSignerInfo(signer1);
        assertEq(info.allowedClaimTypes.length, 3);
        assertTrue(signerRegistry.canSignClaimType(signer1, 2));
        assertTrue(signerRegistry.canSignClaimType(signer1, 3));
    }
    
    function test_UpdateSignerClaimTypes_RevertNotAdmin() public {
        uint256[] memory newTypes = new uint256[](1);
        newTypes[0] = 2;
        
        vm.expectRevert();
        vm.prank(unauthorized);
        signerRegistry.updateSignerClaimTypes(signer1, newTypes);
    }
    
    function test_UpdateSignerClaimTypes_RevertNotActive() public {
        uint256[] memory newTypes = new uint256[](1);
        newTypes[0] = 2;
        
        vm.expectRevert(Errors.SignerNotActive.selector);
        vm.prank(admin);
        signerRegistry.updateSignerClaimTypes(newSigner, newTypes); // Never added
    }
    
    function test_UpdateSignerClaimTypes_RevertEmptyArray() public {
        uint256[] memory newTypes = new uint256[](0);
        
        vm.expectRevert(Errors.EmptyArray.selector);
        vm.prank(admin);
        signerRegistry.updateSignerClaimTypes(signer1, newTypes);
    }
    
    function test_IncrementClaimCount_Success() public {
        // Deploy an identity through the factory
        address identity = createIdentity(user1);
        
        ISignerRegistry.SignerInfo memory infoBefore = signerRegistry.getSignerInfo(signer1);
        uint256 claimsBefore = infoBefore.totalClaims;
        
        // Call from the identity contract
        vm.prank(identity);
        signerRegistry.incrementClaimCount(signer1);
        
        ISignerRegistry.SignerInfo memory infoAfter = signerRegistry.getSignerInfo(signer1);
        assertEq(infoAfter.totalClaims, claimsBefore + 1);
    }
    
    function test_IncrementClaimCount_RevertNotIdentity() public {
        vm.expectRevert(Errors.InvalidIdentityContract.selector);
        vm.prank(unauthorized);
        signerRegistry.incrementClaimCount(signer1);
    }
    
    function test_SetIdentityFactory_RevertAlreadySet() public {
        // Factory is already set in setUp
        vm.expectRevert(Errors.FactoryAlreadySet.selector);
        vm.prank(admin);
        signerRegistry.setIdentityFactory(makeAddr("newFactory"));
    }
    
    function test_SetIdentityFactory_RevertNotAdmin() public {
        // Deploy new registry without factory set
        SignerRegistry newRegistry = new SignerRegistry(admin);
        
        vm.expectRevert();
        vm.prank(unauthorized);
        newRegistry.setIdentityFactory(makeAddr("factory"));
    }
    
    function test_GetSignersPaginated() public {
        // Add more signers for pagination test
        vm.startPrank(admin);
        for (uint256 i = 0; i < 5; i++) {
            address signer = makeAddr(string(abi.encodePacked("pageSigner", i)));
            uint256[] memory types = new uint256[](1);
            types[0] = 1;
            signerRegistry.addSigner(signer, types, string(abi.encodePacked("Signer ", i)));
        }
        vm.stopPrank();
        
        // Test pagination
        (address[] memory page1, uint256 total) = signerRegistry.getSignersPaginated(0, 3);
        assertEq(page1.length, 3);
        assertEq(total, 7); // 2 from setUp + 5 new ones
        
        (address[] memory page2, uint256 total2) = signerRegistry.getSignersPaginated(3, 3);
        assertEq(page2.length, 3);
        assertEq(total2, 7);
        
        (address[] memory page3, uint256 total3) = signerRegistry.getSignersPaginated(6, 3);
        assertEq(page3.length, 1); // Only 1 remaining
        assertEq(total3, 7);
    }
    
    function test_GetSignersForClaimPaginated() public {
        // Add signers for specific claim type
        vm.startPrank(admin);
        for (uint256 i = 0; i < 5; i++) {
            address signer = makeAddr(string(abi.encodePacked("claimSigner", i)));
            uint256[] memory types = new uint256[](1);
            types[0] = 5; // Use claim type 5
            signerRegistry.addSigner(signer, types, string(abi.encodePacked("Claim Signer ", i)));
        }
        vm.stopPrank();
        
        // Test pagination for claim type 5
        (address[] memory page1, uint256 total) = signerRegistry.getSignersForClaimPaginated(5, 0, 2);
        assertEq(page1.length, 2);
        assertEq(total, 5);
        
        (address[] memory page2, uint256 total2) = signerRegistry.getSignersForClaimPaginated(5, 2, 2);
        assertEq(page2.length, 2);
        assertEq(total2, 5);
    }
}