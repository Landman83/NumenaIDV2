// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./NumenaTestBase.sol";
import "../src/libraries/Errors.sol";
import "../src/libraries/Events.sol";

contract IdentityRegistryTest is NumenaTestBase {
    address public testIdentity;
    
    function setUp() public override {
        super.setUp();
        
        // Create a test identity for user1
        vm.prank(user1);
        testIdentity = identityFactory.deployIdentity();
    }
    
    function test_Constructor() public view {
        assertEq(identityRegistry.identityFactory(), address(identityFactory));
    }
    
    function test_RegisterIdentity_Success() public {
        // Deploy a new registry for this test
        IdentityRegistry newRegistry = new IdentityRegistry(address(identityFactory));
        
        // Deploy a mock identity contract
        address mockIdentity = address(new MockIdentity(user2));
        
        vm.expectEmit(true, true, true, true);
        emit Events.IdentityRegistered(user2, mockIdentity);
        
        vm.prank(address(identityFactory));
        newRegistry.registerIdentity(mockIdentity, user2);
        
        assertEq(newRegistry.getIdentity(user2), mockIdentity);
        assertEq(newRegistry.identityCount(), 1);
    }
    
    function test_RegisterIdentity_RevertNotFactory() public {
        address mockIdentity = address(new MockIdentity(user2));
        
        vm.expectRevert(Errors.OnlyFactory.selector);
        vm.prank(unauthorized);
        identityRegistry.registerIdentity(mockIdentity, user2);
    }
    
    function test_RegisterIdentity_RevertZeroAddress() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        vm.prank(address(identityFactory));
        identityRegistry.registerIdentity(address(0), user2);
        
        vm.expectRevert(Errors.ZeroAddress.selector);
        vm.prank(address(identityFactory));
        identityRegistry.registerIdentity(makeAddr("identity"), address(0));
    }
    
    function test_RegisterIdentity_RevertOwnerMismatch() public {
        // Create identity with wrong owner
        address mockIdentity = address(new MockIdentity(user1)); // Owner is user1
        
        vm.expectRevert(Errors.OwnerMismatch.selector);
        vm.prank(address(identityFactory));
        identityRegistry.registerIdentity(mockIdentity, user2); // Try to register for user2
    }
    
    function test_RegisterIdentity_RevertAlreadyExists() public {
        // user1 already has an identity from setUp
        address newIdentity = address(new MockIdentity(user1));
        
        vm.expectRevert(Errors.IdentityAlreadyExists.selector);
        vm.prank(address(identityFactory));
        identityRegistry.registerIdentity(newIdentity, user1);
    }
    
    function test_RemoveIdentity_Success() public {
        // Check identity exists
        assertEq(identityRegistry.getIdentity(user1), testIdentity);
        uint256 countBefore = identityRegistry.identityCount();
        
        vm.expectEmit(true, true, true, true);
        emit Events.IdentityRemoved(user1, testIdentity);
        
        vm.prank(user1);
        identityRegistry.removeIdentity();
        
        assertEq(identityRegistry.getIdentity(user1), address(0));
        assertEq(identityRegistry.identityCount(), countBefore - 1);
    }
    
    function test_RemoveIdentity_RevertNotFound() public {
        vm.expectRevert(Errors.IdentityNotFound.selector);
        vm.prank(user2); // user2 has no identity
        identityRegistry.removeIdentity();
    }
    
    function test_GetIdentity() public view {
        assertEq(identityRegistry.getIdentity(user1), testIdentity);
        assertEq(identityRegistry.getIdentity(user2), address(0));
    }
    
    function test_GetIdentityCount() public {
        uint256 initialCount = identityRegistry.identityCount();
        
        // Deploy identity for user2
        vm.prank(user2);
        identityFactory.deployIdentity();
        
        assertEq(identityRegistry.identityCount(), initialCount + 1);
    }
    
    function test_UpdateIdentity_Success() public {
        // Deploy a new identity contract for user1
        address newIdentity = address(new MockIdentity(user1));
        
        vm.expectEmit(true, true, true, true);
        emit Events.IdentityUpdated(user1, testIdentity, newIdentity);
        
        vm.prank(user1);
        identityRegistry.updateIdentity(newIdentity);
        
        assertEq(identityRegistry.getIdentity(user1), newIdentity);
    }
    
    function test_UpdateIdentity_RevertZeroAddress() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        vm.prank(user1);
        identityRegistry.updateIdentity(address(0));
    }
    
    function test_UpdateIdentity_RevertNoIdentity() public {
        vm.expectRevert(Errors.IdentityNotFound.selector);
        vm.prank(user2); // user2 has no identity
        identityRegistry.updateIdentity(makeAddr("newIdentity"));
    }
    
    function test_UpdateIdentity_RevertOwnerMismatch() public {
        // Create identity with wrong owner
        address wrongIdentity = address(new MockIdentity(user2));
        
        vm.expectRevert(Errors.OwnerMismatch.selector);
        vm.prank(user1);
        identityRegistry.updateIdentity(wrongIdentity);
    }
    
    function test_HasIdentity() public view {
        assertTrue(identityRegistry.hasIdentity(user1));
        assertFalse(identityRegistry.hasIdentity(user2));
    }
    
    function test_MultipleUsersRegistration() public {
        uint256 initialCount = identityRegistry.identityCount();
        
        // Create identities for multiple users
        address[] memory users = new address[](5);
        address[] memory identities = new address[](5);
        
        for (uint256 i = 0; i < 5; i++) {
            users[i] = makeAddr(string(abi.encodePacked("user", i)));
            vm.prank(users[i]);
            identities[i] = identityFactory.deployIdentity();
        }
        
        // Verify all registrations
        for (uint256 i = 0; i < 5; i++) {
            assertEq(identityRegistry.getIdentity(users[i]), identities[i]);
            assertTrue(identityRegistry.hasIdentity(users[i]));
        }
        
        assertEq(identityRegistry.identityCount(), initialCount + 5);
    }
}

// Mock Identity contract for testing
contract MockIdentity {
    address public owner;
    
    constructor(address _owner) {
        owner = _owner;
    }
}