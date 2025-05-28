// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./NumenaTestBase.sol";
import "../src/interfaces/IClaimTypeRegistry.sol";
import "../src/libraries/Errors.sol";
import "../src/libraries/Events.sol";
import "../src/libraries/Roles.sol";

contract ClaimTypeRegistryTest is NumenaTestBase {
    function setUp() public override {
        super.setUp();
    }
    
    function test_Constructor() public view {
        assertTrue(claimTypeRegistry.hasRole(Roles.ADMIN_ROLE, admin));
        
        // Check predefined claim types
        (string memory title, uint256[] memory docs, string memory dataType, bool active) = 
            claimTypeRegistry.getClaimType(claimTypeRegistry.KYC_AML());
        assertEq(title, "KYC/AML Verified");
        assertEq(docs.length, 2);
        assertEq(docs[0], claimTypeRegistry.PASSPORT());
        assertEq(docs[1], claimTypeRegistry.UTILITY_BILL());
        assertEq(dataType, "bool");
        assertTrue(active);
        
        // Check accredited investor
        (title, docs, dataType, active) = claimTypeRegistry.getClaimType(claimTypeRegistry.ACCREDITED_INVESTOR());
        assertEq(title, "Accredited Investor");
        assertEq(docs.length, 2);
        assertEq(dataType, "bool");
        assertTrue(active);
        
        // Check institutional investor
        (title, docs, dataType, active) = claimTypeRegistry.getClaimType(claimTypeRegistry.INSTITUTIONAL_INVESTOR());
        assertEq(title, "Institutional Investor");
        assertEq(docs.length, 2);
        assertEq(dataType, "bool");
        assertTrue(active);
        
        // Check insider status
        (title, docs, dataType, active) = claimTypeRegistry.getClaimType(claimTypeRegistry.INSIDER_STATUS());
        assertEq(title, "Insider Status");
        assertEq(docs.length, 1);
        assertEq(dataType, "bytes");
        assertTrue(active);
    }
    
    function test_AddClaimType_Success() public {
        uint256 newClaimId = 100;
        uint256[] memory requiredDocs = new uint256[](2);
        requiredDocs[0] = claimTypeRegistry.PASSPORT();
        requiredDocs[1] = claimTypeRegistry.BANK_STATEMENT();
        
        vm.expectEmit(true, true, true, true);
        emit Events.ClaimTypeAdded(newClaimId, "New Claim Type", requiredDocs);
        
        vm.prank(admin);
        claimTypeRegistry.addClaimType(newClaimId, "New Claim Type", requiredDocs, "address");
        
        (string memory title, uint256[] memory docs, string memory dataType, bool active) = 
            claimTypeRegistry.getClaimType(newClaimId);
        assertEq(title, "New Claim Type");
        assertEq(docs.length, 2);
        assertEq(docs[0], requiredDocs[0]);
        assertEq(docs[1], requiredDocs[1]);
        assertEq(dataType, "address");
        assertTrue(active);
        
        assertTrue(claimTypeRegistry.isValidClaimType(newClaimId));
    }
    
    function test_AddClaimType_RevertNotAdmin() public {
        uint256[] memory requiredDocs = new uint256[](1);
        requiredDocs[0] = 1;
        
        vm.expectRevert();
        vm.prank(unauthorized);
        claimTypeRegistry.addClaimType(100, "New Type", requiredDocs, "bool");
    }
    
    function test_AddClaimType_RevertAlreadyExists() public {
        uint256[] memory requiredDocs = new uint256[](1);
        requiredDocs[0] = 1;
        
        uint256 existingId = claimTypeRegistry.KYC_AML();
        
        vm.prank(admin);
        vm.expectRevert(Errors.InvalidClaimType.selector);
        claimTypeRegistry.addClaimType(existingId, "Duplicate", requiredDocs, "bool");
    }
    
    function test_AddClaimType_RevertEmptyTitle() public {
        uint256[] memory requiredDocs = new uint256[](1);
        requiredDocs[0] = 1;
        
        vm.expectRevert(Errors.InvalidData.selector);
        vm.prank(admin);
        claimTypeRegistry.addClaimType(100, "", requiredDocs, "bool");
    }
    
    function test_AddClaimType_RevertEmptyDataType() public {
        uint256[] memory requiredDocs = new uint256[](1);
        requiredDocs[0] = 1;
        
        vm.expectRevert(Errors.InvalidData.selector);
        vm.prank(admin);
        claimTypeRegistry.addClaimType(100, "New Type", requiredDocs, "");
    }
    
    function test_RemoveClaimType_Success() public {
        uint256 claimId = claimTypeRegistry.KYC_AML();
        
        vm.expectEmit(true, true, true, true);
        emit Events.ClaimTypeRemoved(claimId);
        
        vm.prank(admin);
        claimTypeRegistry.removeClaimType(claimId);
        
        assertFalse(claimTypeRegistry.isValidClaimType(claimId));
        
        // Should not be in getAllClaimTypes
        uint256[] memory allTypes = claimTypeRegistry.getAllClaimTypes();
        for (uint256 i = 0; i < allTypes.length; i++) {
            assertTrue(allTypes[i] != claimId);
        }
    }
    
    function test_RemoveClaimType_RevertNotAdmin() public {
        uint256 claimId = claimTypeRegistry.KYC_AML();
        
        vm.prank(unauthorized);
        vm.expectRevert();
        claimTypeRegistry.removeClaimType(claimId);
    }
    
    function test_RemoveClaimType_RevertNotFound() public {
        vm.expectRevert(Errors.InvalidClaimType.selector);
        vm.prank(admin);
        claimTypeRegistry.removeClaimType(999); // Non-existent
    }
    
    function test_UpdateClaimType_Success() public {
        uint256 claimId = claimTypeRegistry.KYC_AML();
        uint256[] memory newDocs = new uint256[](3);
        newDocs[0] = claimTypeRegistry.PASSPORT();
        newDocs[1] = claimTypeRegistry.DRIVERS_LICENSE();
        newDocs[2] = claimTypeRegistry.UTILITY_BILL();
        
        vm.expectEmit(true, true, true, true);
        emit Events.ClaimTypeUpdated(claimId, "Updated KYC", newDocs);
        
        vm.prank(admin);
        claimTypeRegistry.updateClaimType(claimId, "Updated KYC", newDocs, "uint256");
        
        (string memory title, uint256[] memory docs, string memory dataType, bool active) = 
            claimTypeRegistry.getClaimType(claimId);
        assertEq(title, "Updated KYC");
        assertEq(docs.length, 3);
        assertEq(dataType, "uint256");
        assertTrue(active);
    }
    
    function test_UpdateClaimType_RevertNotAdmin() public {
        uint256[] memory newDocs = new uint256[](1);
        newDocs[0] = 1;
        uint256 claimId = claimTypeRegistry.KYC_AML();
        
        vm.prank(unauthorized);
        vm.expectRevert();
        claimTypeRegistry.updateClaimType(claimId, "Updated", newDocs, "bool");
    }
    
    function test_UpdateClaimType_RevertNotFound() public {
        uint256[] memory newDocs = new uint256[](1);
        newDocs[0] = 1;
        
        vm.expectRevert(Errors.InvalidClaimType.selector);
        vm.prank(admin);
        claimTypeRegistry.updateClaimType(999, "Updated", newDocs, "bool");
    }
    
    function test_UpdateClaimType_RevertEmptyTitle() public {
        uint256[] memory newDocs = new uint256[](1);
        newDocs[0] = 1;
        uint256 claimId = claimTypeRegistry.KYC_AML();
        
        vm.prank(admin);
        vm.expectRevert(Errors.InvalidData.selector);
        claimTypeRegistry.updateClaimType(claimId, "", newDocs, "bool");
    }
    
    function test_UpdateClaimType_RevertEmptyDataType() public {
        uint256[] memory newDocs = new uint256[](1);
        newDocs[0] = 1;
        uint256 claimId = claimTypeRegistry.KYC_AML();
        
        vm.prank(admin);
        vm.expectRevert(Errors.InvalidData.selector);
        claimTypeRegistry.updateClaimType(claimId, "Updated", newDocs, "");
    }
    
    function test_GetAllClaimTypes() public {
        uint256[] memory allTypes = claimTypeRegistry.getAllClaimTypes();
        assertEq(allTypes.length, 4); // 4 predefined types
        
        // Add a new type
        uint256[] memory docs = new uint256[](1);
        docs[0] = 1;
        vm.prank(admin);
        claimTypeRegistry.addClaimType(100, "New Type", docs, "bool");
        
        allTypes = claimTypeRegistry.getAllClaimTypes();
        assertEq(allTypes.length, 5);
        
        // Remove a type
        uint256 claimToRemove = claimTypeRegistry.KYC_AML();
        vm.prank(admin);
        claimTypeRegistry.removeClaimType(claimToRemove);
        
        allTypes = claimTypeRegistry.getAllClaimTypes();
        assertEq(allTypes.length, 4);
    }
    
    function test_GetRequiredDocuments() public view {
        uint256[] memory docs = claimTypeRegistry.getRequiredDocuments(claimTypeRegistry.KYC_AML());
        assertEq(docs.length, 2);
        assertEq(docs[0], claimTypeRegistry.PASSPORT());
        assertEq(docs[1], claimTypeRegistry.UTILITY_BILL());
    }
    
    function test_GetRequiredDocuments_RevertInvalidType() public {
        vm.expectRevert(Errors.InvalidClaimType.selector);
        claimTypeRegistry.getRequiredDocuments(999);
    }
    
    function test_IsValidClaimType() public view {
        assertTrue(claimTypeRegistry.isValidClaimType(claimTypeRegistry.KYC_AML()));
        assertTrue(claimTypeRegistry.isValidClaimType(claimTypeRegistry.ACCREDITED_INVESTOR()));
        assertFalse(claimTypeRegistry.isValidClaimType(999));
    }
    
    function test_DocumentTypeConstants() public view {
        // Verify all document type constants
        assertEq(claimTypeRegistry.PASSPORT(), 1);
        assertEq(claimTypeRegistry.DRIVERS_LICENSE(), 2);
        assertEq(claimTypeRegistry.UTILITY_BILL(), 3);
        assertEq(claimTypeRegistry.BANK_STATEMENT(), 4);
        assertEq(claimTypeRegistry.INCOME_STATEMENT(), 5);
        assertEq(claimTypeRegistry.TAX_RETURN(), 6);
        assertEq(claimTypeRegistry.CORPORATE_DOCS(), 7);
        assertEq(claimTypeRegistry.AUTHORIZATION_LETTER(), 8);
        assertEq(claimTypeRegistry.NET_WORTH_STATEMENT(), 9);
        assertEq(claimTypeRegistry.INVESTMENT_PORTFOLIO(), 10);
    }
}