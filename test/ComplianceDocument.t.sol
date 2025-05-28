// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./NumenaTestBase.sol";
import "../src/interfaces/IComplianceDocument.sol";
import "../src/libraries/Errors.sol";

contract ComplianceDocumentTest is NumenaTestBase {
    uint256 public testTokenId;
    string public testFileHash = "QmTestHash123456789";
    string public testLocalPath = "/ipfs/QmTestHash123456789";
    uint256 public testDocumentType = 1; // PASSPORT
    uint256 public testFileSize = 1024; // 1KB
    
    function setUp() public override {
        super.setUp();
        
        // Mint a test document
        vm.prank(user1);
        testTokenId = complianceDocument.mintDocument(
            testFileHash,
            testLocalPath,
            testDocumentType,
            testFileSize
        );
    }
    
    function test_Constructor() public view {
        assertEq(complianceDocument.name(), "NumenaID Documents");
        assertEq(complianceDocument.symbol(), "NDOC");
        assertEq(address(complianceDocument.signerRegistry()), address(signerRegistry));
        assertTrue(complianceDocument.hasRole(complianceDocument.ADMIN_ROLE(), admin));
    }
    
    function test_MintDocument_Success() public {
        string memory newHash = "QmNewHash987654321";
        string memory newPath = "/ipfs/QmNewHash987654321";
        uint256 newType = 2; // DRIVERS_LICENSE
        uint256 newSize = 2048;
        
        vm.expectEmit(true, true, true, true);
        emit ComplianceDocument.DocumentMinted(1, user2, newType, newHash); // tokenId will be 1
        
        vm.prank(user2);
        uint256 tokenId = complianceDocument.mintDocument(newHash, newPath, newType, newSize);
        
        assertEq(complianceDocument.ownerOf(tokenId), user2);
        assertEq(complianceDocument.totalDocuments(), 2); // Including the one from setUp
        
        // View as the owner
        vm.prank(user2);
        IComplianceDocument.Document memory doc = complianceDocument.viewDocument(tokenId);
        assertEq(doc.fileHash, newHash);
        assertEq(doc.localPath, newPath);
        assertEq(doc.documentType, newType);
        assertEq(doc.fileSize, newSize);
        assertEq(doc.uploadedBy, user2);
        assertEq(doc.uploadedAt, block.timestamp);
    }
    
    function test_MintDocument_RevertEmptyFileHash() public {
        vm.expectRevert(Errors.InvalidFileHash.selector);
        vm.prank(user1);
        complianceDocument.mintDocument("", testLocalPath, testDocumentType, testFileSize);
    }
    
    function test_MintDocument_RevertEmptyLocalPath() public {
        vm.expectRevert(Errors.InvalidLocalPath.selector);
        vm.prank(user1);
        complianceDocument.mintDocument(testFileHash, "", testDocumentType, testFileSize);
    }
    
    function test_MintDocument_RevertInvalidDocumentType() public {
        vm.expectRevert(Errors.InvalidDocumentType.selector);
        vm.prank(user1);
        complianceDocument.mintDocument(testFileHash, testLocalPath, 0, testFileSize);
    }
    
    function test_MintDocument_RevertInvalidFileSize() public {
        vm.expectRevert(Errors.InvalidFileSize.selector);
        vm.prank(user1);
        complianceDocument.mintDocument(testFileHash, testLocalPath, testDocumentType, 0);
    }
    
    function test_ViewDocument_Success() public {
        // View as owner
        vm.prank(user1);
        IComplianceDocument.Document memory doc = complianceDocument.viewDocument(testTokenId);
        assertEq(doc.fileHash, testFileHash);
        assertEq(doc.localPath, testLocalPath);
        assertEq(doc.documentType, testDocumentType);
        assertEq(doc.fileSize, testFileSize);
        assertEq(doc.uploadedBy, user1);
    }
    
    function test_ViewDocument_RevertDoesNotExist() public {
        vm.expectRevert(Errors.DocumentDoesNotExist.selector);
        complianceDocument.viewDocument(999);
    }
    
    function test_ViewDocument_RevertUnauthorized() public {
        vm.expectRevert(Errors.UnauthorizedDocumentAccess.selector);
        vm.prank(unauthorized);
        complianceDocument.viewDocument(testTokenId);
    }
    
    function test_GetDocument_Success() public {
        // Owner access
        vm.expectEmit(true, true, true, true);
        emit ComplianceDocument.DocumentAccessed(testTokenId, user1, complianceDocument.ACCESS_TYPE_OWNER());
        
        vm.prank(user1);
        IComplianceDocument.Document memory doc = complianceDocument.getDocument(testTokenId);
        
        assertEq(doc.fileHash, testFileHash);
        
        // Verifier access
        vm.expectEmit(true, true, true, true);
        emit ComplianceDocument.DocumentAccessed(testTokenId, signer1, complianceDocument.ACCESS_TYPE_VERIFIER());
        
        vm.prank(signer1);
        doc = complianceDocument.getDocument(testTokenId);
        assertEq(doc.fileHash, testFileHash);
    }
    
    function test_GetDocument_RevertDoesNotExist() public {
        vm.expectRevert(Errors.DocumentDoesNotExist.selector);
        vm.prank(user1);
        complianceDocument.getDocument(999);
    }
    
    function test_GetDocument_RevertUnauthorized() public {
        vm.expectRevert(Errors.UnauthorizedDocumentAccess.selector);
        vm.prank(unauthorized);
        complianceDocument.getDocument(testTokenId);
    }
    
    function test_RecordDocumentAccess_Success() public {
        vm.expectEmit(true, true, true, true);
        emit ComplianceDocument.DocumentAccessed(testTokenId, user1, complianceDocument.ACCESS_TYPE_OWNER());
        
        vm.prank(signer1); // Authorized signer can record access
        complianceDocument.recordDocumentAccess(testTokenId, user1);
    }
    
    function test_RecordDocumentAccess_RevertUnauthorizedCaller() public {
        vm.expectRevert(Errors.CallerNotAuthorizedToRecordAccess.selector);
        vm.prank(unauthorized);
        complianceDocument.recordDocumentAccess(testTokenId, user1);
    }
    
    function test_RecordDocumentAccess_RevertUnauthorizedAccessor() public {
        vm.expectRevert(Errors.AccessorNotAuthorized.selector);
        vm.prank(signer1);
        complianceDocument.recordDocumentAccess(testTokenId, unauthorized);
    }
    
    function test_GetAccessHistory_Success() public {
        // Generate some access history
        vm.prank(user1);
        complianceDocument.getDocument(testTokenId);
        
        vm.prank(signer1);
        complianceDocument.getDocument(testTokenId);
        
        // Check history (only owner can view)
        vm.prank(user1);
        IComplianceDocument.AccessRecord[] memory history = complianceDocument.getAccessHistory(testTokenId);
        
        assertEq(history.length, 3); // Initial mint + 2 accesses
        assertEq(history[0].accessor, user1); // Mint access
        assertEq(history[1].accessor, user1); // Owner access
        assertEq(history[2].accessor, signer1); // Verifier access
    }
    
    function test_GetAccessHistory_RevertNotOwner() public {
        vm.expectRevert(Errors.NotDocumentOwner.selector);
        vm.prank(user2);
        complianceDocument.getAccessHistory(testTokenId);
    }
    
    function test_CanAccessDocument() public view {
        // Owner can access
        assertTrue(complianceDocument.canAccessDocument(testTokenId, user1));
        
        // Authorized signer can access
        assertTrue(complianceDocument.canAccessDocument(testTokenId, signer1));
        
        // Unauthorized cannot access
        assertFalse(complianceDocument.canAccessDocument(testTokenId, unauthorized));
        
        // Non-existent document
        assertFalse(complianceDocument.canAccessDocument(999, user1));
    }
    
    function test_AddRemoveRegulator() public {
        address regulator = makeAddr("regulator");
        
        // Add regulator
        vm.prank(admin);
        complianceDocument.addRegulator(regulator);
        
        assertTrue(complianceDocument.hasRole(complianceDocument.REGULATOR_ROLE(), regulator));
        assertTrue(complianceDocument.canAccessDocument(testTokenId, regulator));
        
        // Remove regulator
        vm.prank(admin);
        complianceDocument.removeRegulator(regulator);
        
        assertFalse(complianceDocument.hasRole(complianceDocument.REGULATOR_ROLE(), regulator));
        assertFalse(complianceDocument.canAccessDocument(testTokenId, regulator));
    }
    
    function test_AddRegulator_RevertNotAdmin() public {
        vm.expectRevert();
        vm.prank(unauthorized);
        complianceDocument.addRegulator(makeAddr("regulator"));
    }
    
    function test_DocumentTransfer_RecordsAccess() public {
        // Transfer document
        vm.expectEmit(true, true, true, true);
        emit ComplianceDocument.DocumentAccessed(testTokenId, user2, complianceDocument.ACCESS_TYPE_OWNER());
        
        vm.prank(user1);
        complianceDocument.transferFrom(user1, user2, testTokenId);
        
        assertEq(complianceDocument.ownerOf(testTokenId), user2);
        
        // Check access was recorded
        vm.prank(user2); // New owner can check history
        IComplianceDocument.AccessRecord[] memory history = complianceDocument.getAccessHistory(testTokenId);
        
        bool foundTransferAccess = false;
        for (uint256 i = 0; i < history.length; i++) {
            if (history[i].accessor == user2 && history[i].accessType == complianceDocument.ACCESS_TYPE_OWNER()) {
                foundTransferAccess = true;
                break;
            }
        }
        assertTrue(foundTransferAccess);
    }
    
    function test_GetDocumentsByOwner() public {
        // Mint more documents
        vm.startPrank(user1);
        uint256 doc2 = complianceDocument.mintDocument("hash2", "path2", 2, 1024);
        uint256 doc3 = complianceDocument.mintDocument("hash3", "path3", 3, 1024);
        vm.stopPrank();
        
        uint256[] memory userDocs = complianceDocument.getDocumentsByOwner(user1);
        assertEq(userDocs.length, 3);
        
        // Should include all documents
        bool found0 = false;
        bool found1 = false;
        bool found2 = false;
        for (uint256 i = 0; i < userDocs.length; i++) {
            if (userDocs[i] == testTokenId) found0 = true;
            if (userDocs[i] == doc2) found1 = true;
            if (userDocs[i] == doc3) found2 = true;
        }
        assertTrue(found0 && found1 && found2);
    }
    
    function test_GetDocumentsByOwnerAndType() public {
        // Mint documents of different types
        vm.startPrank(user1);
        uint256 passport2 = complianceDocument.mintDocument("hash2", "path2", 1, 1024); // Another passport
        uint256 license = complianceDocument.mintDocument("hash3", "path3", 2, 1024); // Driver's license
        vm.stopPrank();
        
        // Get passports only
        uint256[] memory passports = complianceDocument.getDocumentsByOwnerAndType(user1, 1);
        assertEq(passports.length, 2);
        
        // Get licenses only
        uint256[] memory licenses = complianceDocument.getDocumentsByOwnerAndType(user1, 2);
        assertEq(licenses.length, 1);
        assertEq(licenses[0], license);
    }
    
    function test_GetMostRecentDocumentByOwnerAndType() public {
        // Mint documents with time gaps
        vm.warp(block.timestamp + 100);
        vm.prank(user1);
        uint256 doc2 = complianceDocument.mintDocument("hash2", "path2", testDocumentType, 1024);
        
        vm.warp(block.timestamp + 100);
        vm.prank(user1);
        uint256 doc3 = complianceDocument.mintDocument("hash3", "path3", testDocumentType, 1024);
        
        (uint256 mostRecent, bool found) = complianceDocument.getMostRecentDocumentByOwnerAndType(user1, testDocumentType);
        assertTrue(found);
        assertEq(mostRecent, doc3);
    }
    
    function test_GetMostRecentDocumentByOwnerAndType_NotFound() public {
        (uint256 tokenId, bool found) = complianceDocument.getMostRecentDocumentByOwnerAndType(user1, 999);
        assertFalse(found);
        assertEq(tokenId, 0);
    }
    
    function test_GetAccessHistoryLength() public {
        // Generate access events
        vm.prank(user1);
        complianceDocument.getDocument(testTokenId);
        
        vm.prank(signer1);
        complianceDocument.getDocument(testTokenId);
        
        uint256 length = complianceDocument.getAccessHistoryLength(testTokenId);
        assertEq(length, 3); // Mint + 2 accesses
    }
    
    function test_Pagination() public {
        // Mint many documents
        vm.startPrank(user1);
        for (uint256 i = 0; i < 10; i++) {
            complianceDocument.mintDocument(
                string(abi.encodePacked("hash", i)),
                string(abi.encodePacked("path", i)),
                1,
                1024
            );
        }
        vm.stopPrank();
        
        // Test paginated retrieval
        (uint256[] memory page1, uint256 total) = complianceDocument.getDocumentsByOwnerPaginated(user1, 0, 5);
        assertEq(page1.length, 5);
        assertEq(total, 11); // 1 from setUp + 10 new
        
        (uint256[] memory page2, uint256 total2) = complianceDocument.getDocumentsByOwnerPaginated(user1, 5, 5);
        assertEq(page2.length, 5);
        assertEq(total2, 11);
        
        (uint256[] memory page3, uint256 total3) = complianceDocument.getDocumentsByOwnerPaginated(user1, 10, 5);
        assertEq(page3.length, 1); // Only 1 remaining
        assertEq(total3, 11);
    }
}