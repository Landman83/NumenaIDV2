// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/NumenaID.sol";
import "../src/modules/Identity.sol";
import "../src/modules/IdentityRegistry.sol";
import "../src/modules/IdentityFactory.sol";
import "../src/modules/SignerRegistry.sol";
import "../src/modules/ClaimTypeRegistry.sol";
import "../src/modules/Verifier.sol";
import "../src/modules/ComplianceDocument.sol";

abstract contract NumenaTestBase is Test {
    // Main contracts
    NumenaID public numenaID;
    IdentityRegistry public identityRegistry;
    IdentityFactory public identityFactory;
    SignerRegistry public signerRegistry;
    ClaimTypeRegistry public claimTypeRegistry;
    Verifier public verifier;
    ComplianceDocument public complianceDocument;
    
    // Test accounts
    address public admin = makeAddr("admin");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public signer1 = makeAddr("signer1");
    address public signer2 = makeAddr("signer2");
    address public unauthorized = makeAddr("unauthorized");
    
    // Test private keys for signature generation
    uint256 public signer1PrivateKey = 0x1234;
    uint256 public signer2PrivateKey = 0x5678;
    
    // Common test values
    uint256 public constant TEST_CLAIM_TYPE = 1; // KYC_AML
    uint256 public constant TEST_DOCUMENT_TYPE = 1; // PASSPORT
    
    function setUp() public virtual {
        // Set correct addresses for signers based on private keys first
        signer1 = vm.addr(signer1PrivateKey);
        signer2 = vm.addr(signer2PrivateKey);
        
        vm.startPrank(admin);
        
        // Deploy modules in correct order to handle dependencies
        
        // 1. Deploy SignerRegistry first (no dependencies)
        signerRegistry = new SignerRegistry(admin);
        
        // 2. Deploy contracts with circular dependency
        // The IdentityRegistry needs to know the factory address (immutable)
        // The IdentityFactory needs to know the registry address (immutable)
        // Solution: Deploy in specific order with nonce tracking
        
        // Get current nonce after SignerRegistry deployment
        uint64 currentNonce = vm.getNonce(admin);
        
        // Next deployment will be IdentityRegistry (nonce)
        // After that will be IdentityFactory (nonce + 1)
        address predictedFactoryAddress = vm.computeCreateAddress(admin, currentNonce + 1);
        
        // Deploy registry with predicted factory address
        identityRegistry = new IdentityRegistry(predictedFactoryAddress);
        
        // Now deploy factory with the actual registry address
        identityFactory = new IdentityFactory(
            address(identityRegistry),
            address(signerRegistry),
            admin
        );
        
        // 3. Deploy ClaimTypeRegistry
        claimTypeRegistry = new ClaimTypeRegistry(admin);
        
        // 4. Deploy ComplianceDocument
        complianceDocument = new ComplianceDocument(
            address(signerRegistry),
            "NumenaID Documents",
            "NDOC"
        );
        
        // 5. Deploy Verifier first with placeholder NumenaID
        verifier = new Verifier(
            address(identityRegistry),
            address(signerRegistry),
            address(1) // Placeholder NumenaID - will be updated via setter if needed
        );
        
        // 6. Deploy NumenaID router with all addresses
        numenaID = new NumenaID(
            address(identityRegistry),
            address(identityFactory),
            address(signerRegistry),
            address(claimTypeRegistry),
            address(verifier),
            address(complianceDocument)
        );
        
        // 9. Set NumenaID address in IdentityFactory
        identityFactory.setNumenaID(address(numenaID));
        
        // 10. Set IdentityFactory address in SignerRegistry
        signerRegistry.setIdentityFactory(address(identityFactory));
        
        vm.stopPrank();
        
        vm.startPrank(admin);
        
        // Setup test signers with correct addresses
        uint256[] memory allowedClaimTypes = new uint256[](1);
        allowedClaimTypes[0] = TEST_CLAIM_TYPE;
        
        signerRegistry.addSigner(signer1, allowedClaimTypes, "Test Signer 1");
        signerRegistry.addSigner(signer2, allowedClaimTypes, "Test Signer 2");
        
        vm.stopPrank();
        
        // Fund test accounts
        vm.deal(signer1, 1 ether);
        vm.deal(signer2, 1 ether);
        vm.deal(user1, 1 ether);
        vm.deal(user2, 1 ether);
    }
    
    // Helper function to create an identity for a user
    function createIdentity(address user) internal returns (address) {
        vm.prank(user);
        return identityFactory.deployIdentity();
    }
    
    // Helper function to create a test document
    function createTestDocument(address owner, uint256 documentType) internal returns (uint256) {
        vm.prank(owner);
        return complianceDocument.mintDocument(
            "QmTestHash123456789",
            "/ipfs/QmTestHash123456789",
            documentType,
            1024 // 1KB file size
        );
    }
    
    // Helper function to create a valid claim signature
    function createClaimSignature(
        address identityContract,
        uint256 claimType,
        uint256[] memory documentIds,
        bytes memory data,
        uint256 expiresAt,
        uint256 signerPrivateKey
    ) internal view returns (bytes memory) {
        // Get current nonce for signer
        address signer = vm.addr(signerPrivateKey);
        uint256 nonce = Identity(identityContract).nonces(signer);
        
        // Create domain separator (matching Identity contract)
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("NumenaID")),
                keccak256(bytes("1.0.0")),
                block.chainid,
                identityContract // Use the actual identity contract address
            )
        );
        
        // Create claim digest using the correct typehash from Signatures library
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Claim(address subject,uint256 claimType,uint256[] documentIds,bytes32 data,uint256 expiresAt,uint256 nonce,uint256 chainId)"),
                identityContract,
                claimType,
                keccak256(abi.encodePacked(documentIds)),
                keccak256(data),
                expiresAt,
                nonce,
                block.chainid
            )
        );
        
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );
        
        // Sign the digest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}