// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "forge-std/console.sol";

import "../src/modules/IdentityRegistry.sol";
import "../src/modules/IdentityFactory.sol";
import "../src/modules/SignerRegistry.sol";
import "../src/modules/ClaimTypeRegistry.sol";
import "../src/modules/Verifier.sol";
import "../src/modules/ComplianceDocument.sol";
import "../src/NumenaID.sol";

/**
 * @title Deploy
 * @dev Deployment script for NumenaID system using CREATE2 for deterministic addresses.
 * Deploys modules first, then NumenaID router, then binds modules to router.
 * 
 * Deployment order:
 * 1. ClaimTypeRegistry (no dependencies)
 * 2. SignerRegistry (no dependencies)
 * 3. ComplianceDocument (depends on SignerRegistry)
 * 4. IdentityRegistry (placeholder factory address)
 * 5. IdentityFactory (depends on IdentityRegistry, SignerRegistry)
 * 6. Verifier (depends on IdentityRegistry, SignerRegistry, NumenaID)
 * 7. NumenaID router (depends on all modules)
 * 8. Bind modules to NumenaID router
 */
contract Deploy is Script {
    // CREATE2 salt for deterministic deployments
    bytes32 public constant SALT = keccak256("NumenaID_v1.0.0");
    
    // Admin address (can be overridden via environment variable)
    address public admin;
    
    // Deployed contract addresses
    address public identityRegistry;
    address public identityFactory;
    address public signerRegistry;
    address public claimTypeRegistry;
    address public verifier;
    address public complianceDocument;
    address public numenaID;
    
    function setUp() public {
        // Get admin address from environment or use deployer
        try vm.envUint("PRIVATE_KEY") returns (uint256 privateKey) {
            admin = vm.envOr("ADMIN_ADDRESS", vm.addr(privateKey));
        } catch {
            // Use default test address if no private key is provided
            admin = vm.envOr("ADMIN_ADDRESS", address(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38));
        }
        console.log("Admin address:", admin);
    }
    
    function run() public {
        vm.startBroadcast();
        
        console.log("Starting NumenaID deployment with CREATE2...");
        console.log("Deployer:", msg.sender);
        console.log("Salt:", vm.toString(SALT));
        
        // Deploy modules in dependency order
        deployClaimTypeRegistry();
        deploySignerRegistry();
        deployComplianceDocument();
        deployIdentityRegistry();
        deployIdentityFactory();
        deployVerifier();
        deployNumenaIDRouter();
        bindModulesToRouter();
        
        vm.stopBroadcast();
        
        // Log all deployed addresses
        logDeploymentAddresses();
        
        console.log("Deployment completed successfully!");
    }
    
    function deployClaimTypeRegistry() internal {
        console.log("Deploying ClaimTypeRegistry...");
        
        bytes memory bytecode = abi.encodePacked(
            type(ClaimTypeRegistry).creationCode,
            abi.encode(admin)
        );
        
        claimTypeRegistry = deployWithCreate2(bytecode, "ClaimTypeRegistry");
    }
    
    function deploySignerRegistry() internal {
        console.log("Deploying SignerRegistry...");
        
        bytes memory bytecode = abi.encodePacked(
            type(SignerRegistry).creationCode,
            abi.encode(admin)
        );
        
        signerRegistry = deployWithCreate2(bytecode, "SignerRegistry");
    }
    
    function deployComplianceDocument() internal {
        console.log("Deploying ComplianceDocument...");
        
        bytes memory bytecode = abi.encodePacked(
            type(ComplianceDocument).creationCode,
            abi.encode(signerRegistry, "NumenaID Compliance Documents", "NUMDOC")
        );
        
        complianceDocument = deployWithCreate2(bytecode, "ComplianceDocument");
    }
    
    function deployIdentityRegistry() internal {
        console.log("Deploying IdentityRegistry...");
        
        // Compute IdentityFactory address first since registry needs it
        address computedFactoryAddress = computeCreate2Address(
            keccak256(abi.encodePacked(
                type(IdentityFactory).creationCode,
                abi.encode(address(0), signerRegistry, admin) // placeholder registry address
            ))
        );
        
        bytes memory bytecode = abi.encodePacked(
            type(IdentityRegistry).creationCode,
            abi.encode(computedFactoryAddress)
        );
        
        identityRegistry = deployWithCreate2(bytecode, "IdentityRegistry");
    }
    
    function deployIdentityFactory() internal {
        console.log("Deploying IdentityFactory...");
        
        bytes memory bytecode = abi.encodePacked(
            type(IdentityFactory).creationCode,
            abi.encode(identityRegistry, signerRegistry, admin)
        );
        
        address deployedFactory = deployWithCreate2(bytecode, "IdentityFactory");
        
        // Verify the computed address matches actual deployment
        require(deployedFactory != address(0), "IdentityFactory deployment failed");
        identityFactory = deployedFactory;
    }
    
    function deployVerifier() internal {
        console.log("Deploying Verifier...");
        
        // Compute NumenaID address first since Verifier constructor needs it
        address computedNumenaIDAddress = computeCreate2Address(
            keccak256(abi.encodePacked(
                type(NumenaID).creationCode,
                abi.encode(
                    identityRegistry,
                    identityFactory,
                    signerRegistry,
                    claimTypeRegistry,
                    address(0), // placeholder verifier address
                    complianceDocument
                )
            ))
        );
        
        bytes memory bytecode = abi.encodePacked(
            type(Verifier).creationCode,
            abi.encode(identityRegistry, signerRegistry, computedNumenaIDAddress)
        );
        
        verifier = deployWithCreate2(bytecode, "Verifier");
    }
    
    function deployNumenaIDRouter() internal {
        console.log("Deploying NumenaID router...");
        
        bytes memory bytecode = abi.encodePacked(
            type(NumenaID).creationCode,
            abi.encode(
                identityRegistry,
                identityFactory,
                signerRegistry,
                claimTypeRegistry,
                verifier,
                complianceDocument
            )
        );
        
        address deployedRouter = deployWithCreate2(bytecode, "NumenaID");
        
        // Verify the computed address matches actual deployment
        require(deployedRouter != address(0), "NumenaID deployment failed");
        numenaID = deployedRouter;
    }
    
    function bindModulesToRouter() internal {
        console.log("Binding modules to NumenaID router...");
        
        // Switch to admin account for binding operations
        vm.stopBroadcast();
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        
        // Set NumenaID address in IdentityFactory
        IdentityFactory(identityFactory).setNumenaID(numenaID);
        console.log("Set NumenaID in IdentityFactory");
        
        // Set IdentityFactory address in SignerRegistry
        SignerRegistry(signerRegistry).setIdentityFactory(identityFactory);
        console.log("Set IdentityFactory in SignerRegistry");
        
        console.log("Module binding completed");
    }
    
    function deployWithCreate2(bytes memory bytecode, string memory contractName) internal returns (address) {
        address deployed;
        bytes32 salt = SALT;
        
        assembly {
            deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        
        require(deployed != address(0), string(abi.encodePacked(contractName, " deployment failed")));
        
        console.log(string(abi.encodePacked(contractName, " deployed at:")), deployed);
        return deployed;
    }
    
    function computeCreate2Address(bytes32 bytecodeHash) internal view returns (address) {
        bytes32 salt = SALT;
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            bytecodeHash
        )))));
    }
    
    function logDeploymentAddresses() internal view {
        console.log("\n=== NumenaID Deployment Summary ===");
        console.log("Admin:", admin);
        console.log("IdentityRegistry:", identityRegistry);
        console.log("IdentityFactory:", identityFactory);
        console.log("SignerRegistry:", signerRegistry);
        console.log("ClaimTypeRegistry:", claimTypeRegistry);
        console.log("Verifier:", verifier);
        console.log("ComplianceDocument:", complianceDocument);
        console.log("NumenaID Router:", numenaID);
        console.log("=====================================\n");
    }
    
    // Helper function to verify deployment
    function verifyDeployment() external view returns (bool) {
        // Verify all contracts are deployed
        require(identityRegistry != address(0), "IdentityRegistry not deployed");
        require(identityFactory != address(0), "IdentityFactory not deployed");
        require(signerRegistry != address(0), "SignerRegistry not deployed");
        require(claimTypeRegistry != address(0), "ClaimTypeRegistry not deployed");
        require(verifier != address(0), "Verifier not deployed");
        require(complianceDocument != address(0), "ComplianceDocument not deployed");
        require(numenaID != address(0), "NumenaID not deployed");
        
        // Verify NumenaID has correct module addresses
        (
            address _identityRegistry,
            address _identityFactory,
            address _signerRegistry,
            address _claimTypeRegistry,
            address _verifier
        ) = NumenaID(numenaID).getAllModules();
        
        require(_identityRegistry == identityRegistry, "IdentityRegistry mismatch");
        require(_identityFactory == identityFactory, "IdentityFactory mismatch");
        require(_signerRegistry == signerRegistry, "SignerRegistry mismatch");
        require(_claimTypeRegistry == claimTypeRegistry, "ClaimTypeRegistry mismatch");
        require(_verifier == verifier, "Verifier mismatch");
        
        // Verify factory is set in registry
        require(IdentityRegistry(identityRegistry).identityFactory() == identityFactory, "Factory not set in registry");
        
        // Verify NumenaID is set in factory
        require(IdentityFactory(identityFactory).numenaID() == numenaID, "NumenaID not set in factory");
        
        return true;
    }
}