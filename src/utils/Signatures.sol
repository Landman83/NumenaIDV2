// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../libraries/Errors.sol";

/**
 * @title Signatures
 * @notice Utility library for EIP-712 signature creation and verification
 * @dev Implements domain-separated signatures for the NumenaID protocol
 */
library Signatures {
    using ECDSA for bytes32;

    // EIP-712 type hashes
    bytes32 public constant CLAIM_TYPEHASH = keccak256(
        "Claim(address subject,uint256 claimType,uint256[] documentIds,bytes32 data,uint256 expiresAt,uint256 nonce,uint256 chainId)"
    );
    
    bytes32 public constant REVOKE_TYPEHASH = keccak256(
        "RevokeClaim(address subject,uint256 claimType,uint256 nonce,uint256 chainId)"
    );
    
    bytes32 public constant IDENTITY_CLAIM_TYPEHASH = keccak256(
        "IdentityClaim(address claimSubject,uint256 claimType,bytes32 claimData,uint256 expiresAt,uint256 issuedAt,uint256 nonce)"
    );

    /**
     * @dev Computes the domain separator for EIP-712
     * @param name The protocol name
     * @param version The protocol version
     * @return The domain separator
     */
    function computeDomainSeparator(
        string memory name,
        string memory version
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @dev Creates the digest for a claim
     * @param subject The identity contract address
     * @param claimType The type of claim
     * @param documentIds The associated document IDs
     * @param data The claim data
     * @param expiresAt The expiration timestamp
     * @param nonce The nonce for replay protection
     * @param domainSeparator The EIP-712 domain separator
     * @return The message digest
     */
    function createClaimDigest(
        address subject,
        uint256 claimType,
        uint256[] memory documentIds,
        bytes32 data,
        uint256 expiresAt,
        uint256 nonce,
        bytes32 domainSeparator
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                CLAIM_TYPEHASH,
                subject,
                claimType,
                keccak256(abi.encodePacked(documentIds)),
                data,
                expiresAt,
                nonce,
                block.chainid
            )
        );
        
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /**
     * @dev Creates the digest for a claim revocation
     * @param subject The identity contract address
     * @param claimType The type of claim to revoke
     * @param nonce The nonce for replay protection
     * @param domainSeparator The EIP-712 domain separator
     * @return The message digest
     */
    function createRevokeDigest(
        address subject,
        uint256 claimType,
        uint256 nonce,
        bytes32 domainSeparator
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                REVOKE_TYPEHASH,
                subject,
                claimType,
                nonce,
                block.chainid
            )
        );
        
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /**
     * @dev Creates the digest for an identity claim (used in Verifier)
     * @param claimSubject The subject of the claim
     * @param claimType The type of claim
     * @param claimData The claim data
     * @param expiresAt The expiration timestamp
     * @param issuedAt The issuance timestamp
     * @param nonce The nonce for replay protection
     * @param domainSeparator The EIP-712 domain separator
     * @return The message digest
     */
    function createIdentityClaimDigest(
        address claimSubject,
        uint256 claimType,
        bytes32 claimData,
        uint256 expiresAt,
        uint256 issuedAt,
        uint256 nonce,
        bytes32 domainSeparator
    ) internal pure returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                IDENTITY_CLAIM_TYPEHASH,
                claimSubject,
                claimType,
                claimData,
                expiresAt,
                issuedAt,
                nonce
            )
        );
        
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /**
     * @dev Recovers the signer from a signature
     * @param digest The message digest
     * @param signature The signature bytes
     * @return The recovered address
     */
    function recoverSigner(
        bytes32 digest,
        bytes memory signature
    ) internal pure returns (address) {
        return digest.recover(signature);
    }

    /**
     * @dev Verifies a signature against an expected signer
     * @param digest The message digest
     * @param signature The signature bytes
     * @param expectedSigner The expected signer address
     * @return True if the signature is valid
     */
    function verifySignature(
        bytes32 digest,
        bytes memory signature,
        address expectedSigner
    ) internal pure returns (bool) {
        address recoveredSigner = recoverSigner(digest, signature);
        return recoveredSigner == expectedSigner;
    }
}