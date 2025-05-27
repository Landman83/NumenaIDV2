// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title ISigner
 * @dev Interface that signers can implement to create and manage claims.
 * Signers must be registered in SignerRegistry to create valid claims.
 * This interface is optional - signers can be EOAs or contracts.
 */
interface ISigner {
    // Events
    event ClaimSigned(address indexed identity, uint256 indexed claimType, address docRef);
    event ClaimRevoked(address indexed identity, uint256 indexed claimType);
    
    /**
     * @dev Signs and adds a claim to an identity contract
     * @param identity The identity contract to add claim to
     * @param claimType The type of claim to create
     * @param docRef Reference document NFT address
     * @param expiresAt When the claim should expire
     * @param data The encoded claim data
     * @notice Caller must be registered in SignerRegistry with isValidSigner=true
     */
    function signClaim(
        address identity,
        uint256 claimType,
        address docRef,
        uint256 expiresAt,
        bytes calldata data
    ) external;
    
    /**
     * @dev Revokes a previously signed claim
     * @param identity The identity contract containing the claim
     * @param claimType The type of claim to revoke
     * @notice Caller must be registered in SignerRegistry with isValidSigner=true
     * @notice Can only revoke claims that caller originally signed
     */
    function revokeClaim(
        address identity,
        uint256 claimType
    ) external;
}