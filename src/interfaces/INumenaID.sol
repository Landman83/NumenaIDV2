// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title INumenaID
 * @dev Interface for the main NumenaID router contract
 */
interface INumenaID {
    function identityRegistry() external view returns (address);
    function identityFactory() external view returns (address);
    function signerRegistry() external view returns (address);
    function claimTypeRegistry() external view returns (address);
    function verifier() external view returns (address);
    function complianceDocument() external view returns (address);
}