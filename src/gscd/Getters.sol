// contracts/Getters.sol
// SPDX-License-Identifier: Apache 2

pragma solidity ^0.8.0;

import "./State.sol";

contract Getters is State {
    function getGuardianSet(uint32 index) public view returns (IWormhole.GuardianSet memory) {
        return _state.guardianSets[index];
    }

    function getCurrentGuardianSetIndex() public view returns (uint32) {
        return _state.guardianSetIndex;
    }

    function getGuardianSetExpiry() public view returns (uint32) {
        return _state.guardianSetExpiry;
    }

    function governanceActionIsConsumed(bytes32 hash) public view returns (bool) {
        return _state.consumedGovernanceActions[hash];
    }

    function isInitialized(address impl) public view returns (bool) {
        return _state.initializedImplementations[impl];
    }

    function chainId() public view returns (uint16) {
        return _state.provider.chainId;
    }

    function evmChainId() public view returns (uint256) {
        return _state.evmChainId;
    }

    function isFork() public view returns (bool) {
        return evmChainId() != block.chainid;
    }

    function governanceChainId() public view returns (uint16){
        return _state.provider.governanceChainId;
    }

    function governanceContract() public view returns (bytes32){
        return _state.provider.governanceContract;
    }

    function messageFee() public view returns (uint256) {
        return _state.messageFee;
    }

    function nextSequence(address emitter) public view returns (uint64) {
        return _state.sequences[emitter];
    }

    function getGuardianSetHash(uint32 index) public view returns (bytes32) {
        return _state.guardianSetHashes[index];
    }

    function getEncodedGuardianSet(uint32 index) public view returns (bytes memory encodedGuardianSet) {
        IWormhole.GuardianSet memory guardianSet = getGuardianSet(index);

        // Encode the guardian set.
        uint256 guardianCount = guardianSet.keys.length;
        for (uint256 i = 0; i < guardianCount; ++i)
            encodedGuardianSet = abi.encodePacked(encodedGuardianSet, guardianSet.keys[i]);

        encodedGuardianSet = abi.encodePacked(encodedGuardianSet, guardianSet.expirationTime);
    }
}