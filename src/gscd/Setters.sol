// contracts/Setters.sol
// SPDX-License-Identifier: Apache 2

pragma solidity ^0.8.0;

import "./State.sol";

contract Setters is State {
    function updateGuardianSetIndex(uint32 newIndex) internal {
        _state.guardianSetIndex = newIndex;
    }

    function expireGuardianSet(uint32 index) internal {
        _state.guardianSets[index].expirationTime = uint32(block.timestamp) + 86400;
    }

    function storeGuardianSet(IWormhole.GuardianSet memory set, uint32 index) internal {
        uint setLength = set.keys.length;
        for (uint i = 0; i < setLength;) {
            require(set.keys[i] != address(0), "Invalid key");
            unchecked { ++i; }
        }
        _state.guardianSets[index] = set;
    }

    function setInitialized(address implementatiom) internal {
        _state.initializedImplementations[implementatiom] = true;
    }

    function setGovernanceActionConsumed(bytes32 hash) internal {
        _state.consumedGovernanceActions[hash] = true;
    }

    function setChainId(uint16 chainId) internal {
        _state.provider.chainId = chainId;
    }

    function setGovernanceChainId(uint16 chainId) internal {
        _state.provider.governanceChainId = chainId;
    }

    function setGovernanceContract(bytes32 governanceContract) internal {
        _state.provider.governanceContract = governanceContract;
    }

    function setMessageFee(uint256 newFee) internal {
        _state.messageFee = newFee;
    }

    function setNextSequence(address emitter, uint64 sequence) internal {
        _state.sequences[emitter] = sequence;
    }

    function setEvmChainId(uint256 evmChainId) internal {
        require(evmChainId == block.chainid, "invalid evmChainId");
        _state.evmChainId = evmChainId;
    }

    function setGuardianSetHash(uint32 index) public {
        // Fetch the guardian set at the specified index. 
        IWormhole.GuardianSet memory guardianSet = _state.guardianSets[index];
        
        uint256 guardianCount = guardianSet.keys.length;
        
        // Only allow setting the hash for a valid guardian set index
        // Governance guards against updating to an empty guardian set
        require(guardianCount > 0, "non-existent guardian set");

        bytes memory encodedGuardianSet;
        for (uint256 i = 0; i < guardianCount;) {
            encodedGuardianSet = abi.encodePacked(encodedGuardianSet, guardianSet.keys[i]);
            unchecked { i += 1; }
        }

        // Store the hash. 
        _state.guardianSetHashes[index] = keccak256(
            abi.encodePacked(encodedGuardianSet, guardianSet.expirationTime)
        );
    }
}