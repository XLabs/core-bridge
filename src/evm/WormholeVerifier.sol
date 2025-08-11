// SPDX-License-Identifier: MIT

pragma solidity ^0.8.25;

import {console} from "forge-std/console.sol";

import {CoreBridgeVM, ICoreBridge, GuardianSet} from "wormhole-solidity-sdk/interfaces/ICoreBridge.sol";
import {CHAIN_ID_SOLANA} from "wormhole-solidity-sdk/constants/Chains.sol";
import {BytesParsing} from "wormhole-solidity-sdk/libraries/BytesParsing.sol";
import {VaaLib} from "wormhole-solidity-sdk/libraries/VaaLib.sol";
import {eagerAnd, eagerOr} from "wormhole-solidity-sdk/Utils.sol";

import {EIP712Encoding} from "./EIP712Encoding.sol";
import {SSTORE2} from "./ExtStore.sol";

// Verify opcodes
uint8 constant VERIFY_ANY              = 0;
uint8 constant VERIFY_MULTISIG         = 1;
uint8 constant VERIFY_SCHNORR          = 2;
uint8 constant VERIFY_MULTISIG_UNIFORM = 3;
uint8 constant VERIFY_SCHNORR_UNIFORM  = 4;
uint8 constant VERIFY_ECDSA            = 5;
uint8 constant VERIFY_ECDSA_UNIFORM    = 6;

// Verify error flags
uint256 constant MASK_VERIFY_RESULT_INVALID_VERSION         = 1 << 16;
uint256 constant MASK_VERIFY_RESULT_INVALID_EXPIRATION_TIME = 1 << 17;
uint256 constant MASK_VERIFY_RESULT_INVALID_KEY             = 1 << 18;
uint256 constant MASK_VERIFY_RESULT_INVALID_SIGNATURE       = 1 << 19;
uint256 constant MASK_VERIFY_RESULT_SIGNATURE_MISMATCH      = 1 << 20;
uint256 constant MASK_VERIFY_RESULT_INVALID_SIGNATURE_COUNT = 1 << 21;
uint256 constant MASK_VERIFY_RESULT_INVALID_SIGNER_INDEX    = 1 << 22;
uint256 constant MASK_VERIFY_RESULT_SIGNER_USED             = 1 << 23;
uint256 constant MASK_VERIFY_RESULT_INVALID_OPCODE          = 1 << 24;
uint256 constant MASK_VERIFY_RESULT_INVALID_MESSAGE_LENGTH  = 1 << 25;
uint256 constant MASK_VERIFY_RESULT_INVALID_KEY_DATA_SIZE   = 1 << 26;

// Update opcodes
uint8 constant UPDATE_SET_SHARD_ID           = 0;
uint8 constant UPDATE_APPEND_SCHNORR_KEY     = 1;
uint8 constant UPDATE_PULL_MULTISIG_KEY_DATA = 2;

// Update error flags
uint256 constant MASK_UPDATE_DEPLOYMENT_FAILED                  = 1 << 16;
uint256 constant MASK_UPDATE_RESULT_INVALID_VERSION             = 1 << 17;
uint256 constant MASK_UPDATE_RESULT_INVALID_SCHNORR_KEY_INDEX   = 1 << 18;
uint256 constant MASK_UPDATE_RESULT_NONCE_ALREADY_CONSUMED      = 1 << 19;
uint256 constant MASK_UPDATE_RESULT_INVALID_SIGNER_INDEX        = 1 << 20;
uint256 constant MASK_UPDATE_RESULT_SIGNATURE_MISMATCH          = 1 << 21;
uint256 constant MASK_UPDATE_RESULT_INVALID_MULTISIG_KEY_INDEX  = 1 << 22;
uint256 constant MASK_UPDATE_RESULT_INVALID_SIGNATURE_COUNT     = 1 << 23;
uint256 constant MASK_UPDATE_RESULT_INVALID_GOVERNANCE_CHAIN    = 1 << 24;
uint256 constant MASK_UPDATE_RESULT_INVALID_GOVERNANCE_ADDRESS  = 1 << 25;
uint256 constant MASK_UPDATE_RESULT_INVALID_MODULE              = 1 << 26;
uint256 constant MASK_UPDATE_RESULT_INVALID_ACTION              = 1 << 27;
uint256 constant MASK_UPDATE_RESULT_INVALID_KEY_INDEX           = 1 << 28;
uint256 constant MASK_UPDATE_RESULT_INVALID_SCHNORR_KEY         = 1 << 29;
uint256 constant MASK_UPDATE_RESULT_SHARD_DATA_MISMATCH         = 1 << 30;
uint256 constant MASK_UPDATE_RESULT_INVALID_OPCODE              = 1 << 31;
uint256 constant MASK_UPDATE_RESULT_INVALID_DATA_LENGTH         = 1 << 32;
uint256 constant MASK_UPDATE_RESULT_MULTISIG_KEY_INDEX_MISMATCH = 1 << 33;
uint256 constant MASK_UPDATE_RESULT_INVALID_ECDSA_KEY           = 1 << 34;

// Get opcodes
uint8 constant GET_CURRENT_MULTISIG_KEY_DATA = 0;
uint8 constant GET_MULTISIG_KEY_DATA         = 1;
uint8 constant GET_CURRENT_SCHNORR_KEY_DATA  = 2;
uint8 constant GET_SCHNORR_KEY_DATA          = 3;
uint8 constant GET_SCHNORR_SHARD_DATA        = 4;
uint8 constant GET_CURRENT_ECDSA_KEY_DATA    = 5;
uint8 constant GET_ECDSA_KEY_DATA            = 6;
uint8 constant GET_ECDSA_SHARD_DATA          = 7;

// Get error flags
uint256 constant MASK_GET_RESULT_INVALID_OPCODE      = 1 << 16;
uint256 constant MASK_GET_RESULT_INVALID_DATA_LENGTH = 1 << 17;

// Governance emitter address
bytes32 constant GOVERNANCE_ADDRESS = bytes32(0x0000000000000000000000000000000000000000000000000000000000000004);

// Module ID for the VerificationV2 contract, ASCII "TSS"
bytes32 constant MODULE_VERIFICATION_V2 = bytes32(0x0000000000000000000000000000000000000000000000000000000000545353);

// Action ID for appending a threshold key
uint8 constant ACTION_APPEND_SCHNORR_KEY = 0x01;
uint8 constant ACTION_APPEND_ECDSA_KEY   = 0x02;

contract WormholeVerifier is EIP712Encoding {
  using BytesParsing for bytes;
  using VaaLib for bytes;

  // Secp256k1 information
  uint256 private constant SECP256K1_ORDER               = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
  uint256 private constant SECP256K1_ORDER_MINUS_ONE     = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140;
  uint256 private constant HALF_SECP256K1_ORDER_PLUS_ONE = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92f46681B20A1;

  // Common memory pointer information
  uint256 private constant PTR_FREE_MEMORY = 0x40;
  uint256 private constant PTR_SCRATCH     = 0;
  uint256 private constant LENGTH_WORD     = 0x20;
  uint256 private constant LOG2_WORD_BYTES = 5;

  // Common shift information
  uint256 private constant SHIFT_GET_1  = 256 -  1 * 8;
  uint256 private constant SHIFT_GET_2  = 256 -  2 * 8;
  uint256 private constant SHIFT_GET_4  = 256 -  4 * 8;
  uint256 private constant SHIFT_GET_8  = 256 -  8 * 8;
  uint256 private constant SHIFT_GET_20 = 256 - 20 * 8;

  // Slot layout information
  uint256 private constant SLOT_MULTISIG_KEY_COUNT  = 1000;
  uint256 private constant SLOT_SCHNORR_KEY_COUNT   = 1001;
  uint256 private constant SLOT_SCHNORR_SHARD_COUNT = 1002;
  uint256 private constant SLOT_ECDSA_KEY_COUNT     = 1003;
  uint256 private constant SLOT_ECDSA_SHARD_COUNT   = 1004;

  uint256 private constant SLOT_SCHNORR_KEY_DATA   = 1 << 48;
  uint256 private constant SLOT_SCHNORR_EXTRA_DATA = 2 << 48;
  uint256 private constant SLOT_SCHNORR_SHARD_DATA = 3 << 48;
  uint256 private constant SLOT_MULTISIG_KEY_DATA  = 4 << 48;
  uint256 private constant SLOT_ECDSA_KEY_DATA     = 5 << 48;
  uint256 private constant SLOT_ECDSA_EXTRA_DATA   = 6 << 48;
  uint256 private constant SLOT_ECDSA_SHARD_DATA   = 7 << 48;
  uint256 private constant SLOT_NONCE_BITMAP       = 1 << 64;

  // ECDSA key data information
  uint256 private constant MASK_ECDSA_ENTRY_EXPIRATION_TIME    = 0xFFFFFFFF;
  uint256 private constant SHIFT_ECDSA_ENTRY_PUBKEY             = 32;

  // ECDSA extra data information
  uint256 private constant MASK_ECDSA_ENTRY_SHARD_BASE        = 0xFFFFFFFFFF;
  uint256 private constant MASK_ECDSA_ENTRY_SHARD_COUNT        = 0xFF;
  uint256 private constant MASK_ECDSA_ENTRY_MULTISIG_KEY_INDEX  = 0xFFFFFFFF;
  uint256 private constant SHIFT_ECDSA_ENTRY_SHARD_COUNT       = 40;
  uint256 private constant SHIFT_ECDSA_ENTRY_MULTISIG_KEY_INDEX = 40 + 8;
  
  // Schnorr key data information
  uint256 private constant SHIFT_SCHNORR_KEY_PX = 1;
  uint256 private constant MASK_SCHNORR_KEY_PARITY = 1;

  // Schnorr extra data information
  uint256 private constant MASK_SCHNORR_EXTRA_EXPIRATION_TIME     = 0xFFFFFFFF;
  uint256 private constant MASK_SCHNORR_EXTRA_SHARD_COUNT         = 0xFF;
  uint256 private constant MASK_SCHNORR_EXTRA_SHARD_BASE          = 0xFFFFFFFFFF;
  uint256 private constant MASK_SCHNORR_EXTRA_MULTISIG_KEY_INDEX  = 0xFFFFFFFF;
  uint256 private constant SHIFT_SCHNORR_EXTRA_SHARD_COUNT        = 32;
  uint256 private constant SHIFT_SCHNORR_EXTRA_SHARD_BASE         = 32 + 8;
  uint256 private constant SHIFT_SCHNORR_EXTRA_MULTISIG_KEY_INDEX = 32 + 8 + 40;

  // Multisig key data information
  uint256 private constant MASK_MULTISIG_ENTRY_EXPIRATION_TIME = 0xFFFFFFFF;
  uint256 private constant SHIFT_MULTISIG_ENTRY_ADDRESS = 32;
  
  uint256 private constant OFFSET_MULTISIG_CONTRACT_DATA = 1;

  // Verification result information
  uint256 private constant SHIFT_VERIFY_RESULT_INVALID_VERSION         = 16;
  uint256 private constant SHIFT_VERIFY_RESULT_INVALID_EXPIRATION_TIME = 17;
  uint256 private constant SHIFT_VERIFY_RESULT_INVALID_KEY             = 18;
  uint256 private constant SHIFT_VERIFY_RESULT_INVALID_SIGNATURE       = 19;
  uint256 private constant SHIFT_VERIFY_RESULT_SIGNATURE_MISMATCH      = 20;
  uint256 private constant SHIFT_VERIFY_RESULT_INVALID_SIGNATURE_COUNT = 21;
  uint256 private constant SHIFT_VERIFY_RESULT_INVALID_SIGNER_INDEX    = 22;
  uint256 private constant SHIFT_VERIFY_RESULT_SIGNER_USED             = 23;
  uint256 private constant SHIFT_VERIFY_RESULT_INVALID_OPCODE          = 24;
  uint256 private constant SHIFT_VERIFY_RESULT_INVALID_MESSAGE_LENGTH  = 25;

  // Update result information
  uint256 private constant SHIFT_UPDATE_DEPLOYMENT_FAILED                  = 16;
  uint256 private constant SHIFT_UPDATE_RESULT_INVALID_VERSION             = 17;
  uint256 private constant SHIFT_UPDATE_RESULT_INVALID_SCHNORR_KEY_INDEX   = 18;
  uint256 private constant SHIFT_UPDATE_RESULT_EXPIRED                     = 19;
  uint256 private constant SHIFT_UPDATE_RESULT_INVALID_SIGNER_INDEX        = 20;
  uint256 private constant SHIFT_UPDATE_RESULT_SIGNATURE_MISMATCH          = 21;
  uint256 private constant SHIFT_UPDATE_RESULT_INVALID_MULTISIG_KEY_INDEX  = 22;
  uint256 private constant SHIFT_UPDATE_RESULT_INVALID_SIGNATURE_COUNT     = 23;
  uint256 private constant SHIFT_UPDATE_RESULT_INVALID_GOVERNANCE_CHAIN    = 24;
  uint256 private constant SHIFT_UPDATE_RESULT_INVALID_GOVERNANCE_ADDRESS  = 25;
  uint256 private constant SHIFT_UPDATE_RESULT_INVALID_MODULE              = 26;
  uint256 private constant SHIFT_UPDATE_RESULT_INVALID_ACTION              = 27;
  uint256 private constant SHIFT_UPDATE_RESULT_INVALID_KEY_INDEX           = 28;
  uint256 private constant SHIFT_UPDATE_RESULT_INVALID_SCHNORR_KEY         = 29;
  uint256 private constant SHIFT_UPDATE_RESULT_SHARD_DATA_MISMATCH         = 30;
  uint256 private constant SHIFT_UPDATE_RESULT_INVALID_OPCODE              = 31;
  uint256 private constant SHIFT_UPDATE_RESULT_INVALID_DATA_LENGTH         = 32;
  uint256 private constant SHIFT_UPDATE_RESULT_MULTISIG_KEY_INDEX_MISMATCH = 33;

  // VAA header information
  uint256 private constant OFFSET_HEADER_KEY_INDEX = 1;

  uint256 private constant OFFSET_HEADER_ECDSA_R        = 1 + 4;
  uint256 private constant OFFSET_HEADER_ECDSA_S        = 1 + 4 + 32;
  uint256 private constant OFFSET_HEADER_ECDSA_V        = 1 + 4 + 32 + 32;
  uint256 private constant OFFSET_HEADER_ECDSA_ENVELOPE = 1 + 4 + 32 + 32 + 1;
  uint256 private constant OFFSET_HEADER_ECDSA_PAYLOAD  = 1 + 4 + 32 + 32 + 1 + 4 + 4 + 2 + 32 + 8 + 1;

  uint256 private constant OFFSET_HEADER_SCHNORR_R        = 1 + 4;
  uint256 private constant OFFSET_HEADER_SCHNORR_S        = 1 + 4 + 20;
  uint256 private constant OFFSET_HEADER_SCHNORR_ENVELOPE = 1 + 4 + 20 + 32;
  uint256 private constant OFFSET_HEADER_SCHNORR_PAYLOAD  = 1 + 4 + 20 + 32 + 4 + 4 + 2 + 32 + 8 + 1;

  uint256 private constant OFFSET_HEADER_MULTISIG_SIGNATURE_COUNT = 1 + 4;
  uint256 private constant OFFSET_HEADER_MULTISIG_SIGNATURES      = 1 + 4 + 1;

  // VAA envelope information
  uint256 private constant OFFSET_ENVELOPE_EMITTER_CHAIN_ID = 4 + 4;
  uint256 private constant OFFSET_ENVELOPE_EMITTER_ADDRESS  = 4 + 4 + 2;
  uint256 private constant OFFSET_ENVELOPE_SEQUENCE         = 4 + 4 + 2 + 32;
  uint256 private constant OFFSET_ENVELOPE_PAYLOAD_OFFSET   = 4 + 4 + 2 + 32 + 8 + 1;

  // VAA multisig signature information
  uint256 private constant OFFSET_MULTISIG_SIGNATURE_R = 1;
  uint256 private constant OFFSET_MULTISIG_SIGNATURE_S = 1 + 32;
  uint256 private constant OFFSET_MULTISIG_SIGNATURE_V = 1 + 32 + 32;
  uint256 private constant LENGTH_MULTISIG_SIGNATURE   = 1 + 32 + 32 + 1;

  // Append schnorr key message information
  uint256 private constant LENGTH_APPEND_SCHNORR_KEY_MESSAGE_BODY = 32 + 1 + 4 + 4 + 32 + 4 + 32;

  // Append ecdsa key message information
  uint256 private constant LENGTH_APPEND_ECDSA_KEY_MESSAGE_BODY = 32 + 1 + 4 + 4 + 20 + 4 + 32;

  // Batch format information
  // Offsets relative to the message data start
  uint256 private constant OFFSET_BATCH_OPCODE       = 4;
  uint256 private constant OFFSET_BATCH_DATA         = 4 + 1;
  uint256 private constant OFFSET_BATCH_UNIFORM_DATA = 4 + 1 + 4;

  // Offsets relative to each entry's start
  uint256 private constant OFFSET_BATCH_MULTISIG_SIGNATURE_COUNT = 4;
  uint256 private constant OFFSET_BATCH_MULTISIG_SIGNATURES      = 4 + 1;

  uint256 private constant OFFSET_BATCH_SCHNORR_ENTRY_R      = 4;
  uint256 private constant OFFSET_BATCH_SCHNORR_ENTRY_S      = 4 + 20;
  uint256 private constant OFFSET_BATCH_SCHNORR_ENTRY_DIGEST = 4 + 20 + 32;
  uint256 private constant LENGTH_BATCH_SCHNORR_ENTRY        = 4 + 20 + 32 + 32;

  uint256 private constant OFFSET_BATCH_SCHNORR_UNIFORM_S      = 20;
  uint256 private constant OFFSET_BATCH_SCHNORR_UNIFORM_DIGEST = 20 + 32;
  uint256 private constant LENGTH_BATCH_SCHNORR_UNIFORM_ENTRY  = 20 + 32 + 32;

  uint256 private constant OFFSET_BATCH_ECDSA_ENTRY_R      = 4;
  uint256 private constant OFFSET_BATCH_ECDSA_ENTRY_S      = 4 + 32;
  uint256 private constant OFFSET_BATCH_ECDSA_ENTRY_V      = 4 + 32 + 32;
  uint256 private constant OFFSET_BATCH_ECDSA_ENTRY_DIGEST = 4 + 32 + 32 + 1;
  uint256 private constant LENGTH_BATCH_ECDSA_ENTRY        = 4 + 32 + 32 + 1 + 32;

  uint256 private constant OFFSET_BATCH_ECDSA_UNIFORM_S      = 32;
  uint256 private constant OFFSET_BATCH_ECDSA_UNIFORM_V      = 32 + 32;
  uint256 private constant OFFSET_BATCH_ECDSA_UNIFORM_DIGEST = 32 + 32 + 1;
  uint256 private constant LENGTH_BATCH_ECDSA_UNIFORM_ENTRY  = 32 + 32 + 1 + 32;

  // Schnorr challenge information
  uint256 private constant OFFSET_SCHNORR_CHALLENGE_PARITY = 32;
  uint256 private constant OFFSET_SCHNORR_CHALLENGE_DIGEST = 32 + 1;
  uint256 private constant OFFSET_SCHNORR_CHALLENGE_R      = 32 + 1 + 32;
  uint256 private constant LENGTH_SCHNORR_CHALLENGE        = 32 + 1 + 32 + 20;

  // Ecrecover information
  address private constant ADDRESS_ECRECOVER = 0x0000000000000000000000000000000000000001;
  uint256 private constant OFFSET_ECRECOVER_V      = 32 * 1;
  uint256 private constant OFFSET_ECRECOVER_R      = 32 * 2;
  uint256 private constant OFFSET_ECRECOVER_S      = 32 * 3;
  uint256 private constant LENGTH_ECRECOVER_BUFFER = 32 * 4;
  uint256 private constant LENGTH_ECRECOVER_RESULT = 32;
  uint256 private constant MAGIC_ECRECOVER_PARITY_DELTA = 27;

  // Error encoding information
  uint256 private constant SELECTOR_ERROR_VERIFICATION_FAILED = 0x32629d58 << (256 - 32);
  uint256 private constant OFFSET_VERIFICATION_FAILED_RESULT = 0x04;
  uint256 private constant LENGTH_VERIFICATION_FAILED = 0x24;

  uint256 private constant SELECTOR_ERROR_UPDATE_FAILED = 0xa77ba01e << (256 - 32);
  uint256 private constant OFFSET_UPDATE_FAILED_RESULT = 0x04;
  uint256 private constant LENGTH_UPDATE_FAILED = 0x24;

  error VerificationFailed(uint256 result);
  error GetFailed(uint256 result);
  error UpdateFailed(uint256 result);

  error UnknownGuardianSet(uint32 index);
  error GovernanceVaaVerificationFailure();

  // We don't make this immutable to keep bytecode verification from build simple.
  // It's only used in cold execution paths like governance operations.
  ICoreBridge private _coreBridge;

  constructor(
    ICoreBridge coreBridge,
    uint32 initialMultisigKeyCount,
    uint32 initialSchnorrKeyCount,
    uint32 initialMultisigKeyPullLimit,
    bytes memory appendSchnorrKeyVaa
  ) {
    _coreBridge = coreBridge;

    _updateMultisigKeyCount(initialMultisigKeyCount);
    _updateSchnorrKeyCount(initialSchnorrKeyCount);

    if (initialMultisigKeyPullLimit > 0) {
      _pullMultisigKeyData(initialMultisigKeyPullLimit);
    }

    if (appendSchnorrKeyVaa.length > 0) _appendSchnorrKey(appendSchnorrKeyVaa);
  }

  function verify(bytes calldata data) external view returns (
    uint16 emitterChainId,
    bytes32 emitterAddress,
    uint64 sequence,
    uint16 payloadOffset
  ) {
    assembly ("memory-safe") {
      // NOTE: Unfortunately, we have to duplicate this pile of functions because of Solidity's inability to share them between assembly blocks

      // !!!!!                    START OF DUPLICATED FUNCTIONS                    !!!!!
      // !!!!!    Please make sure that they are kept identical between copies!    !!!!!

      // Calldata reader functions
      function getCd_1(offset) -> value {
        value := shr(SHIFT_GET_1, calldataload(offset))
      }

      function getCd_2(offset) -> value {
        value := shr(SHIFT_GET_2, calldataload(offset))
      }

      function getCd_4(offset) -> value {
        value := shr(SHIFT_GET_4, calldataload(offset))
      }

      function getCd_8(offset) -> value {
        value := shr(SHIFT_GET_8, calldataload(offset))
      }

      function getCd_20(offset) -> value {
        value := shr(SHIFT_GET_20, calldataload(offset))
      }

      function getCd_32(offset) -> value {
        value := calldataload(offset)
      }

      // Slot reader functions
      function getSchnorrKeyData(keyIndex) -> pubkeyX, parity {
        let pubkey := sload(add(SLOT_SCHNORR_KEY_DATA, keyIndex))
        pubkeyX := shr(SHIFT_SCHNORR_KEY_PX, pubkey)
        parity := and(pubkey, MASK_SCHNORR_KEY_PARITY)
      }

      function getSchnorrKeyExtra(keyIndex) -> expirationTime {
        let entry := sload(add(SLOT_SCHNORR_EXTRA_DATA, keyIndex))
        expirationTime := and(entry, MASK_SCHNORR_EXTRA_EXPIRATION_TIME)
      }

      function getMultisigKeyData(keyIndex) -> keyDataAddress, expirationTime {
        let entry := sload(add(SLOT_MULTISIG_KEY_DATA, keyIndex))
        keyDataAddress := shr(SHIFT_MULTISIG_ENTRY_ADDRESS, entry)
        expirationTime := and(entry, MASK_MULTISIG_ENTRY_EXPIRATION_TIME)
      }

      function getECDSAKeyData(keyIndex) -> pubkey, expirationTime {
        let entry := sload(add(SLOT_ECDSA_KEY_DATA, keyIndex))
        pubkey := shr(SHIFT_ECDSA_ENTRY_PUBKEY, entry)
        expirationTime := and(entry, MASK_ECDSA_ENTRY_EXPIRATION_TIME)
      }

      // Multisig key data access functions
      function getMultisigKeyDataFromContract(keyDataAddress, buffer) -> keyDataSize {
        keyDataSize := extcodesize(keyDataAddress)
        if iszero(keyDataSize) {
          mstore(PTR_SCRATCH, SELECTOR_ERROR_VERIFICATION_FAILED)
          mstore(OFFSET_VERIFICATION_FAILED_RESULT, MASK_VERIFY_RESULT_INVALID_KEY_DATA_SIZE)
          revert(PTR_SCRATCH, LENGTH_VERIFICATION_FAILED)
        }
        extcodecopy(keyDataAddress, buffer, OFFSET_MULTISIG_CONTRACT_DATA, sub(keyDataSize, OFFSET_MULTISIG_CONTRACT_DATA))
      }

      // Cryptographic functions
      function doubleHash(offset, length, buffer) -> digest {
        calldatacopy(buffer, offset, length)
        let singleHash := keccak256(buffer, length)
        mstore(PTR_SCRATCH, singleHash)
        digest := keccak256(PTR_SCRATCH, LENGTH_WORD)
      }

      function computeSchnorrChallenge(px, parity, digest, r, buffer) -> e {
        mstore(buffer, px)
        mstore8(add(buffer, OFFSET_SCHNORR_CHALLENGE_PARITY), parity)
        mstore(add(buffer, OFFSET_SCHNORR_CHALLENGE_DIGEST), digest)
        mstore(add(buffer, OFFSET_SCHNORR_CHALLENGE_R), shl(SHIFT_GET_20, r))
        e := keccak256(buffer, LENGTH_SCHNORR_CHALLENGE)
      }

      function ecrecover(digest, v, r, s, buffer, expected) -> success {
        mstore(buffer, digest)
        mstore(add(buffer, OFFSET_ECRECOVER_V), v)
        mstore(add(buffer, OFFSET_ECRECOVER_R), r)
        mstore(add(buffer, OFFSET_ECRECOVER_S), s)
        success := staticcall(gas(), ADDRESS_ECRECOVER, buffer, LENGTH_ECRECOVER_BUFFER, buffer, LENGTH_ECRECOVER_RESULT)
        success := and(success, eq(expected, mload(buffer)))
      }

      function checkSchnorrSignature(px, parity, digest, r, s, buffer) -> invalidPubkey, invalidSignature, invalidMismatch {
        let e := computeSchnorrChallenge(px, parity, digest, r, buffer)

        let success := ecrecover(
          sub(SECP256K1_ORDER, mulmod(px, s, SECP256K1_ORDER)),
          add(parity, MAGIC_ECRECOVER_PARITY_DELTA),
          px,
          mulmod(px, e, SECP256K1_ORDER),
          buffer,
          r
        )

        invalidPubkey := iszero(px)
        invalidSignature := or(iszero(r), gt(s, SECP256K1_ORDER_MINUS_ONE))
        invalidMismatch := iszero(success)
      }

      function checkMultisigSignature(digest, signaturesOffset, signatureCount, keyDataOffset, keyCount, buffer) -> invalidIndex, invalidMismatch, invalidUsedSigner {
        // Verify the signatures
        let usedSignerBitfield := 0
        invalidIndex := 0
        invalidMismatch := 0
        invalidUsedSigner := 0

        for { let i := 0 } lt(i, signatureCount) { i := add(i, 1) } {
          let signerIndex := getCd_1(signaturesOffset)
          let r := getCd_32(add(signaturesOffset, OFFSET_MULTISIG_SIGNATURE_R))
          let s := getCd_32(add(signaturesOffset, OFFSET_MULTISIG_SIGNATURE_S))
          let v := getCd_1(add(signaturesOffset, OFFSET_MULTISIG_SIGNATURE_V))

          // Call ecrecover
          let expected := mload(add(keyDataOffset, shl(5, signerIndex)))
          let signatureMatch := ecrecover(digest, add(v, MAGIC_ECRECOVER_PARITY_DELTA), r, s, buffer, expected)

          // Validate the result
          let indexInvalid := iszero(lt(signerIndex, keyCount))
          let signerUsedInvalid := and(usedSignerBitfield, shl(signerIndex, 1))

          invalidIndex := or(invalidIndex, indexInvalid)
          invalidMismatch := or(invalidMismatch, iszero(signatureMatch))
          invalidUsedSigner := or(invalidUsedSigner, signerUsedInvalid)

          // Update the used signer bitfield and offset for the next signature
          usedSignerBitfield := or(usedSignerBitfield, shl(signerIndex, 1))
          signaturesOffset := add(signaturesOffset, LENGTH_MULTISIG_SIGNATURE)
        }
      }

      function checkExpirationTime(expirationTime) -> invalidExpirationTime {
        invalidExpirationTime := iszero(or(iszero(expirationTime), gt(expirationTime, timestamp())))
      }
      
      function checkQuorum(signatureCount, keyCount) -> invalidSignatureCount {
        // Verify that signatureCount > 2 * keyCount / 3
        let quorum := div(shl(1, keyCount), 3)
        let entryInvalidSignatureCount := iszero(gt(signatureCount, quorum))
      }

      // Verification functions
      function verifySingleECDSA(keyIndex, r, s, v, digest, buffer) -> invalidExpirationTime, invalidMismatch {
        let pubkey, expirationTime := getECDSAKeyData(keyIndex)
        invalidExpirationTime := checkExpirationTime(expirationTime)
        invalidMismatch := iszero(ecrecover(digest, v, r, s, buffer, pubkey))
      }

      function verifySingleSchnorr(keyIndex, r, s, digest, buffer) -> invalidExpirationTime, invalidPubkey, invalidSignature, invalidMismatch {
        // Load the public key data
        let px, parity := getSchnorrKeyData(keyIndex)
        let expirationTime := getSchnorrKeyExtra(keyIndex)

        // Verify the signature
        invalidExpirationTime := checkExpirationTime(expirationTime)
        invalidPubkey, invalidSignature, invalidMismatch := checkSchnorrSignature(px, parity, digest, r, s, buffer)
      }

      function verifySingleMultisig(keyIndex, signatureCount, signaturesOffset, digest, buffer) -> invalidExpirationTime, invalidSignatureCount, invalidIndex, invalidMismatch, invalidUsedSigner {
        // Load the key data
        let keyDataAddress, expirationTime := getMultisigKeyData(keyIndex)

        // Load the key data contract
        let keyDataSize := getMultisigKeyDataFromContract(keyDataAddress, buffer)
        let keyCount := shr(LOG2_WORD_BYTES, keyDataSize)

        // Verify the signatures
        let newBuffer := add(buffer, keyDataSize)
        invalidIndex, invalidMismatch, invalidUsedSigner := checkMultisigSignature(digest, signaturesOffset, signatureCount, buffer, keyCount, newBuffer)

        // Validate the header
        invalidSignatureCount := checkQuorum(signatureCount, keyCount)
        invalidExpirationTime := checkExpirationTime(expirationTime)
      }

      // Output functions
      function verificationFailed(result) {
        mstore(PTR_SCRATCH, SELECTOR_ERROR_VERIFICATION_FAILED)
        mstore(OFFSET_VERIFICATION_FAILED_RESULT, result)
        revert(PTR_SCRATCH, LENGTH_VERIFICATION_FAILED)
      }

      function verificationFailedMultisig(invalidExpirationTime, invalidSignatureCount, invalidIndex, invalidMismatch, invalidUsedSigner, invalidMessageLength, offset) {
        let invalidExpirationTimeFlag := shl(SHIFT_VERIFY_RESULT_INVALID_EXPIRATION_TIME, invalidExpirationTime)
        let invalidSignatureCountFlag := shl(SHIFT_VERIFY_RESULT_INVALID_SIGNATURE_COUNT, invalidSignatureCount)
        let invalidIndexFlag := shl(SHIFT_VERIFY_RESULT_INVALID_SIGNER_INDEX, invalidIndex)
        let invalidMismatchFlag := shl(SHIFT_VERIFY_RESULT_SIGNATURE_MISMATCH, invalidMismatch)
        let invalidUsedSignerFlag := shl(SHIFT_VERIFY_RESULT_SIGNER_USED, invalidUsedSigner)
        let invalidMessageLengthFlag := shl(SHIFT_VERIFY_RESULT_INVALID_MESSAGE_LENGTH, invalidMessageLength)

        let flags1 := or(invalidExpirationTimeFlag, invalidSignatureCountFlag)
        let flags2 := or(invalidIndexFlag, invalidMismatchFlag)
        let flags3 := or(invalidUsedSignerFlag, invalidMessageLengthFlag)
        verificationFailed(or(offset, or(flags1, or(flags2, flags3))))
      }

      function verificationFailedSchnorr(invalidExpirationTime, invalidPubkey, invalidSignature, invalidMismatch, invalidMessageLength, offset) {
        let invalidExpirationTimeFlag := shl(SHIFT_VERIFY_RESULT_INVALID_EXPIRATION_TIME, invalidExpirationTime)
        let invalidPubkeyFlag := shl(SHIFT_VERIFY_RESULT_INVALID_KEY, invalidPubkey)
        let invalidSignatureFlag := shl(SHIFT_VERIFY_RESULT_INVALID_SIGNATURE, invalidSignature)
        let invalidRecoveredFlag := shl(SHIFT_VERIFY_RESULT_SIGNATURE_MISMATCH, invalidMismatch)
        let invalidMessageLengthFlag := shl(SHIFT_VERIFY_RESULT_INVALID_MESSAGE_LENGTH, invalidMessageLength)

        let flags1 := or(invalidExpirationTimeFlag, invalidPubkeyFlag)
        let flags2 := or(or(invalidSignatureFlag, invalidRecoveredFlag), invalidMessageLengthFlag)
        verificationFailed(or(offset, or(flags1, flags2)))
      }

      function verificationFailedECDSA(invalidExpirationTime, invalidMismatch, invalidMessageLength, offset) {
        let invalidExpirationTimeFlag := shl(SHIFT_VERIFY_RESULT_INVALID_EXPIRATION_TIME, invalidExpirationTime)
        let invalidMismatchFlag := shl(SHIFT_VERIFY_RESULT_SIGNATURE_MISMATCH, invalidMismatch)
        let invalidMessageLengthFlag := shl(SHIFT_VERIFY_RESULT_INVALID_MESSAGE_LENGTH, invalidMessageLength)

        let flags := or(invalidExpirationTimeFlag, or(invalidMismatchFlag, invalidMessageLengthFlag))
        verificationFailed(or(offset, flags))
      }

      // !!!!!                    END OF DUPLICATED FUNCTIONS                    !!!!!

      // Decode the common header
      let version := getCd_1(data.offset)
      let keyIndex := getCd_4(add(data.offset, OFFSET_HEADER_KEY_INDEX))

      switch version
      case 0x03 {
        // Decode the ECDSA header
        let r := getCd_32(add(data.offset, OFFSET_HEADER_ECDSA_R))
        let s := getCd_32(add(data.offset, OFFSET_HEADER_ECDSA_S))
        let v := getCd_1(add(data.offset, OFFSET_HEADER_ECDSA_V))
        
        // Compute the double hash of the VAA
        let envelopePtr := add(data.offset, OFFSET_HEADER_ECDSA_ENVELOPE)
        let buffer := mload(PTR_FREE_MEMORY)
        let digest := doubleHash(envelopePtr, sub(data.length, OFFSET_HEADER_ECDSA_ENVELOPE), buffer)

        // Verify signatures
        // NOTE: The next line destroys the buffer
        let invalidExpirationTime, invalidMismatch := verifySingleECDSA(keyIndex, r, s, v, digest, buffer)

        // Check for errors
        if or(invalidExpirationTime, invalidMismatch) {
          verificationFailedECDSA(invalidExpirationTime, invalidMismatch, 0, 0)
        }

        // Generate the result
        emitterChainId := getCd_2(add(envelopePtr, OFFSET_ENVELOPE_EMITTER_CHAIN_ID))
        emitterAddress := getCd_32(add(envelopePtr, OFFSET_ENVELOPE_EMITTER_ADDRESS))
        sequence := getCd_8(add(envelopePtr, OFFSET_ENVELOPE_SEQUENCE))
        payloadOffset := OFFSET_HEADER_ECDSA_PAYLOAD
      }
      case 0x02 {
        // Decode the schnorr header
        let r := getCd_20(add(data.offset, OFFSET_HEADER_SCHNORR_R))
        let s := getCd_32(add(data.offset, OFFSET_HEADER_SCHNORR_S))

        // Compute the double hash of the VAA
        let envelopePtr := add(data.offset, OFFSET_HEADER_SCHNORR_ENVELOPE)
        let buffer := mload(PTR_FREE_MEMORY)
        let digest := doubleHash(envelopePtr, sub(data.length, OFFSET_HEADER_SCHNORR_ENVELOPE), buffer)

        // Verify the signature
        // NOTE: The next line destroys the buffer
        let invalidExpirationTime, invalidPubkey, invalidSignature, invalidMismatch := verifySingleSchnorr(keyIndex, r, s, digest, buffer)

        // Error when any of the invalid flags are set
        if or(invalidExpirationTime, or(invalidPubkey, or(invalidSignature, invalidMismatch))) {
          verificationFailedSchnorr(invalidExpirationTime, invalidPubkey, invalidSignature, invalidMismatch, 0, 0)
        }

        // Generate the result
        emitterChainId := getCd_2(add(envelopePtr, OFFSET_ENVELOPE_EMITTER_CHAIN_ID))
        emitterAddress := getCd_32(add(envelopePtr, OFFSET_ENVELOPE_EMITTER_ADDRESS))
        sequence := getCd_8(add(envelopePtr, OFFSET_ENVELOPE_SEQUENCE))
        payloadOffset := OFFSET_HEADER_SCHNORR_PAYLOAD
      }
      case 0x01 {
        // Decode the multisig header
        let signatureCount := getCd_1(add(data.offset, OFFSET_HEADER_MULTISIG_SIGNATURE_COUNT))
        let signaturesOffset := add(data.offset, OFFSET_HEADER_MULTISIG_SIGNATURES)

        // Compute the envelope offset
        let envelopeOffset := add(OFFSET_HEADER_MULTISIG_SIGNATURES, mul(signatureCount, LENGTH_MULTISIG_SIGNATURE))
        let envelopePtr := add(data.offset, envelopeOffset)

        // Compute the double hash of the VAA
        let buffer := mload(PTR_FREE_MEMORY)
        let digest := doubleHash(envelopePtr, sub(data.length, envelopeOffset), buffer)

        let invalidExpirationTime, invalidSignatureCount, invalidIndex, invalidMismatch, invalidUsedSigner :=
          verifySingleMultisig(keyIndex, signatureCount, signaturesOffset, digest, buffer)

        // Generate the result
        if or(invalidExpirationTime, or(invalidSignatureCount, or(invalidIndex, or(invalidMismatch, invalidUsedSigner)))) {
          verificationFailedMultisig(invalidExpirationTime, invalidSignatureCount, invalidIndex, invalidMismatch, invalidUsedSigner, 0, 0)
        }

        // Generate the result
        emitterChainId := getCd_2(add(envelopePtr, OFFSET_ENVELOPE_EMITTER_CHAIN_ID))
        emitterAddress := getCd_32(add(envelopePtr, OFFSET_ENVELOPE_EMITTER_ADDRESS))
        sequence := getCd_8(add(envelopePtr, OFFSET_ENVELOPE_SEQUENCE))
        payloadOffset := add(envelopeOffset, OFFSET_ENVELOPE_PAYLOAD_OFFSET)
      }
      default {
        verificationFailed(MASK_VERIFY_RESULT_INVALID_VERSION)
      }
    }
  }

  function verifyBatch() external view {
    assembly ("memory-safe") {
      // NOTE: Unfortunately, we have to duplicate this pile of functions because of Solidity's inability to share them between assembly blocks

      // !!!!!                    START OF DUPLICATED FUNCTIONS                    !!!!!
      // !!!!!    Please make sure that they are kept identical between copies!    !!!!!

      // Calldata reader functions
      function getCd_1(offset) -> value {
        value := shr(SHIFT_GET_1, calldataload(offset))
      }

      function getCd_2(offset) -> value {
        value := shr(SHIFT_GET_2, calldataload(offset))
      }

      function getCd_4(offset) -> value {
        value := shr(SHIFT_GET_4, calldataload(offset))
      }

      function getCd_8(offset) -> value {
        value := shr(SHIFT_GET_8, calldataload(offset))
      }

      function getCd_20(offset) -> value {
        value := shr(SHIFT_GET_20, calldataload(offset))
      }

      function getCd_32(offset) -> value {
        value := calldataload(offset)
      }

      // Slot reader functions
      function getSchnorrKeyData(keyIndex) -> pubkeyX, parity {
        let pubkey := sload(add(SLOT_SCHNORR_KEY_DATA, keyIndex))
        pubkeyX := shr(SHIFT_SCHNORR_KEY_PX, pubkey)
        parity := and(pubkey, MASK_SCHNORR_KEY_PARITY)
      }

      function getSchnorrKeyExtra(keyIndex) -> expirationTime {
        let entry := sload(add(SLOT_SCHNORR_EXTRA_DATA, keyIndex))
        expirationTime := and(entry, MASK_SCHNORR_EXTRA_EXPIRATION_TIME)
      }

      function getMultisigKeyData(keyIndex) -> keyDataAddress, expirationTime {
        let entry := sload(add(SLOT_MULTISIG_KEY_DATA, keyIndex))
        keyDataAddress := shr(SHIFT_MULTISIG_ENTRY_ADDRESS, entry)
        expirationTime := and(entry, MASK_MULTISIG_ENTRY_EXPIRATION_TIME)
      }

      function getECDSAKeyData(keyIndex) -> pubkey, expirationTime {
        let entry := sload(add(SLOT_ECDSA_KEY_DATA, keyIndex))
        pubkey := shr(SHIFT_ECDSA_ENTRY_PUBKEY, entry)
        expirationTime := and(entry, MASK_ECDSA_ENTRY_EXPIRATION_TIME)
      }

      // Multisig key data access functions
      function getMultisigKeyDataFromContract(keyDataAddress, buffer) -> keyDataSize {
        keyDataSize := extcodesize(keyDataAddress)
        if iszero(keyDataSize) {
          mstore(PTR_SCRATCH, SELECTOR_ERROR_VERIFICATION_FAILED)
          mstore(OFFSET_VERIFICATION_FAILED_RESULT, MASK_VERIFY_RESULT_INVALID_KEY_DATA_SIZE)
          revert(PTR_SCRATCH, LENGTH_VERIFICATION_FAILED)
        }
        extcodecopy(keyDataAddress, buffer, OFFSET_MULTISIG_CONTRACT_DATA, sub(keyDataSize, OFFSET_MULTISIG_CONTRACT_DATA))
      }

      // Cryptographic functions
      function doubleHash(offset, length, buffer) -> digest {
        calldatacopy(buffer, offset, length)
        let singleHash := keccak256(buffer, length)
        mstore(PTR_SCRATCH, singleHash)
        digest := keccak256(PTR_SCRATCH, LENGTH_WORD)
      }

      function computeSchnorrChallenge(px, parity, digest, r, buffer) -> e {
        mstore(buffer, px)
        mstore8(add(buffer, OFFSET_SCHNORR_CHALLENGE_PARITY), parity)
        mstore(add(buffer, OFFSET_SCHNORR_CHALLENGE_DIGEST), digest)
        mstore(add(buffer, OFFSET_SCHNORR_CHALLENGE_R), shl(SHIFT_GET_20, r))
        e := keccak256(buffer, LENGTH_SCHNORR_CHALLENGE)
      }

      function ecrecover(digest, v, r, s, buffer, expected) -> success {
        mstore(buffer, digest)
        mstore(add(buffer, OFFSET_ECRECOVER_V), v)
        mstore(add(buffer, OFFSET_ECRECOVER_R), r)
        mstore(add(buffer, OFFSET_ECRECOVER_S), s)
        success := staticcall(gas(), ADDRESS_ECRECOVER, buffer, LENGTH_ECRECOVER_BUFFER, buffer, LENGTH_ECRECOVER_RESULT)
        success := and(success, eq(expected, mload(buffer)))
      }

      function checkSchnorrSignature(px, parity, digest, r, s, buffer) -> invalidPubkey, invalidSignature, invalidMismatch {
        let e := computeSchnorrChallenge(px, parity, digest, r, buffer)

        let success := ecrecover(
          sub(SECP256K1_ORDER, mulmod(px, s, SECP256K1_ORDER)),
          add(parity, MAGIC_ECRECOVER_PARITY_DELTA),
          px,
          mulmod(px, e, SECP256K1_ORDER),
          buffer,
          r
        )

        invalidPubkey := iszero(px)
        invalidSignature := or(iszero(r), gt(s, SECP256K1_ORDER_MINUS_ONE))
        invalidMismatch := iszero(success)
      }

      function checkMultisigSignature(digest, signaturesOffset, signatureCount, keyDataOffset, keyCount, buffer) -> invalidIndex, invalidMismatch, invalidUsedSigner {
        // Verify the signatures
        let usedSignerBitfield := 0
        invalidIndex := 0
        invalidMismatch := 0
        invalidUsedSigner := 0

        for { let i := 0 } lt(i, signatureCount) { i := add(i, 1) } {
          let signerIndex := getCd_1(signaturesOffset)
          let r := getCd_32(add(signaturesOffset, OFFSET_MULTISIG_SIGNATURE_R))
          let s := getCd_32(add(signaturesOffset, OFFSET_MULTISIG_SIGNATURE_S))
          let v := getCd_1(add(signaturesOffset, OFFSET_MULTISIG_SIGNATURE_V))

          // Call ecrecover
          let expected := mload(add(keyDataOffset, shl(5, signerIndex)))
          let signatureMatch := ecrecover(digest, add(v, MAGIC_ECRECOVER_PARITY_DELTA), r, s, buffer, expected)

          // Validate the result
          let indexInvalid := iszero(lt(signerIndex, keyCount))
          let signerUsedInvalid := and(usedSignerBitfield, shl(signerIndex, 1))

          invalidIndex := or(invalidIndex, indexInvalid)
          invalidMismatch := or(invalidMismatch, iszero(signatureMatch))
          invalidUsedSigner := or(invalidUsedSigner, signerUsedInvalid)

          // Update the used signer bitfield and offset for the next signature
          usedSignerBitfield := or(usedSignerBitfield, shl(signerIndex, 1))
          signaturesOffset := add(signaturesOffset, LENGTH_MULTISIG_SIGNATURE)
        }
      }

      function checkExpirationTime(expirationTime) -> invalidExpirationTime {
        invalidExpirationTime := iszero(or(iszero(expirationTime), gt(expirationTime, timestamp())))
      }

      function checkQuorum(signatureCount, keyCount) -> invalidSignatureCount {
        // Verify that signatureCount > 2 * keyCount / 3
        let quorum := div(shl(1, keyCount), 3)
        let entryInvalidSignatureCount := iszero(gt(signatureCount, quorum))
      }

      // Verification functions
      function verifySingleECDSA(keyIndex, r, s, v, digest, buffer) -> invalidExpirationTime, invalidMismatch {
        let pubkey, expirationTime := getECDSAKeyData(keyIndex)
        invalidExpirationTime := checkExpirationTime(expirationTime)
        invalidMismatch := iszero(ecrecover(digest, v, r, s, buffer, pubkey))
      }

      function verifySingleSchnorr(keyIndex, r, s, digest, buffer) -> invalidExpirationTime, invalidPubkey, invalidSignature, invalidMismatch {
        // Load the public key data
        let px, parity := getSchnorrKeyData(keyIndex)
        let expirationTime := getSchnorrKeyExtra(keyIndex)

        // Verify the signature
        invalidExpirationTime := checkExpirationTime(expirationTime)
        invalidPubkey, invalidSignature, invalidMismatch := checkSchnorrSignature(px, parity, digest, r, s, buffer)
      }

      function verifySingleMultisig(keyIndex, signatureCount, signaturesOffset, digest, buffer) -> invalidExpirationTime, invalidSignatureCount, invalidIndex, invalidMismatch, invalidUsedSigner {
        // Load the key data
        let keyDataAddress, expirationTime := getMultisigKeyData(keyIndex)

        // Load the key data contract
        let keyDataSize := getMultisigKeyDataFromContract(keyDataAddress, buffer)
        let keyCount := shr(LOG2_WORD_BYTES, keyDataSize)

        // Verify the signatures
        let newBuffer := add(buffer, keyDataSize)
        invalidIndex, invalidMismatch, invalidUsedSigner := checkMultisigSignature(digest, signaturesOffset, signatureCount, buffer, keyCount, newBuffer)

        // Validate the header
        invalidSignatureCount := checkQuorum(signatureCount, keyCount)
        invalidExpirationTime := checkExpirationTime(expirationTime)
      }

      // Output functions
      function verificationFailed(result) {
        mstore(PTR_SCRATCH, SELECTOR_ERROR_VERIFICATION_FAILED)
        mstore(OFFSET_VERIFICATION_FAILED_RESULT, result)
        revert(PTR_SCRATCH, LENGTH_VERIFICATION_FAILED)
      }

      function verificationFailedMultisig(invalidExpirationTime, invalidSignatureCount, invalidIndex, invalidMismatch, invalidUsedSigner, invalidMessageLength, offset) {
        let invalidExpirationTimeFlag := shl(SHIFT_VERIFY_RESULT_INVALID_EXPIRATION_TIME, invalidExpirationTime)
        let invalidSignatureCountFlag := shl(SHIFT_VERIFY_RESULT_INVALID_SIGNATURE_COUNT, invalidSignatureCount)
        let invalidIndexFlag := shl(SHIFT_VERIFY_RESULT_INVALID_SIGNER_INDEX, invalidIndex)
        let invalidMismatchFlag := shl(SHIFT_VERIFY_RESULT_SIGNATURE_MISMATCH, invalidMismatch)
        let invalidUsedSignerFlag := shl(SHIFT_VERIFY_RESULT_SIGNER_USED, invalidUsedSigner)
        let invalidMessageLengthFlag := shl(SHIFT_VERIFY_RESULT_INVALID_MESSAGE_LENGTH, invalidMessageLength)

        let flags1 := or(invalidExpirationTimeFlag, invalidSignatureCountFlag)
        let flags2 := or(invalidIndexFlag, invalidMismatchFlag)
        let flags3 := or(invalidUsedSignerFlag, invalidMessageLengthFlag)
        verificationFailed(or(offset, or(flags1, or(flags2, flags3))))
      }

      function verificationFailedSchnorr(invalidExpirationTime, invalidPubkey, invalidSignature, invalidMismatch, invalidMessageLength, offset) {
        let invalidExpirationTimeFlag := shl(SHIFT_VERIFY_RESULT_INVALID_EXPIRATION_TIME, invalidExpirationTime)
        let invalidPubkeyFlag := shl(SHIFT_VERIFY_RESULT_INVALID_KEY, invalidPubkey)
        let invalidSignatureFlag := shl(SHIFT_VERIFY_RESULT_INVALID_SIGNATURE, invalidSignature)
        let invalidRecoveredFlag := shl(SHIFT_VERIFY_RESULT_SIGNATURE_MISMATCH, invalidMismatch)
        let invalidMessageLengthFlag := shl(SHIFT_VERIFY_RESULT_INVALID_MESSAGE_LENGTH, invalidMessageLength)

        let flags1 := or(invalidExpirationTimeFlag, invalidPubkeyFlag)
        let flags2 := or(or(invalidSignatureFlag, invalidRecoveredFlag), invalidMessageLengthFlag)
        verificationFailed(or(offset, or(flags1, flags2)))
      }

      function verificationFailedECDSA(invalidExpirationTime, invalidMismatch, invalidMessageLength, offset) {
        let invalidExpirationTimeFlag := shl(SHIFT_VERIFY_RESULT_INVALID_EXPIRATION_TIME, invalidExpirationTime)
        let invalidMismatchFlag := shl(SHIFT_VERIFY_RESULT_SIGNATURE_MISMATCH, invalidMismatch)
        let invalidMessageLengthFlag := shl(SHIFT_VERIFY_RESULT_INVALID_MESSAGE_LENGTH, invalidMessageLength)

        let flags := or(invalidExpirationTimeFlag, or(invalidMismatchFlag, invalidMessageLengthFlag))
        verificationFailed(or(offset, flags))
      }

      // !!!!!                    END OF DUPLICATED FUNCTIONS                    !!!!!

      function verifyBatch() {
        let invalidExpirationTime := 0
        let invalidPubkey := 0
        let invalidSignature := 0
        let invalidMismatch := 0
        let invalidSignatureCount := 0
        let invalidUsedSigner := 0
        let invalidIndex := 0
        let invalidTotal := 0

        let buffer := mload(PTR_FREE_MEMORY)
        let offset := OFFSET_BATCH_DATA

        for {} and(iszero(invalidTotal), lt(offset, calldatasize())) {} {
          let version := getCd_1(offset)
          switch version
          case 0x03 {
            // Decode the ECDSA header and digest
            let keyIndex := getCd_4(add(offset, OFFSET_HEADER_KEY_INDEX))
            let r := getCd_32(add(offset, OFFSET_HEADER_ECDSA_R))
            let s := getCd_32(add(offset, OFFSET_HEADER_ECDSA_S))
            let v := getCd_1(add(offset, OFFSET_HEADER_ECDSA_V))
            let digest := getCd_32(add(offset, OFFSET_HEADER_SCHNORR_ENVELOPE))

            // Verify the signature
            invalidExpirationTime, invalidMismatch := verifySingleECDSA(keyIndex, r, s, v, digest, buffer)
            invalidTotal := or(invalidExpirationTime, invalidMismatch)
            offset := add(offset, LENGTH_BATCH_ECDSA_ENTRY)
          }
          case 0x02 {
            // Decode the schnorr header and digest
            let keyIndex := getCd_4(add(offset, OFFSET_HEADER_KEY_INDEX))
            let r := getCd_20(add(offset, OFFSET_HEADER_SCHNORR_R))
            let s := getCd_32(add(offset, OFFSET_HEADER_SCHNORR_S))
            let digest := getCd_32(add(offset, OFFSET_HEADER_SCHNORR_ENVELOPE))

            // Verify the signature
            invalidExpirationTime, invalidPubkey, invalidSignature, invalidMismatch := verifySingleSchnorr(keyIndex, r, s, digest, buffer)
            invalidTotal := or(invalidExpirationTime, or(invalidPubkey, or(invalidSignature, invalidMismatch)))
            offset := add(offset, LENGTH_BATCH_SCHNORR_ENTRY)
          }
          case 0x01 {
            // Decode the multisig header and digest
            let keyIndex := getCd_4(add(offset, OFFSET_HEADER_KEY_INDEX))
            let signatureCount := getCd_1(add(offset, OFFSET_HEADER_MULTISIG_SIGNATURE_COUNT))
            let signaturesOffset := add(offset, OFFSET_HEADER_MULTISIG_SIGNATURES)
            let digestOffset := add(signaturesOffset, mul(signatureCount, LENGTH_MULTISIG_SIGNATURE))
            let digest := getCd_32(digestOffset)

            // Verify the signature
            invalidExpirationTime, invalidSignatureCount, invalidIndex, invalidMismatch, invalidUsedSigner := verifySingleMultisig(keyIndex, signatureCount, signaturesOffset, digest, buffer)
            invalidTotal := or(invalidSignatureCount, or(invalidExpirationTime, or(invalidIndex, or(invalidMismatch, invalidUsedSigner))))
            offset := add(digestOffset, LENGTH_WORD)
          }
          default {
            verificationFailed(MASK_VERIFY_RESULT_INVALID_VERSION)
          }
        }

        let invalidMessageLength := iszero(eq(calldatasize(), offset))
        invalidTotal := or(invalidTotal, invalidMessageLength)

        if invalidTotal {
          let flagInvalidExpirationTime := shl(SHIFT_VERIFY_RESULT_INVALID_EXPIRATION_TIME, invalidExpirationTime)
          let flagInvalidPubkey := shl(SHIFT_VERIFY_RESULT_INVALID_KEY, invalidPubkey)
          let flagInvalidSignature := shl(SHIFT_VERIFY_RESULT_INVALID_SIGNATURE, invalidSignature)
          let flagInvalidMismatch := shl(SHIFT_VERIFY_RESULT_SIGNATURE_MISMATCH, invalidMismatch)
          let flagInvalidSignatureCount := shl(SHIFT_VERIFY_RESULT_INVALID_SIGNATURE_COUNT, invalidSignatureCount)
          let flagInvalidUsedSigner := shl(SHIFT_VERIFY_RESULT_SIGNER_USED, invalidUsedSigner)
          let flagInvalidIndex := shl(SHIFT_VERIFY_RESULT_INVALID_SIGNER_INDEX, invalidIndex)

          let flags1 := or(flagInvalidExpirationTime, flagInvalidPubkey)
          let flags2 := or(flagInvalidSignature, flagInvalidMismatch)
          let flags3 := or(or(flagInvalidSignatureCount, flagInvalidUsedSigner), flagInvalidIndex)
          verificationFailed(or(flags1, or(flags2, flags3)))
        }
      }

      function verifyBatchMultisig() {
        // Format: [uint32 keyIndex, uint8 signatureCount, MultisigSignature[signatureCount] signatures, bytes32 digest][]
        let invalidExpirationTime := 0
        let invalidSignatureCount := 0
        let invalidIndex := 0
        let invalidMismatch := 0
        let invalidUsedSigner := 0
        let invalidTotal := 0

        let buffer := mload(PTR_FREE_MEMORY)
        let offset := OFFSET_BATCH_DATA

        for {} and(iszero(invalidTotal), lt(offset, calldatasize())) {} {
          let keyIndex := getCd_4(offset)
          let signatureCount := getCd_1(add(offset, OFFSET_BATCH_MULTISIG_SIGNATURE_COUNT))
          let signaturesOffset := add(offset, OFFSET_BATCH_MULTISIG_SIGNATURES)
          let digestOffset := add(signaturesOffset, mul(signatureCount, LENGTH_MULTISIG_SIGNATURE))
          let digest := getCd_32(digestOffset)

          // Verify the signature
          invalidExpirationTime, invalidSignatureCount, invalidIndex, invalidMismatch, invalidUsedSigner :=
            verifySingleMultisig(keyIndex, signatureCount, signaturesOffset, digest, buffer)
          invalidTotal := or(invalidSignatureCount, or(invalidExpirationTime, or(invalidIndex, or(invalidMismatch, invalidUsedSigner))))
          offset := add(digestOffset, LENGTH_WORD)
        }

        let invalidMessageLength := iszero(eq(calldatasize(), offset))
        invalidTotal := or(invalidTotal, invalidMessageLength)

        if invalidTotal {
          verificationFailedMultisig(invalidExpirationTime, invalidSignatureCount, invalidIndex, invalidMismatch, invalidUsedSigner, invalidMessageLength, offset)
        }
      }

      function verifyBatchSchnorr() {
        let invalidExpirationTime := 0
        let invalidPubkey := 0
        let invalidSignature := 0
        let invalidMismatch := 0
        let invalidTotal := 0

        let buffer := mload(PTR_FREE_MEMORY)
        let offset := OFFSET_BATCH_DATA

        for {} and(iszero(invalidTotal), lt(offset, calldatasize())) { offset := add(offset, LENGTH_BATCH_SCHNORR_ENTRY) } {
          // Decode the schnorr header and digest
          let keyIndex := getCd_4(offset)
          let r := getCd_20(add(offset, OFFSET_BATCH_SCHNORR_ENTRY_R))
          let s := getCd_32(add(offset, OFFSET_BATCH_SCHNORR_ENTRY_S))
          let digest := getCd_32(add(offset, OFFSET_BATCH_SCHNORR_ENTRY_DIGEST))

          // Verify the signature
          invalidExpirationTime, invalidPubkey, invalidSignature, invalidMismatch := verifySingleSchnorr(keyIndex, r, s, digest, buffer)
          invalidTotal := or(invalidExpirationTime, or(invalidPubkey, or(invalidSignature, invalidMismatch)))
        }

        let invalidMessageLength := iszero(eq(calldatasize(), offset))
        invalidTotal := or(invalidTotal, invalidMessageLength)

        if invalidTotal {
          verificationFailedSchnorr(invalidExpirationTime, invalidPubkey, invalidSignature, invalidMismatch, invalidMessageLength, offset)
        }
      }

      function verifyBatchECDSA() {
        let invalidExpirationTime := 0
        let invalidMismatch := 0
        let invalidTotal := 0

        let buffer := mload(PTR_FREE_MEMORY)
        let offset := OFFSET_BATCH_DATA

        for {} and(iszero(invalidTotal), lt(offset, calldatasize())) { offset := add(offset, LENGTH_BATCH_ECDSA_ENTRY) } {
          // Decode the schnorr header and digest
          let keyIndex := getCd_4(offset)
          let r := getCd_32(add(offset, OFFSET_BATCH_ECDSA_ENTRY_R))
          let s := getCd_32(add(offset, OFFSET_BATCH_ECDSA_ENTRY_S))
          let v := getCd_1(add(offset, OFFSET_BATCH_ECDSA_ENTRY_V))
          let digest := getCd_32(add(offset, OFFSET_BATCH_ECDSA_ENTRY_DIGEST))

          // Verify the signature
          invalidExpirationTime, invalidMismatch := verifySingleECDSA(keyIndex, r, s, v, digest, buffer)
          invalidTotal := or(invalidExpirationTime, invalidMismatch)
        }

        let invalidMessageLength := iszero(eq(calldatasize(), offset))
        invalidTotal := or(invalidTotal, invalidMessageLength)

        if invalidTotal {
          verificationFailedECDSA(invalidExpirationTime, invalidMismatch, invalidMessageLength, offset)
        }
      }

      function verifyBatchMultisigUniform() {
        // Decode the key index
        let keyIndex := getCd_4(OFFSET_BATCH_DATA)

        // Load the key data
        let keyDataAddress, expirationTime := getMultisigKeyData(keyIndex)
        let invalidExpirationTime := checkExpirationTime(expirationTime)

        // Load the key data contract
        let keyDataOffset := mload(PTR_FREE_MEMORY)
        let keyDataSize := getMultisigKeyDataFromContract(keyDataAddress, keyDataOffset)
        let keyCount := shr(LOG2_WORD_BYTES, keyDataSize)
        let quorum := div(shl(1, keyCount), 3) // Quorum when signatureCount > 2 * keycount / 3

        // Validate the entries
        let invalidSignatureCount := 0
        let invalidIndex := 0
        let invalidMismatch := 0
        let invalidUsedSigner := 0
        let invalidTotal := invalidExpirationTime
        
        let buffer := add(keyDataOffset, keyDataSize)
        let offset := OFFSET_BATCH_UNIFORM_DATA

        for {} and(iszero(invalidTotal), lt(offset, calldatasize())) {} {
          let signatureCount := getCd_1(offset)
          let signaturesOffset := add(offset, 1) // TODO: magic number
          let digestOffset := add(signaturesOffset, mul(signatureCount, LENGTH_MULTISIG_SIGNATURE))
          let digest := getCd_32(digestOffset)

          // Verify the signature
          invalidIndex, invalidMismatch, invalidUsedSigner := checkMultisigSignature(digest, signaturesOffset, signatureCount, keyDataOffset, keyCount, buffer)
          invalidSignatureCount := iszero(gt(signatureCount, quorum))
          invalidTotal := or(invalidSignatureCount, or(invalidIndex, or(invalidMismatch, invalidUsedSigner)))
          offset := add(digestOffset, LENGTH_WORD)
        }

        let invalidMessageLength := iszero(eq(calldatasize(), offset))
        invalidTotal := or(invalidTotal, invalidMessageLength)

        if invalidTotal {
          verificationFailedMultisig(invalidExpirationTime, invalidSignatureCount, invalidIndex, invalidMismatch, invalidUsedSigner, invalidMessageLength, offset)
        }
      }

      function verifyBatchSchnorrUniform() {
        // Decode the key index
        let keyIndex := getCd_4(OFFSET_BATCH_DATA)

        // Load the key data
        let px, parity := getSchnorrKeyData(keyIndex)
        let expirationTime := getSchnorrKeyExtra(keyIndex)
        let invalidExpirationTime := checkExpirationTime(expirationTime)

        // Validate the entries
        let invalidPubkey := 0
        let invalidSignature := 0
        let invalidMismatch := 0
        let invalidTotal := invalidExpirationTime

        let buffer := mload(PTR_FREE_MEMORY)
        let offset := OFFSET_BATCH_UNIFORM_DATA

        for {} and(iszero(invalidTotal), lt(offset, calldatasize())) { offset := add(offset, LENGTH_BATCH_SCHNORR_UNIFORM_ENTRY) } {
          let r := getCd_20(offset)
          let s := getCd_32(add(offset, OFFSET_BATCH_SCHNORR_UNIFORM_S))
          let digest := getCd_32(add(offset, OFFSET_BATCH_SCHNORR_UNIFORM_DIGEST))

          // Verify the signature
          invalidPubkey, invalidSignature, invalidMismatch := checkSchnorrSignature(px, parity, digest, r, s, buffer)
          invalidTotal := or(invalidPubkey, or(invalidSignature, invalidMismatch))
        }

        let invalidMessageLength := iszero(eq(calldatasize(), offset))
        invalidTotal := or(invalidTotal, invalidMessageLength)

        if invalidTotal {
          verificationFailedSchnorr(invalidExpirationTime, invalidPubkey, invalidSignature, invalidMismatch, invalidMessageLength, offset)
        }
      }

      function verifyBatchECDSAUniform() {
        // Decode the key index
        let keyIndex := getCd_4(OFFSET_BATCH_DATA)

        // Load the key data
        let pubkey, expirationTime := getECDSAKeyData(keyIndex)
        let invalidExpirationTime := checkExpirationTime(expirationTime)

        // Validate the entries
        let invalidMismatch := 0
        let invalidTotal := invalidExpirationTime

        let buffer := mload(PTR_FREE_MEMORY)
        let offset := OFFSET_BATCH_UNIFORM_DATA

        for {} and(iszero(invalidTotal), lt(offset, calldatasize())) { offset := add(offset, LENGTH_BATCH_ECDSA_ENTRY) } {
          // Decode the schnorr header and digest
          let r := getCd_32(add(offset, OFFSET_BATCH_ECDSA_ENTRY_R))
          let s := getCd_32(add(offset, OFFSET_BATCH_ECDSA_ENTRY_S))
          let v := getCd_1(add(offset, OFFSET_BATCH_ECDSA_ENTRY_V))
          let digest := getCd_32(add(offset, OFFSET_BATCH_ECDSA_ENTRY_DIGEST))

          // Verify the signature
          invalidMismatch := iszero(ecrecover(digest, r, s, v, buffer, pubkey))
          invalidTotal := or(invalidExpirationTime, invalidMismatch)
        }

        let invalidMessageLength := iszero(eq(calldatasize(), offset))
        invalidTotal := or(invalidTotal, invalidMessageLength)

        if invalidTotal {
          verificationFailedECDSA(invalidExpirationTime, invalidMismatch, invalidMessageLength, offset)
        }
      }

      function dispatchValidRange(opcode) {
        switch and(opcode, 4)
        case 0 {
          switch and(opcode, 2)
          case 0 {
            switch and(opcode, 1)
            case 0 {
              verifyBatch()
            }
            default {
              verifyBatchMultisig()
            }
          }
          default {
            switch and(opcode, 1)
            case 0 {
              verifyBatchSchnorr()
            }
            default {
              verifyBatchMultisigUniform()
            }
          }
        }
        default {
          switch and(opcode, 2)
          case 0 {
            switch and(opcode, 1)
            case 0 {
              verifyBatchSchnorrUniform()
            }
            default {
              verifyBatchECDSA()
            }
          }
          default {
            verifyBatchECDSAUniform()
          }
        }
      }

      // Dispatch
      let opcode := getCd_1(OFFSET_BATCH_OPCODE)
      switch gt(opcode, VERIFY_ECDSA_UNIFORM)
      case 0 {
        dispatchValidRange(opcode)
      }
      default {
        verificationFailed(MASK_VERIFY_RESULT_INVALID_OPCODE)
      }
    }
  }

  function get(bytes calldata data) external view returns (bytes memory) {
    unchecked {
      uint256 offset = 0;
      bytes memory result;

      while (offset < data.length) {
        uint8 opcode;

        (opcode, offset) = data.asUint8CdUnchecked(offset);

        if (opcode == GET_CURRENT_ECDSA_KEY_DATA) {
          uint32 index = _getECDSAKeyCount() - 1;
          (address pubkey, uint32 expirationTime) = _getECDSAKeyData(index);
          (uint40 shardBase, uint8 shardCount, uint32 multisigKeyIndex) = _getECDSAExtraData(index);

          result = abi.encodePacked(result, index, pubkey, expirationTime, shardBase, shardCount, multisigKeyIndex);
        } else if (opcode == GET_CURRENT_SCHNORR_KEY_DATA) {
          uint32 index = _getSchnorrKeyCount() - 1;
          uint256 pubkey = _getSchnorrKeyData(index);
          (uint32 expirationTime, uint8 shardCount, , uint32 multisigKeyIndex) = _getSchnorrExtraData(index);

          result = abi.encodePacked(result, index, pubkey, expirationTime, shardCount, multisigKeyIndex);
        } else if (opcode == GET_CURRENT_MULTISIG_KEY_DATA) {
          uint32 index = _getMultisigKeyCount() - 1;
          (address[] memory keys,) = _getMultisigKeyData(index);

          result = abi.encodePacked(result, uint32(index), uint8(keys.length), keys);
        } else if (opcode == GET_ECDSA_KEY_DATA) {
          uint32 index;
          (index, offset) = data.asUint32CdUnchecked(offset);

          (address pubkey, uint32 expirationTime) = _getECDSAKeyData(index);
          (uint40 shardBase, uint8 shardCount, uint32 multisigKeyIndex) = _getECDSAExtraData(index);

          result = abi.encodePacked(result, pubkey, expirationTime, shardBase, shardCount, multisigKeyIndex);
        } else if (opcode == GET_SCHNORR_KEY_DATA) {
          uint32 index;
          (index, offset) = data.asUint32CdUnchecked(offset);

          uint256 pubkey = _getSchnorrKeyData(index);
          (uint32 expirationTime, uint8 shardCount, , uint32 multisigKeyIndex) = _getSchnorrExtraData(index);

          result = abi.encodePacked(result, pubkey, expirationTime, shardCount, multisigKeyIndex);
        } else if (opcode == GET_MULTISIG_KEY_DATA) {
          uint32 index;
          (index, offset) = data.asUint32CdUnchecked(offset);

          (address[] memory keys, uint32 expirationTime) = _getMultisigKeyData(index);

          result = abi.encodePacked(result, uint8(keys.length), keys, expirationTime);
        } else if (opcode == GET_ECDSA_SHARD_DATA) {
          uint32 ecdsaKeyIndex;
          (ecdsaKeyIndex, offset) = data.asUint32CdUnchecked(offset);

          (uint40 shardBase, uint8 shardCount,) = _getECDSAExtraData(ecdsaKeyIndex);
          bytes memory shardData = _getShardDataExport(SLOT_ECDSA_SHARD_DATA, shardBase, shardCount);

          result = abi.encodePacked(result, shardCount, shardData);
        } else if (opcode == GET_SCHNORR_SHARD_DATA) {
          uint32 schnorrKeyIndex;
          (schnorrKeyIndex, offset) = data.asUint32CdUnchecked(offset);

          (, uint8 shardCount, uint40 shardBase,) = _getSchnorrExtraData(schnorrKeyIndex);
          bytes memory shardData = _getShardDataExport(SLOT_SCHNORR_SHARD_DATA, shardBase, shardCount);

          result = abi.encodePacked(result, shardCount, shardData);
        } else {
          revert GetFailed(offset | MASK_GET_RESULT_INVALID_OPCODE);
        }
      }

      require(offset == data.length, GetFailed(offset | MASK_GET_RESULT_INVALID_DATA_LENGTH));

      return result;
    }
  }

  function update(bytes calldata data) external {
    uint256 offset = 0;

    while (offset < data.length) {
      uint8 opcode;

      (opcode, offset) = data.asUint8CdUnchecked(offset);

      if (opcode == UPDATE_SET_SHARD_ID) {
        offset = _updateShardId(data, offset);
      } else if (opcode == UPDATE_APPEND_SCHNORR_KEY) {
        // The size here allows us to pass in just the slice of the VAA + shard data.
        bytes memory appendSchnorrKeyInstruction;
        (appendSchnorrKeyInstruction, offset) = data.sliceUint16PrefixedCdUnchecked(offset);
        _appendSchnorrKey(appendSchnorrKeyInstruction);
      } else if (opcode == UPDATE_PULL_MULTISIG_KEY_DATA) {
        uint32 limit;
        (limit, offset) = data.asUint32CdUnchecked(offset);
        _pullMultisigKeyData(limit);
      } else {
        revert UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_OPCODE);
      }
    }

    require(offset == data.length, UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_DATA_LENGTH));
  }

  // Update functions
  function _updateShardId(bytes calldata data, uint256 offset) internal returns (uint256 newOffset) {
    uint32 schnorrKeyIndex;
    uint32 nonce;
    bytes32 shardId;
    uint8 signerIndex;
    bytes32 r;
    bytes32 s;
    uint8 v;

    uint256 baseOffset = offset;
    (schnorrKeyIndex, offset) = data.asUint32CdUnchecked(offset);
    (nonce, offset) = data.asUint32CdUnchecked(offset);
    (shardId, offset) = data.asBytes32CdUnchecked(offset);
    (signerIndex, r, s, v, offset) = data.decodeGuardianSignatureCdUnchecked(offset);

    // We only allow registrations for the current threshold key
    require(schnorrKeyIndex + 1 == _getSchnorrKeyCount(), UpdateFailed(baseOffset | MASK_UPDATE_RESULT_INVALID_SCHNORR_KEY_INDEX));

    // Get the shard data range associated with the schnorr key
    (, uint8 shardCount, uint40 shardBase, uint32 multisigKeyIndex) = _getSchnorrExtraData(schnorrKeyIndex);
    require(signerIndex < shardCount, UpdateFailed(baseOffset | MASK_UPDATE_RESULT_INVALID_SIGNER_INDEX));

    (address[] memory keys,) = _getMultisigKeyData(multisigKeyIndex);

    address expected = keys[signerIndex];

    // Verify the signature
    // We're not doing replay protection with the signature itself so we don't care about
    // verifying only canonical (low s) signatures.
    bytes32 digest = getRegisterGuardianDigest(schnorrKeyIndex, nonce, shardId);
    address signatory = ecrecover(digest, v, r, s);
    require(signatory == expected, UpdateFailed(baseOffset | MASK_UPDATE_RESULT_SIGNATURE_MISMATCH));

    _useUnorderedNonce(schnorrKeyIndex, signerIndex, nonce, baseOffset);

    // Store the shard ID
    _setSchnorrShardId(shardBase, signerIndex, shardId);

    return offset;
  }

  function _verifyGovernanceMessage(bytes memory data, uint256 messageBodyLength) internal view returns (uint256 offset, uint32 multisigKeyIndex, uint8 signatureCount, bytes32 module, uint8 action) {
    unchecked {
      // Decode the VAA
      uint8 version;

      (version, offset) = data.asUint8MemUnchecked(offset);
      (multisigKeyIndex, offset) = data.asUint32MemUnchecked(offset);
      (signatureCount, offset) = data.asUint8MemUnchecked(offset);

      uint256 envelopeOffset = offset + signatureCount * LENGTH_MULTISIG_SIGNATURE;

      uint16 emitterChainId;
      bytes32 emitterAddress;
      uint16 payloadOffset;

      (bytes memory vaa,) = data.sliceMemUnchecked(0, envelopeOffset + VaaLib.ENVELOPE_SIZE + messageBodyLength);
      (emitterChainId, emitterAddress,, payloadOffset) = this.verify(vaa);
      (CoreBridgeVM memory parsedVM, bool valid,) = _coreBridge.parseAndVerifyVM(vaa);
      require(valid, GovernanceVaaVerificationFailure());

      offset = payloadOffset;
      (module, offset) = data.asBytes32MemUnchecked(envelopeOffset + VaaLib.ENVELOPE_SIZE);
      (action, offset) = data.asUint8MemUnchecked(offset);

      // Validate the relevant fields
      uint32 currentMultisigKeyIndex = _getMultisigKeyCount() - 1;
      (address[] memory multisigKeys,) = _getMultisigKeyData(currentMultisigKeyIndex);
      uint8 shardCount = uint8(multisigKeys.length);

      bool validVersion = version == 1;
      bool validMultisigKeyIndex = eagerAnd(multisigKeyIndex == currentMultisigKeyIndex, parsedVM.guardianSetIndex == currentMultisigKeyIndex);
      bool validSignatureCount = signatureCount == shardCount;
      bool validEmitterChainId = emitterChainId == CHAIN_ID_SOLANA;
      bool validEmitterAddress = emitterAddress == GOVERNANCE_ADDRESS;
      // NOTE: No need to check multisig expiration, since it's the current multisig key

      require(validVersion,          UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_VERSION));
      require(validMultisigKeyIndex, UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_MULTISIG_KEY_INDEX));
      require(validSignatureCount,   UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_SIGNATURE_COUNT));
      require(validEmitterChainId,   UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_GOVERNANCE_CHAIN));
      require(validEmitterAddress,   UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_GOVERNANCE_ADDRESS));
    }
  }

  function _appendShardData(bytes memory data, uint256 offset, uint256 shardSlot, uint32 keyIndex, uint8 signatureCount, bytes32 initialShardDataHash) internal {
    unchecked {
      bytes memory shardData;
      (shardData, offset) = data.sliceMemUnchecked(offset, uint256(signatureCount) << 6);

      bytes32 expectedHash = keccak256(shardData);
      require(expectedHash == initialShardDataHash, UpdateFailed(offset | MASK_UPDATE_RESULT_SHARD_DATA_MISMATCH));

      // Store the shard data
      (,, uint40 shardOffset,) = _getSchnorrExtraData(keyIndex);
      _storeShardDataBlock(shardSlot + shardOffset, shardData);

      // Bounds check on data read
      require(offset == data.length, UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_DATA_LENGTH));
    }
  }

  function _appendECDSAKey(bytes memory data) internal {
    unchecked {
      (uint256 offset, uint32 multisigKeyIndex, uint8 signatureCount, bytes32 module, uint8 action) = _verifyGovernanceMessage(data, LENGTH_APPEND_ECDSA_KEY_MESSAGE_BODY);
      require(module == MODULE_VERIFICATION_V2,  UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_MODULE));
      require(action == ACTION_APPEND_ECDSA_KEY, UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_ACTION));

      uint32 newECDSAKeyIndex;
      uint32 expectedMultisigKeyIndex;
      address newECDSAKey;
      uint32 expirationDelaySeconds;
      bytes32 initialShardDataHash;

      (newECDSAKeyIndex, offset) = data.asUint32MemUnchecked(offset);
      (expectedMultisigKeyIndex, offset) = data.asUint32MemUnchecked(offset);
      (newECDSAKey, offset) = data.asAddressMemUnchecked(offset);
      (expirationDelaySeconds, offset) = data.asUint32MemUnchecked(offset);
      (initialShardDataHash, offset) = data.asBytes32MemUnchecked(offset);

      // Validate the body of the message
      bool validKeyIndex = eagerAnd(newECDSAKeyIndex == _getECDSAKeyCount(), newECDSAKeyIndex < type(uint32).max);
      bool validMultisigKeyIndex = expectedMultisigKeyIndex == multisigKeyIndex;
      bool validPubkey = newECDSAKey != address(0);

      require(validKeyIndex, UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_KEY_INDEX));
      require(validMultisigKeyIndex, UpdateFailed(offset | MASK_UPDATE_RESULT_MULTISIG_KEY_INDEX_MISMATCH));
      require(validPubkey, UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_ECDSA_KEY));

      // If there is a previous ecdsa key that is now expired, store the expiration time
      if (newECDSAKeyIndex > 0) {
        uint32 newExpirationTime = uint32(block.timestamp) + expirationDelaySeconds;
        _setECDSAExpirationTime(newECDSAKeyIndex - 1, newExpirationTime);
      }

      // Store the new ecdsa key data
      _appendECDSAKeyData(newECDSAKey, multisigKeyIndex, signatureCount);

      // Read and validate the shard data
      _appendShardData(data, offset, SLOT_ECDSA_SHARD_DATA, newECDSAKeyIndex, signatureCount, initialShardDataHash);
    }
  }

  function _appendSchnorrKey(bytes memory data) internal {
    unchecked {
      (uint256 offset, uint32 multisigKeyIndex, uint8 signatureCount, bytes32 module, uint8 action) = _verifyGovernanceMessage(data, LENGTH_APPEND_SCHNORR_KEY_MESSAGE_BODY);
      require(module == MODULE_VERIFICATION_V2,    UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_MODULE));
      require(action == ACTION_APPEND_SCHNORR_KEY, UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_ACTION));

      uint32 newSchnorrKeyIndex;
      uint32 expectedMultisigKeyIndex;
      uint256 newSchnorrKey;
      uint32 expirationDelaySeconds;
      bytes32 initialShardDataHash;

      (newSchnorrKeyIndex, offset) = data.asUint32MemUnchecked(offset);
      (expectedMultisigKeyIndex, offset) = data.asUint32MemUnchecked(offset);
      (newSchnorrKey, offset) = data.asUint256MemUnchecked(offset);
      (expirationDelaySeconds, offset) = data.asUint32MemUnchecked(offset);
      (initialShardDataHash, offset) = data.asBytes32MemUnchecked(offset);

      // Validate the body of the message
      uint256 px = newSchnorrKey >> 1;
      bool validKeyIndex = eagerAnd(newSchnorrKeyIndex == _getSchnorrKeyCount(), newSchnorrKeyIndex < type(uint32).max);
      bool validPubkey = eagerAnd(px != 0, px < HALF_SECP256K1_ORDER_PLUS_ONE);
      bool validMultisigKeyIndex = expectedMultisigKeyIndex == multisigKeyIndex;

      require(validKeyIndex, UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_KEY_INDEX));
      require(validPubkey, UpdateFailed(offset | MASK_UPDATE_RESULT_INVALID_SCHNORR_KEY));
      require(validMultisigKeyIndex, UpdateFailed(offset | MASK_UPDATE_RESULT_MULTISIG_KEY_INDEX_MISMATCH));

      // If there is a previous schnorr key that is now expired, store the expiration time
      if (newSchnorrKeyIndex > 0) {
        uint32 newExpirationTime = uint32(block.timestamp) + expirationDelaySeconds;
        _setSchnorrExpirationTime(newSchnorrKeyIndex - 1, newExpirationTime);
      }

      // Store the new schnorr key data
      _appendSchnorrKeyData(newSchnorrKey, multisigKeyIndex, signatureCount);

      // Read and validate the shard data
      _appendShardData(data, offset, SLOT_SCHNORR_SHARD_DATA, newSchnorrKeyIndex, signatureCount, initialShardDataHash);
    }
  }

  function _pullMultisigKeyData(uint32 limit) internal {
    unchecked {
      // Get the current state
      uint256 currentMultisigKeyIndex = _coreBridge.getCurrentGuardianSetIndex();
      uint256 currentMultisigKeysLength = currentMultisigKeyIndex + 1;
      uint256 oldMultisigKeysLength = _getMultisigKeyCount();

      // If we've already pulled all the guardian sets, return
      if (currentMultisigKeysLength == oldMultisigKeysLength) return;

      // Check if we need to update the current guardian set
      if (oldMultisigKeysLength > 0) {
        // Pull and write the current guardian set expiration time
        uint32 updateIndex = uint32(oldMultisigKeysLength - 1);
        uint32 expirationTime = _coreBridge.getGuardianSet(updateIndex).expirationTime;
        _setMultisigExpirationTime(updateIndex, expirationTime);
      }

      // Calculate the upper bound of the guardian sets to pull
      uint256 upper = eagerOr(limit == 0, currentMultisigKeysLength - oldMultisigKeysLength < limit)
        ? currentMultisigKeysLength : oldMultisigKeysLength + limit;

      // Pull and append the guardian sets
      for (uint256 i = oldMultisigKeysLength; i < upper; i++) {
        // Pull the guardian set, write the expiration time, and append the guardian set data to the ExtStore
        GuardianSet memory guardians = _coreBridge.getGuardianSet(uint32(i));
        _appendMultisigKeyData(guardians.keys, guardians.expirationTime);
      }
    }
  }

  // Internal multisig state access functions
  function _getMultisigKeyCount() internal view returns (uint32 result) {
    assembly ("memory-safe") {
      result := sload(SLOT_MULTISIG_KEY_COUNT)
    }
  }

  function _updateMultisigKeyCount(uint32 count) internal {
    assembly ("memory-safe") {
      sstore(SLOT_MULTISIG_KEY_COUNT, count)
    }
  }

  function _getMultisigKeyData(uint32 index) internal view returns (
    address[] memory keys,
    uint32 expirationTime
  ) {
    // Load and decode the multisig key data entry
    uint256 multisigDataSlot = SLOT_MULTISIG_KEY_DATA + index;
    uint256 entry;
    assembly ("memory-safe") { entry := sload(multisigDataSlot) }
    expirationTime = uint32(entry & MASK_MULTISIG_ENTRY_EXPIRATION_TIME);

    // Load the key data contract, validate the size
    address keyDataAddress = address(uint160(entry >> SHIFT_MULTISIG_ENTRY_ADDRESS));
    uint256 keyDataSize = keyDataAddress.code.length;
    require (keyDataSize > 0, UnknownGuardianSet(index));

    // Copy the value to memory
    bytes memory keysBuffer = SSTORE2.read(keyDataAddress);

    uint256 size = keyDataSize - OFFSET_MULTISIG_CONTRACT_DATA;
    uint256 keyCount = size / LENGTH_WORD;
    keys = new address[](keyCount);

    uint256 offset = 0;
    for (uint i = 0; i < keyCount; ++i) {
      address key;
      // each key is padded to 32 bytes
      (key, offset) = keysBuffer.asAddressMemUnchecked(offset + 12);

      keys[i] = key;
    }
  }

  function _setMultisigExpirationTime(uint256 index, uint32 expirationTime) internal {
    uint256 multisigKeySlot = SLOT_MULTISIG_KEY_DATA + index;
    uint256 oldEntry;
    assembly ("memory-safe") { oldEntry := sload(multisigKeySlot) }

    uint256 newEntry = (oldEntry & ~MASK_MULTISIG_ENTRY_EXPIRATION_TIME) | expirationTime;
    assembly ("memory-safe") { sstore(multisigKeySlot, newEntry) }
  }

  // Append a new multisig key data entry and creates the corresponding contract
  function _appendMultisigKeyData(address[] memory keys, uint32 expirationTime) internal {
    bytes memory keysBuffer = new bytes(keys.length * LENGTH_WORD);
    for (uint i = 0; i < keys.length; ++i) {
      address key = keys[i];
      uint256 offset = (i + 1) * LENGTH_WORD;
      assembly ("memory-safe") { mstore(add(keysBuffer, offset), key) }
    }

    address deployedAddress = SSTORE2.write(keysBuffer);

    // Store the entry in the storage array
    uint32 index = _getMultisigKeyCount();
    bytes32 entry =
      bytes32(uint256(uint160(deployedAddress)) << SHIFT_MULTISIG_ENTRY_ADDRESS)
      | bytes32(uint256(expirationTime));

    uint256 multisigKeyDataPtr = SLOT_MULTISIG_KEY_DATA + index;
    assembly ("memory-safe") { sstore(multisigKeyDataPtr, entry) }
    _updateMultisigKeyCount(index + 1);
  }

  // Internal schnorr state access functions
  function _getSchnorrKeyCount() internal view returns (uint32 result) {
    assembly ("memory-safe") {
      result := sload(SLOT_SCHNORR_KEY_COUNT)
    }
  }

  function _updateSchnorrKeyCount(uint32 count) internal {
    assembly ("memory-safe") {
      sstore(SLOT_SCHNORR_KEY_COUNT, count)
    }
  }

  function _getSchnorrKeyData(uint32 index) internal view returns (uint256 pubkey) {
    assembly ("memory-safe") {
      pubkey := sload(add(SLOT_SCHNORR_KEY_DATA, index))
    }
  }

  function _getSchnorrExtraData(uint32 index) internal view returns (uint32 expirationTime, uint8 shardCount, uint40 shardBase, uint32 multisigKeyIndex) {
    uint256 extraDataSlot = SLOT_SCHNORR_EXTRA_DATA + index;
    uint256 storageWord;
    assembly ("memory-safe") { storageWord := sload(extraDataSlot) }

    expirationTime   = uint32( storageWord                                           & MASK_SCHNORR_EXTRA_EXPIRATION_TIME);
    shardCount       = uint8 ((storageWord >> SHIFT_SCHNORR_EXTRA_SHARD_COUNT)       & MASK_SCHNORR_EXTRA_SHARD_COUNT    );
    shardBase        = uint40((storageWord >> SHIFT_SCHNORR_EXTRA_SHARD_BASE )       & MASK_SCHNORR_EXTRA_SHARD_BASE     );
    multisigKeyIndex = uint32( storageWord >> SHIFT_SCHNORR_EXTRA_MULTISIG_KEY_INDEX                                     );
  }

  function _getShardDataExport(uint256 shardDataSlot, uint40 shardBase, uint8 shardCount) internal view returns (bytes memory shardData) {
    // 32 bytes for the shard + 32 for the ID
    uint256 entries = shardCount * 2;
    shardData = new bytes(entries * LENGTH_WORD);

    for (uint i = 0; i < entries; ++i) {
      uint256 memoryOffset = (i + 1) * LENGTH_WORD;
      uint256 readSlot = shardDataSlot + shardBase + i * LENGTH_WORD;
      assembly ("memory-safe") {
        let entry := sload(readSlot)
        mstore(add(shardData, memoryOffset), entry)
      }
    }
  }

  function _setSchnorrExpirationTime(uint32 index, uint32 expirationTime) internal {
    uint256 schnorrDataSlot = SLOT_SCHNORR_EXTRA_DATA + index;
    uint256 oldEntry;
    assembly ("memory-safe") { oldEntry := sload(schnorrDataSlot) }

    uint256 newEntry = (oldEntry & ~MASK_SCHNORR_EXTRA_EXPIRATION_TIME) | expirationTime;
    assembly ("memory-safe") { sstore(schnorrDataSlot, newEntry) }
  }

  function _setSchnorrShardId(uint40 shardBase, uint8 signerIndex, bytes32 newSchnorrId) internal {
    uint256 shardIdSlot = SLOT_SCHNORR_SHARD_DATA + shardBase + (signerIndex * 2 + 1) * LENGTH_WORD;
    assembly ("memory-safe") {
      sstore(shardIdSlot, newSchnorrId)
    }
  }
  
  function _appendSchnorrKeyData(uint256 pubkey, uint32 multisigKeyIndex, uint8 shardCount) internal {
    uint32 keyIndex = _getSchnorrKeyCount();
    // Append the key data
    uint256 pubkeySlot = SLOT_SCHNORR_KEY_DATA + keyIndex;
    assembly ("memory-safe") { sstore(pubkeySlot, pubkey) }

    uint40 shardBase;
    assembly ("memory-safe") { shardBase := sload(SLOT_SCHNORR_SHARD_COUNT) }

    // Append the extra data
    uint256 extraInfo =
        uint256(shardCount      ) << SHIFT_SCHNORR_EXTRA_SHARD_COUNT
      | uint256(shardBase       ) << SHIFT_SCHNORR_EXTRA_SHARD_BASE
      | uint256(multisigKeyIndex) << SHIFT_SCHNORR_EXTRA_MULTISIG_KEY_INDEX;

    uint256 extraDataSlot = SLOT_SCHNORR_EXTRA_DATA + keyIndex;
    assembly ("memory-safe") { sstore(extraDataSlot, extraInfo) }

    // Update the lengths
    uint256 newShardBase = shardBase + (uint256(shardCount) << 1);
    assembly ("memory-safe") { sstore(SLOT_SCHNORR_SHARD_COUNT, newShardBase) }
    _updateSchnorrKeyCount(keyIndex + 1);
  }

  function _storeShardDataBlock(uint256 shardSlot, bytes memory shardData) internal {
    uint256 entries = shardData.length / LENGTH_WORD;
    for (uint i = 0; i < entries; ++i) {
      uint256 memoryOffset = (i + 1) * LENGTH_WORD;
      uint256 writeSlot = shardSlot + i * LENGTH_WORD;
      assembly ("memory-safe") {
        let entry := mload(add(shardData, memoryOffset))
        sstore(writeSlot, entry)
      }
    }
  }

  // Internal ecdsa state access functions
  // TODO: We could save some space by factoring out the common code between the schnorr and ecdsa methods,
  //       but it's not worth it unless we need more code space
  function _getECDSAKeyCount() internal view returns (uint32 result) {
    assembly ("memory-safe") {
      result := sload(SLOT_ECDSA_KEY_COUNT)
    }
  }

  function _updateECDSAKeyCount(uint32 count) internal {
    assembly ("memory-safe") {
      sstore(SLOT_ECDSA_KEY_COUNT, count)
    }
  }

  function _getECDSAKeyData(uint32 index) internal view returns (address pubkey, uint32 expirationTime) {
    assembly ("memory-safe") {
      let entry := sload(add(SLOT_ECDSA_KEY_DATA, index))
      expirationTime := and(entry, MASK_ECDSA_ENTRY_EXPIRATION_TIME)
      pubkey := shr(SHIFT_ECDSA_ENTRY_PUBKEY, entry)
    }
  }

  function _getECDSAExtraData(uint32 index) internal view returns (
    uint40 shardBase,
    uint8 shardCount,
    uint32 multisigKeyIndex
  ) {
    assembly ("memory-safe") {
      let entry := sload(add(SLOT_ECDSA_EXTRA_DATA, index))
      shardBase := and(entry, MASK_ECDSA_ENTRY_SHARD_BASE)
      shardCount := and(shr(SHIFT_ECDSA_ENTRY_SHARD_COUNT, entry), MASK_ECDSA_ENTRY_SHARD_COUNT)
      multisigKeyIndex := shr(SHIFT_ECDSA_ENTRY_MULTISIG_KEY_INDEX, entry)
    }
  }

  function _setECDSAExpirationTime(uint32 index, uint32 expirationTime) internal {
    uint256 ecdsaDataSlot = SLOT_ECDSA_KEY_DATA + index;
    uint256 oldEntry;
    assembly ("memory-safe") { oldEntry := sload(ecdsaDataSlot) }

    uint256 newEntry = (oldEntry & ~MASK_ECDSA_ENTRY_EXPIRATION_TIME) | expirationTime;
    assembly ("memory-safe") { sstore(ecdsaDataSlot, newEntry) }
  }

  function _appendECDSAKeyData(address pubkey, uint32 multisigKeyIndex, uint8 shardCount) internal {
    uint32 keyIndex = _getECDSAKeyCount();
    // Append the key data
    uint256 pubkeySlot = SLOT_ECDSA_KEY_DATA + keyIndex;
    assembly ("memory-safe") { sstore(pubkeySlot, pubkey) }

    uint40 shardBase;
    assembly ("memory-safe") { shardBase := sload(SLOT_ECDSA_SHARD_COUNT) }

    // Append the extra data
    uint256 extraInfo = shardBase
      | (uint256(shardCount) << SHIFT_ECDSA_ENTRY_SHARD_COUNT)
      | (uint256(multisigKeyIndex) << SHIFT_ECDSA_ENTRY_MULTISIG_KEY_INDEX);

    uint256 extraDataSlot = SLOT_ECDSA_EXTRA_DATA + keyIndex;
    assembly ("memory-safe") { sstore(extraDataSlot, extraInfo) }

    // Update the lengths
    uint256 newShardBase = shardBase + (uint256(shardCount) << 1);
    assembly ("memory-safe") { sstore(SLOT_ECDSA_SHARD_COUNT, newShardBase) }
    _updateECDSAKeyCount(keyIndex + 1);
  }

  function _useUnorderedNonce(uint32 keyIndex, uint8 signerIndex, uint32 nonce, uint256 baseOffset) internal {
    uint256 nonceSlot = SLOT_NONCE_BITMAP | (keyIndex << 32) | (signerIndex << 24) | (nonce >> 8);
    uint256 oldEntry;
    assembly ("memory-safe") { oldEntry := sload(nonceSlot) }

    uint256 bit = 1 << (nonce & 0xFF);
    require(oldEntry & bit == 0, UpdateFailed(baseOffset | MASK_UPDATE_RESULT_NONCE_ALREADY_CONSUMED));

    uint256 newEntry = oldEntry | bit;
    assembly ("memory-safe") { sstore(nonceSlot, newEntry) }
  }
}
