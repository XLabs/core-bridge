import assert from "assert"

import * as anchor from "@coral-xyz/anchor"
import { ComputeBudgetProgram, Keypair, PublicKey } from "@solana/web3.js"
import { keccak256, toUniversal, UniversalAddress } from "@wormhole-foundation/sdk-definitions"
import { Chain, encoding, serializeLayout } from "@wormhole-foundation/sdk-base"
import { randomBytes } from "@noble/hashes/utils"
import { secp256k1 } from "@noble/curves/secp256k1"

import { VerificationV2 } from "../target/types/verification_v2.js"

import { guardianAddress, TestingWormholeCore } from "./testing-wormhole-core.js"
import { WormholeContracts, TestsHelper, expectFailure } from "./testing_helpers.js"
import { inspect } from "util"
import { appendSchnorrKeyMessageLayout, appendECDSAKeyMessageLayout, HeaderV2, headerV2Layout, HeaderV3, headerV3Layout } from "./layouts.js"


interface SchnorrKeyMessage {
  keyIndex: number;
  publicKey: Uint8Array;
  previousSetExpirationTime: number;
  expectedMssIndex?: number;
}

interface InitSchnorrKey extends SchnorrKeyMessage {
  operation: "InitSchnorrKey";
}

interface AppendSchnorrKey extends SchnorrKeyMessage {
  operation: "AppendSchnorrKey";
  oldKeyIndex: number;
}

interface AddKeyTest {
  name: string;
  test: InitSchnorrKey | AppendSchnorrKey;
  extraMessageData?: string | Uint8Array;
  expectFailureHandler?: (error: Error) => void | Promise<void>;
}

const $ = new TestsHelper()

export const createAppendSchnorrKeyMessage = ({
  keyIndex,
  publicKey,
  previousSetExpirationTime,
  expectedMssIndex = 0,
}: SchnorrKeyMessage) => serializeLayout(appendSchnorrKeyMessageLayout, {
  schnorrKeyIndex: keyIndex,
  schnorrKey: publicKey,
  expirationDelaySeconds: previousSetExpirationTime,
  expectedMssIndex,
  shardDataHash: randomBytes(32),
})

interface ECDSAKeyMessage {
  keyIndex: number;
  address: Uint8Array;
  previousSetExpirationTime: number;
  expectedMssIndex?: number;
}

interface InitECDSAKey extends ECDSAKeyMessage {
  operation: "InitECDSAKey";
}

interface AppendECDSAKey extends ECDSAKeyMessage {
  operation: "AppendECDSAKey";
  oldKeyIndex: number;
}

interface AddECDSAKeyTest {
  name: string;
  test: InitECDSAKey | AppendECDSAKey;
  extraMessageData?: string | Uint8Array;
  expectFailureHandler?: (error: Error) => void | Promise<void>;
}

export const createAppendECDSAKeyMessage = ({
  keyIndex,
  address,
  previousSetExpirationTime,
  expectedMssIndex = 0,
}: ECDSAKeyMessage) => serializeLayout(appendECDSAKeyMessageLayout, {
  ecdsaKeyIndex: keyIndex,
  ecdsaKey: address,
  expirationDelaySeconds: previousSetExpirationTime,
  expectedMssIndex,
  shardDataHash: randomBytes(32),
})

const testSchnorrKey = encoding.bignum.toBytes(
  0xc11b6c8b8e4ecc62ebf10437678eb70f17f1e53abdb3fa8df1912e3b3d11b5b9n, 32
);

// Generate a valid ECDSA signature for testing
function generateECDSASignature(message: Uint8Array, privateKey: Uint8Array) {
  // Get the public key from private key (uncompressed, 65 bytes starting with 0x04)
  const publicKey = secp256k1.getPublicKey(privateKey, false)
  
  // Compute Ethereum address from keccak256 of X||Y (drop the 0x04 prefix)
  const pubkeyNoPrefix = publicKey.length === 65 && publicKey[0] === 4 ? publicKey.slice(1) : publicKey
  const address = keccak256(pubkeyNoPrefix).slice(12)
  
  // Sign the message
  const signature = secp256k1.sign(message, privateKey)
  
  // Convert to VAA format (r, s, v)
  const r = signature.r
  const s = signature.s
  const v = signature.recovery // Use recovery ID directly (0 or 1)
  
  return {
    address,
    signature: {
      r: encoding.bignum.toBytes(r, 32),
      s: encoding.bignum.toBytes(s, 32),
      v: v
    }
  }
}

// Test private key for generating signatures
const testPrivateKey = encoding.hex.decode("0x4c0883a69102937d6231471b5dbb1522082c6c3e3e3e3e3e3e3e3e3e3e3e3e3e")

// Generate test data
const testMessage = new Uint8Array(100) // 100 zero bytes
const testDigest = keccak256(keccak256(testMessage)) // Double hash as used in VAA

const ecdsaTestData = generateECDSASignature(testDigest, testPrivateKey)
const testECDSAAddress = ecdsaTestData.address

// Generate signature for the VAA body (same as Schnorr)
// For ECDSA, we compute digest from body only, not the full message
const bodyDigest = keccak256(keccak256(testMessage))
const ecdsaVaaTestData = generateECDSASignature(bodyDigest, testPrivateKey)

const validECDSASignatureTest = ecdsaVaaTestData.signature

const invalidECDSASignature = {
  r: encoding.hex.decode("0x1111111111111111111111111111111111111111111111111111111111111111"),
  s: encoding.hex.decode("0x2222222222222222222222222222222222222222222222222222222222222222"),
  v: 1
}

const signatureTestMessage100Zeroed = {
  r: encoding.hex.decode("0x41CF8d30EBCc800b655eAD15cC96014d36c4246B"),
  s: encoding.hex.decode("0xfb5fa64887c4a05818b02afa7483e5115f19a93739c4b9ce4e92bae191a2ef4b"),
}

const invalidSignature = {
  r: encoding.hex.decode("0xE46Df5BEa4597CEF7D346EfF36356A3F0bA33a56"),
  s: encoding.hex.decode("0x1c2d1ca6fd3830e653d6abfc57956f3700059a661d8cabae684ea1bc62294e4c"),
}

const getDeserializedHeaderTestMessage100Zeroed = (schnorrKeyIndex: number): HeaderV2 => ({
  schnorrKeyIndex: schnorrKeyIndex,
  signature: signatureTestMessage100Zeroed,
})

const getDeserializedHeaderTestMessageInvalidSignature = (schnorrKeyIndex: number): HeaderV2 => ({
  schnorrKeyIndex: schnorrKeyIndex,
  signature: invalidSignature,
})

const getHeaderTestMessage100Zeroed = (schnorrKeyIndex: number): Uint8Array =>
  serializeLayout(headerV2Layout, getDeserializedHeaderTestMessage100Zeroed(schnorrKeyIndex))

const getHeaderTestMessageInvalidSignature = (schnorrKeyIndex: number): Uint8Array =>
  serializeLayout(headerV2Layout, getDeserializedHeaderTestMessageInvalidSignature(schnorrKeyIndex))

const getDeserializedHeaderECDSATestMessage = (ecdsaKeyIndex: number): HeaderV3 => ({
  ecdsaKeyIndex: ecdsaKeyIndex,
  signature: validECDSASignatureTest,
})

const getDeserializedHeaderECDSATestMessageInvalidSignature = (ecdsaKeyIndex: number): HeaderV3 => ({
  ecdsaKeyIndex: ecdsaKeyIndex,
  signature: invalidECDSASignature,
})

const getHeaderECDSATestMessage = (ecdsaKeyIndex: number): Uint8Array =>
  serializeLayout(headerV3Layout, getDeserializedHeaderECDSATestMessage(ecdsaKeyIndex))

const getHeaderECDSATestMessageInvalidSignature = (ecdsaKeyIndex: number): Uint8Array =>
  serializeLayout(headerV3Layout, getDeserializedHeaderECDSATestMessageInvalidSignature(ecdsaKeyIndex))

const getTestMessage100Zeroed = (schnorrKeyIndex: number) => Uint8Array.from([
  ...getHeaderTestMessage100Zeroed(schnorrKeyIndex),
  ...new Uint8Array(100)
])

const getTestMessageInvalidSignature = (schnorrKeyIndex: number) => Uint8Array.from([
  ...getHeaderTestMessageInvalidSignature(schnorrKeyIndex),
  ...new Uint8Array(100)
])

const getTestECDSAMessage100Zeroed = (ecdsaKeyIndex: number) => Uint8Array.from([
  ...getHeaderECDSATestMessage(ecdsaKeyIndex),
  ...new Uint8Array(100)
])

const getTestECDSAMessageInvalidSignature = (ecdsaKeyIndex: number) => Uint8Array.from([
  ...getHeaderECDSATestMessageInvalidSignature(ecdsaKeyIndex),
  ...new Uint8Array(100)
])

const vaaDigest = (vaaBody: Uint8Array) => keccak256(keccak256(vaaBody));


// ------------------------------------------------------------------------------------------------


describe("VerificationV2", function() {
  const coreV1Address = new PublicKey('worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth')
  const guardianSetExpirationTime = 86400
  const fee = 100
  const txSigner = $.keypair.generate()
  let coreV1: TestingWormholeCore<"Devnet">
  const connection = $.connection
  let payer: Keypair;
  const coreV2 = anchor.workspace.VerificationV2 as anchor.Program<VerificationV2>
  const testKeyIndex = 2

  let fakeCoreV1: TestingWormholeCore<"Devnet">


  function deriveSchnorrKeyPda(schnorrKeyIndex: number) {
    // Buffer write already checks that the value is within bounds
    if (!Number.isSafeInteger(schnorrKeyIndex)) {
      throw new Error(`invalid non integer Schnorr index ${schnorrKeyIndex}`)
    }

    const schnorrKeyIndexBuf = Buffer.alloc(4)
    schnorrKeyIndexBuf.writeUint32LE(schnorrKeyIndex)

    // See impl SeedPrefix for SchnorrKeyAccount
    const seeds = [Buffer.from("schnorrkey"), schnorrKeyIndexBuf]

    return PublicKey.findProgramAddressSync(
      seeds,
      coreV2.programId
    )
  }

  function deriveECDSAKeyPda(ecdsaKeyIndex: number) {
    // Buffer write already checks that the value is within bounds
    if (!Number.isSafeInteger(ecdsaKeyIndex)) {
      throw new Error(`invalid non integer ECDSA index ${ecdsaKeyIndex}`)
    }

    const ecdsaKeyIndexBuf = Buffer.alloc(4)
    ecdsaKeyIndexBuf.writeUint32LE(ecdsaKeyIndex)

    // See impl SeedPrefix for ECDSAKeyAccount
    const seeds = [Buffer.from("ecdsakey"), ecdsaKeyIndexBuf]

    return PublicKey.findProgramAddressSync(
      seeds,
      coreV2.programId
    )
  }

  function deriveLatestSchnorrKeyPda() {
    // See impl SeedPrefix for LatestSchnorrKeyAccount
    const seeds = [Buffer.from("latestschnorrkey")]

    return PublicKey.findProgramAddressSync(
      seeds,
      coreV2.programId
    )
  }

  function deriveLatestECDSAKeyPda() {
    // See impl SeedPrefix for LatestECDSAKeyAccount
    const seeds = [Buffer.from("latestecdsakey")]

    return PublicKey.findProgramAddressSync(
      seeds,
      coreV2.programId
    )
  }

  function postVaaV1(
    message: Uint8Array,
    core = coreV1,
    emitter = {
      chain: "Solana" as Chain,
      emitterAddress: new UniversalAddress("0000000000000000000000000000000000000000000000000000000000000004", "hex"),
    }
  ) {
    return core.postVaa(
      payer,
      emitter,
      message,
    )
  }

  function addKeyTest({
    name,
    test,
    extraMessageData,
    expectFailureHandler,
  }: AddKeyTest) {
    it(name, async () => {
      let message = createAppendSchnorrKeyMessage(test)
      if (extraMessageData !== undefined) {
        message = Uint8Array.from([...message, ...extraMessageData])
      }

      const {postedVaa: postedVaaAddress, signatureSet} = await postVaaV1(message)

      let ix
      if (test.operation === "InitSchnorrKey") {
        ix = await coreV2.methods.appendSchnorrKey().accountsPartial({
          vaa: postedVaaAddress,
          signatureSet,
          newSchnorrKey: deriveSchnorrKeyPda(test.keyIndex)[0],
          oldSchnorrKey: null,
        }).instruction()
      } else {
        ix = await coreV2.methods.appendSchnorrKey().accountsPartial({
          vaa: postedVaaAddress,
          signatureSet,
          newSchnorrKey: deriveSchnorrKeyPda(test.keyIndex)[0],
          oldSchnorrKey: deriveSchnorrKeyPda(test.oldKeyIndex)[0],
        }).instruction()
      }

      if (expectFailureHandler !== undefined) {
        return expectFailure(
          () => $.sendAndConfirm(ix, payer),
          expectFailureHandler
        )
      } else {
        return $.sendAndConfirm(ix, payer)
      }
    })
  }

  function addECDSAKeyTest({
    name,
    test,
    extraMessageData,
    expectFailureHandler,
  }: AddECDSAKeyTest) {
    it(name, async () => {
      let message = createAppendECDSAKeyMessage(test)
      if (extraMessageData !== undefined) {
        message = Uint8Array.from([...message, ...extraMessageData])
      }

      const {postedVaa: postedVaaAddress, signatureSet} = await postVaaV1(message)

      let ix
      if (test.operation === "InitECDSAKey") {
        ix = await coreV2.methods.appendEcdsaKey().accountsPartial({
          vaa: postedVaaAddress,
          signatureSet,
          latestEcdsaKey: deriveLatestECDSAKeyPda()[0],
          newEcdsaKey: deriveECDSAKeyPda(test.keyIndex)[0],
          oldEcdsaKey: null,
        }).instruction()
      } else {
        ix = await coreV2.methods.appendEcdsaKey().accountsPartial({
          vaa: postedVaaAddress,
          signatureSet,
          latestEcdsaKey: deriveLatestECDSAKeyPda()[0],
          newEcdsaKey: deriveECDSAKeyPda(test.keyIndex)[0],
          oldEcdsaKey: deriveECDSAKeyPda(test.oldKeyIndex)[0],
        }).instruction()
      }

      if (expectFailureHandler !== undefined) {
        return expectFailure(
          () => $.sendAndConfirm(ix, payer),
          expectFailureHandler
        )
      } else {
        return $.sendAndConfirm(ix, payer)
      }
    })
  }

  before(async function() {
    payer = anchor.getProvider().wallet?.payer!
    assert(payer, "Payer not found")

    await $.airdrop([
      txSigner.publicKey,
      payer.publicKey,
    ]);

    const wormholeContracts = new WormholeContracts();

    coreV1 = new TestingWormholeCore(
      txSigner,
      connection,
      wormholeContracts.network,
      coreV1Address,
      wormholeContracts.addresses,
    );

    let txid = await coreV1.initialize(undefined, guardianSetExpirationTime, fee)
    let tx = await $.getTransaction(txid)

    const fakeWormholeContracts = new WormholeContracts("fake-wormhole-core-v1");

    fakeCoreV1 = new TestingWormholeCore(
      txSigner,
      connection,
      fakeWormholeContracts.network,
      coreV1Address,
      fakeWormholeContracts.addresses,
    );

    txid = await fakeCoreV1.initialize(undefined, guardianSetExpirationTime, fee)
    tx = await $.getTransaction(txid)
  });

  it("Check correct core v1 setup", async function() {
    const accounts = await connection.getProgramAccounts(coreV1Address)
    assert(accounts.length === 2, "Expected 2 accounts")

    const guardianSetIndex = await coreV1.client.getGuardianSetIndex()
    assert(guardianSetIndex === 0, "Expected guardian set index to be 0")
    const guardianSet = await coreV1.client.getGuardianSet(guardianSetIndex);

    const queriedFee = await coreV1.client.getMessageFee();
    assert(queriedFee === BigInt(fee), "Expected fee to be 100")

    assert(guardianSet.index === 0, "Expected guardian set index to be 0")
    assert(guardianSet.keys.length === 1, "Expected guardian set keys to have length 1")

    const queriedGuardian = new UniversalAddress(guardianSet.keys[0], "hex")
    const expectedGuardian = toUniversal("Ethereum", guardianAddress)
    assert(queriedGuardian.equals(expectedGuardian), "Expected guardian set keys to be the devnet guardian")
  });

  ([
    {
      name: "Posts invalid init append Schnorr key VAA and fails",
      test: {
        operation: "InitSchnorrKey",
        keyIndex: 0,
        publicKey: generateMockPubkey(),
        previousSetExpirationTime: guardianSetExpirationTime,
      },
      extraMessageData: "junkdata",
      expectFailureHandler: expectInvalidPayload,
    },
    {
      name: "Posts init append Schnorr key VAA successfully",
      test: {
        operation: "InitSchnorrKey",
        keyIndex: 0,
        publicKey: generateMockPubkey(),
        previousSetExpirationTime: guardianSetExpirationTime,
      },
    },
    {
      name: "Posts invalid append Schnorr key VAA and fails",
      test: {
        operation: "AppendSchnorrKey",
        keyIndex: 1,
        publicKey: generateMockPubkey(),
        previousSetExpirationTime: guardianSetExpirationTime,
        oldKeyIndex: 0,
      },
      extraMessageData: "junkdata",
      expectFailureHandler: expectInvalidPayload,
    },
    {
      name: "Posts append Schnorr key VAA successfully",
      test: {
        operation: "AppendSchnorrKey",
        keyIndex: 1,
        publicKey: generateMockPubkey(),
        previousSetExpirationTime: guardianSetExpirationTime,
        oldKeyIndex: 0,
      }
    },
    {
      name: "Fails to append Schnorr key when skipping indices",
      test: {
        operation: "AppendSchnorrKey",
        keyIndex: 5,
        publicKey: testSchnorrKey,
        previousSetExpirationTime: guardianSetExpirationTime,
        oldKeyIndex: 1,
      },
      expectFailureHandler: expectNewKeyIndexNotDirectSuccessor,
    },
    {
      name: "Appends a third Schnorr key",
      test: {
        operation: "AppendSchnorrKey",
        keyIndex: testKeyIndex,
        publicKey: testSchnorrKey,
        previousSetExpirationTime: guardianSetExpirationTime,
        oldKeyIndex: 1,
      }
    },
    {
      name: "Fails to append Schnorr key when referencing an old key",
      test: {
        operation: "AppendSchnorrKey",
        keyIndex: testKeyIndex,
        publicKey: testSchnorrKey,
        previousSetExpirationTime: guardianSetExpirationTime,
        oldKeyIndex: testKeyIndex - 1,
      },
      expectFailureHandler: expectAllocateAccountError(deriveSchnorrKeyPda(testKeyIndex)[0].toBase58()),
    },
    {
      name: "Fails to append invalid Schnorr key",
      test: {
        operation: "AppendSchnorrKey",
        keyIndex: testKeyIndex + 1,
        publicKey: generateInvalidMockPubkey(),
        previousSetExpirationTime: guardianSetExpirationTime,
        oldKeyIndex: testKeyIndex,
      },
      expectFailureHandler: expectInvalidSchnorrKey,
    },
    {
      name: "Fails to append Schnorr key before the new guardian set is submitted",
      test: {
        operation: "AppendSchnorrKey",
        keyIndex: testKeyIndex + 1,
        publicKey: testSchnorrKey,
        previousSetExpirationTime: guardianSetExpirationTime,
        oldKeyIndex: testKeyIndex,
        expectedMssIndex: 1,
      },
      expectFailureHandler: expectInvalidGuardianSet,
    },
  ] satisfies AddKeyTest[]).map((test) => addKeyTest(test));

  [{
    name: "Fails to append Schnorr key when emitter chain is not Solana",
    emitter: {
      chain: "Ethereum",
      emitterAddress: new UniversalAddress("0x0000000000000000000000000000000000000000000000000000000000000004"),
    } as const,
    test: {
      keyIndex: testKeyIndex + 1,
      publicKey: testSchnorrKey,
      previousSetExpirationTime: guardianSetExpirationTime,
      oldKeyIndex: testKeyIndex,
    },
    expectFailureHandler: expectInvalidGovernanceChain,
  },{
    name: "Fails to append Schnorr key when emitter address is not governance contract",
    emitter: {
      chain: "Solana",
      emitterAddress: new UniversalAddress("0x0000000000000000000000000000000000000000000000000000000000000009"),
    } as const,
    test: {
      keyIndex: testKeyIndex + 1,
      publicKey: testSchnorrKey,
      previousSetExpirationTime: guardianSetExpirationTime,
      oldKeyIndex: testKeyIndex,
    },
    expectFailureHandler: expectInvalidGovernanceContract,
  }].map(({name, emitter, test, expectFailureHandler}) => it(name, async () => {
    let message = createAppendSchnorrKeyMessage(test)

    const {postedVaa: postedVaaAddress, signatureSet} = await postVaaV1(message, undefined, emitter)

    let ix = await coreV2.methods.appendSchnorrKey().accountsPartial({
      vaa: postedVaaAddress,
      signatureSet,
      newSchnorrKey: deriveSchnorrKeyPda(test.keyIndex)[0],
      oldSchnorrKey: deriveSchnorrKeyPda(test.oldKeyIndex)[0],
    }).instruction()

    return expectFailure(
      () => $.sendAndConfirm(ix, payer),
      expectFailureHandler
    )
  }))

  it("Posting a governance VAA to a fake wormhole contract is not accepted by VerificationV2", async () => {
    const newKeyIndex = 10
    const message = createAppendSchnorrKeyMessage({
      keyIndex: newKeyIndex,
      publicKey: testSchnorrKey,
      previousSetExpirationTime: guardianSetExpirationTime,
    })

    const {postedVaa: postedVaaAddress, signatureSet} = await postVaaV1(message, fakeCoreV1)

    const ix = await coreV2.methods.appendSchnorrKey().accountsPartial({
      vaa: postedVaaAddress,
      signatureSet,
      newSchnorrKey: deriveSchnorrKeyPda(newKeyIndex)[0],
      oldSchnorrKey: deriveSchnorrKeyPda(testKeyIndex)[0],
    }).instruction()

    return expectFailure(
      () => $.sendAndConfirm(ix, payer),
      (error) => expectAtLeastOneLog(error, "Error Code: AccountOwnedByWrongProgram."),
    )
  })

  it("Verifies a v2 VAA", async function() {
    const vaa = Buffer.from(getTestMessage100Zeroed(testKeyIndex));
    const verifyIx = await coreV2.methods.verifyVaa(vaa).accounts({
      keyAccount: deriveSchnorrKeyPda(testKeyIndex)[0],
    }).instruction()

    const txid = await $.sendAndConfirm(verifyIx, payer)
    const tx = await $.getTransaction(txid);
    console.log(`logs: ${tx?.meta?.logMessages?.join("\n")}`)
    console.log(`${this.test?.title}: CUs consumed: ${tx?.meta?.computeUnitsConsumed}`)
  })

  it("Fails when providing ECDSA key account for Schnorr signature", async function() {
    const vaa = Buffer.from(getTestMessage100Zeroed(testKeyIndex));
    const verifyIx = await coreV2.methods.verifyVaa(vaa).accounts({
      keyAccount: deriveECDSAKeyPda(0)[0], // Wrong account type! Use ECDSA key index 0
    }).instruction()

    expectFailure(
      () => $.sendAndConfirm(verifyIx, payer),
      (error) => expectAtLeastOneLog(error, "Error Code: InvalidAccounts.")
    )
  })

  it("Fails when providing invalid version in VAA", async function() {
    // Create a VAA with invalid version (not 2 or 3)
    const invalidVaa = Buffer.from([1, ...getTestMessage100Zeroed(testKeyIndex).slice(1)]); // Version 1
    const verifyIx = await coreV2.methods.verifyVaa(invalidVaa).accounts({
      keyAccount: deriveSchnorrKeyPda(testKeyIndex)[0],
    }).instruction()

    expectFailure(
      () => $.sendAndConfirm(verifyIx, payer),
      (error) => expectAtLeastOneLog(error, "Error Code: InvalidAccounts.")
    )
  })

  it("v2 VAA verification fails for an invalid signature", async function() {
    const vaa = Buffer.from(getTestMessageInvalidSignature(testKeyIndex));
    const verifyIx = await coreV2.methods.verifyVaa(vaa).accounts({
      keyAccount: deriveSchnorrKeyPda(testKeyIndex)[0],
    }).instruction()

    expectFailure(
      () => $.sendAndConfirm(verifyIx, payer),
      expectFailedSignatureVerification
    )
  })

  it("Verifies a v2 VAA and decodes", async function() {
    const vaa = Buffer.from(getTestMessage100Zeroed(testKeyIndex));
    const verifyIx = await coreV2.methods.verifyVaaAndDecode(vaa).accounts({
      keyAccount: deriveSchnorrKeyPda(testKeyIndex)[0],
    }).instruction()

    const txid = await $.sendAndConfirm(verifyIx, payer)
    const tx = await $.getTransaction(txid);
    // console.log(`logs: ${tx?.meta?.logMessages?.join("\n")}`)
    console.log(`${this.test?.title}: CUs consumed: ${tx?.meta?.computeUnitsConsumed}`)
  })

  it("v2 VAA verification and decoding fails for an invalid signature", async function() {
    const vaa = Buffer.from(getTestMessageInvalidSignature(testKeyIndex));
    const verifyIx = await coreV2.methods.verifyVaaAndDecode(vaa).accounts({
      keyAccount: deriveSchnorrKeyPda(testKeyIndex)[0],
    }).instruction()

    expectFailure(
      () => $.sendAndConfirm(verifyIx, payer),
      expectFailedSignatureVerification
    )
  })

  it("Verifies a v2 VAA header with digest", async function() {
    const vaaHeader = Buffer.from(getHeaderTestMessage100Zeroed(testKeyIndex))
    const digest = Array.from(vaaDigest(new Uint8Array(100)))
    const verifyIx = await coreV2.methods.verifyVaaHeaderWithDigest(vaaHeader, digest).accounts({
      keyAccount: deriveSchnorrKeyPda(testKeyIndex)[0],
    }).instruction()

    const txid = await $.sendAndConfirm(verifyIx, payer)
    const tx = await $.getTransaction(txid);
    // console.log(`logs: ${tx?.meta?.logMessages?.join("\n")}`)
    console.log(`${this.test?.title}: CUs consumed: ${tx?.meta?.computeUnitsConsumed}`)
  })

  it("v2 VAA header and digest verification fails for an invalid signature", async function() {
    const vaaHeader = Buffer.from(getHeaderTestMessageInvalidSignature(testKeyIndex))
    const digest = Array.from(vaaDigest(new Uint8Array(100)))
    const verifyIx = await coreV2.methods.verifyVaaHeaderWithDigest(vaaHeader, digest).accounts({
      keyAccount: deriveSchnorrKeyPda(testKeyIndex)[0],
    }).instruction()

    expectFailure(
      () => $.sendAndConfirm(verifyIx, payer),
      expectFailedSignatureVerification
    )
  })

  // ECDSA Key Tests
  describe("ECDSA Key Management", function() {
    const testECDSAKeyIndex = 2

    ;([
      {
        name: "Posts invalid init append ECDSA key VAA and fails",
        test: {
          operation: "InitECDSAKey",
          keyIndex: 0,
          address: testECDSAAddress, // Use real ECDSA address
          previousSetExpirationTime: guardianSetExpirationTime,
        },
        extraMessageData: "junkdata",
        expectFailureHandler: expectInvalidPayload,
      },
      {
        name: "Posts init append ECDSA key VAA successfully",
        test: {
          operation: "InitECDSAKey",
          keyIndex: 0,
          address: testECDSAAddress, // Use the same address as signature tests
          previousSetExpirationTime: guardianSetExpirationTime,
        },
      },
      {
        name: "Posts invalid append ECDSA key VAA and fails",
        test: {
          operation: "AppendECDSAKey",
          keyIndex: 1,
          address: testECDSAAddress, // Use real ECDSA address
          previousSetExpirationTime: guardianSetExpirationTime,
          oldKeyIndex: 0,
        },
        extraMessageData: "junkdata",
        expectFailureHandler: expectInvalidPayload,
      },
      {
        name: "Posts append ECDSA key VAA successfully",
        test: {
          operation: "AppendECDSAKey",
          keyIndex: 1,
          address: testECDSAAddress, // Use the same address as signature tests
          previousSetExpirationTime: guardianSetExpirationTime,
          oldKeyIndex: 0,
        }
      },
      {
        name: "Posts append ECDSA key VAA successfully (index 2)",
        test: {
          operation: "AppendECDSAKey",
          keyIndex: 2,
          address: testECDSAAddress, // Use the same address as signature tests
          previousSetExpirationTime: guardianSetExpirationTime,
          oldKeyIndex: 1,
        }
      },
      {
        name: "Fails to append ECDSA key when skipping indices",
        test: {
          operation: "AppendECDSAKey",
          keyIndex: 5,
          address: testECDSAAddress,
          previousSetExpirationTime: guardianSetExpirationTime,
          oldKeyIndex: 2,
        },
        expectFailureHandler: expectNewKeyIndexNotDirectSuccessor,
      },
      {
        name: "Appends a third ECDSA key",
        test: {
          operation: "AppendECDSAKey",
          keyIndex: 3,
          address: testECDSAAddress,
          previousSetExpirationTime: guardianSetExpirationTime,
          oldKeyIndex: 2,
        }
      },
      {
        name: "Fails to append ECDSA key when referencing an old key",
        test: {
          operation: "AppendECDSAKey",
          keyIndex: 4,
          address: testECDSAAddress,
          previousSetExpirationTime: guardianSetExpirationTime,
          oldKeyIndex: 0, // Reference old key instead of previous
        },
        expectFailureHandler: expectOldKeyIndexNotPrevious,
      },
      {
        name: "Fails to append invalid ECDSA key (all zeros)",
        test: {
          operation: "AppendECDSAKey",
          keyIndex: 4, // Use the next sequential index after 3
          address: new Uint8Array(20), // All zeros - invalid
          previousSetExpirationTime: guardianSetExpirationTime,
          oldKeyIndex: 3, // Use the latest key index from successful tests
        },
        expectFailureHandler: expectInvalidECDSAKey,
      },
      {
        name: "Fails to append ECDSA key before the new guardian set is submitted",
        test: {
          operation: "AppendECDSAKey",
          keyIndex: 4, // Use the next sequential index after 3
          address: testECDSAAddress,
          previousSetExpirationTime: guardianSetExpirationTime,
          oldKeyIndex: 3, // Use the latest existing key index
          expectedMssIndex: 1,
        },
        expectFailureHandler: expectInvalidGuardianSet,
      },
    ] satisfies AddECDSAKeyTest[]).map((test) => addECDSAKeyTest(test));

    [{
      name: "Fails to append ECDSA key when emitter chain is not Solana",
      emitter: {
        chain: "Ethereum",
        emitterAddress: new UniversalAddress("0x0000000000000000000000000000000000000000000000000000000000000004"),
      } as const,
      test: {
        keyIndex: 6, // Use a different key index to avoid conflicts
        address: testECDSAAddress,
        previousSetExpirationTime: guardianSetExpirationTime,
        oldKeyIndex: 3, // Use the latest key index from successful tests
      },
      expectFailureHandler: expectInvalidGovernanceChain,
    },{
      name: "Fails to append ECDSA key when emitter address is not governance contract",
      emitter: {
        chain: "Solana",
        emitterAddress: new UniversalAddress("0x0000000000000000000000000000000000000000000000000000000000000009"),
      } as const,
      test: {
        keyIndex: 7, // Use a different key index to avoid conflicts
        address: testECDSAAddress,
        previousSetExpirationTime: guardianSetExpirationTime,
        oldKeyIndex: 3, // Use the latest key index from successful tests
      },
      expectFailureHandler: expectInvalidGovernanceContract,
    }].map(({name, emitter, test, expectFailureHandler}) => it(name, async () => {
      let message = createAppendECDSAKeyMessage(test)

      const {postedVaa: postedVaaAddress, signatureSet} = await postVaaV1(message, undefined, emitter)

      let ix = await coreV2.methods.appendEcdsaKey().accountsPartial({
        vaa: postedVaaAddress,
        signatureSet,
        latestEcdsaKey: deriveLatestECDSAKeyPda()[0],
        newEcdsaKey: deriveECDSAKeyPda(test.keyIndex)[0],
        oldEcdsaKey: deriveECDSAKeyPda(test.oldKeyIndex)[0],
      }).instruction()

      return expectFailure(
        () => $.sendAndConfirm(ix, payer),
        expectFailureHandler
      )
    }))

    it("Posting a governance VAA to a fake wormhole contract is not accepted by VerificationV2 for ECDSA", async () => {
      const newKeyIndex = 10
      const message = createAppendECDSAKeyMessage({
        keyIndex: newKeyIndex,
        address: testECDSAAddress,
        previousSetExpirationTime: guardianSetExpirationTime,
      })

      const {postedVaa: postedVaaAddress, signatureSet} = await postVaaV1(message, fakeCoreV1)

      const ix = await coreV2.methods.appendEcdsaKey().accountsPartial({
        vaa: postedVaaAddress,
        signatureSet,
        latestEcdsaKey: deriveLatestECDSAKeyPda()[0],
        newEcdsaKey: deriveECDSAKeyPda(newKeyIndex)[0],
        oldEcdsaKey: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      return expectFailure(
        () => $.sendAndConfirm(ix, payer),
        (error) => expectAtLeastOneLog(error, "Error Code: AccountOwnedByWrongProgram."),
      )
    })
  })

  // ECDSA Signature Verification Tests
  describe("ECDSA Signature Verification", function() {
    const testECDSAKeyIndex = 3 // Use the latest existing ECDSA key from key management tests

    it("Fails when providing Schnorr key account for ECDSA signature", async function() {
      const vaa = Buffer.from(getTestECDSAMessage100Zeroed(testECDSAKeyIndex));
      const verifyIx = await coreV2.methods.verifyVaa(vaa).accounts({
        keyAccount: deriveSchnorrKeyPda(testKeyIndex)[0], // Wrong account type!
      }).instruction()

      expectFailure(
        () => $.sendAndConfirm(verifyIx, payer),
        (error) => expectAtLeastOneLog(error, "Error Code: InvalidAccounts.")
      )
    })

    it("Fails when providing invalid version in ECDSA VAA", async function() {
      // Create an ECDSA VAA with invalid version (not 2 or 3)
      const invalidVaa = Buffer.from([1, ...getTestECDSAMessage100Zeroed(testECDSAKeyIndex).slice(1)]); // Version 1
      const verifyIx = await coreV2.methods.verifyVaa(invalidVaa).accounts({
        keyAccount: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      expectFailure(
        () => $.sendAndConfirm(verifyIx, payer),
        (error) => expectAtLeastOneLog(error, "Error Code: InvalidAccounts.")
      )
    })

    it("Verifies a v3 VAA", async function() {
      // First, let's check if the ECDSA key account exists and has the correct address
      const ecdsaKeyAccount = await coreV2.account.ecdsaKeyAccount.fetch(deriveECDSAKeyPda(testECDSAKeyIndex)[0]);
      console.log("ECDSA Key Account:", {
        index: ecdsaKeyAccount.index,
        address: Array.from(ecdsaKeyAccount.ecdsaKey.address),
        expectedAddress: Array.from(testECDSAAddress)
      });
      
      // Let's also verify the signature generation
      const testBody = new Uint8Array(100);
      const testDigest = keccak256(keccak256(testBody));
      console.log("Test digest:", Array.from(testDigest));
      console.log("Signature used:", {
        r: Array.from(validECDSASignatureTest.r),
        s: Array.from(validECDSASignatureTest.s),
        v: validECDSASignatureTest.v
      });
      
      const vaa = Buffer.from(getTestECDSAMessage100Zeroed(testECDSAKeyIndex));
      const verifyIx = await coreV2.methods.verifyVaa(vaa).accounts({
        keyAccount: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      const txid = await $.sendAndConfirm(verifyIx, payer)
      const tx = await $.getTransaction(txid);
      console.log(`logs: ${tx?.meta?.logMessages?.join("\n")}`)
      console.log(`${this.test?.title}: CUs consumed: ${tx?.meta?.computeUnitsConsumed}`)
    })

    it("v3 VAA verification fails for an invalid signature", async function() {
      const vaa = Buffer.from(getTestECDSAMessageInvalidSignature(testECDSAKeyIndex));
      const verifyIx = await coreV2.methods.verifyVaa(vaa).accounts({
        keyAccount: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      expectFailure(
        () => $.sendAndConfirm(verifyIx, payer),
        expectFailedSignatureVerification
      )
    })

    it("Verifies a v3 VAA and decodes", async function() {
      const vaa = Buffer.from(getTestECDSAMessage100Zeroed(testECDSAKeyIndex));
      const verifyIx = await coreV2.methods.verifyVaaAndDecode(vaa).accounts({
        keyAccount: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      const txid = await $.sendAndConfirm(verifyIx, payer)
      const tx = await $.getTransaction(txid);
      console.log(`${this.test?.title}: CUs consumed: ${tx?.meta?.computeUnitsConsumed}`)
    })

    it("v3 VAA verification and decoding fails for an invalid signature", async function() {
      const vaa = Buffer.from(getTestECDSAMessageInvalidSignature(testECDSAKeyIndex));
      const verifyIx = await coreV2.methods.verifyVaaAndDecode(vaa).accounts({
        keyAccount: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      expectFailure(
        () => $.sendAndConfirm(verifyIx, payer),
        expectFailedSignatureVerification
      )
    })

    it("Verifies a v3 VAA header with digest", async function() {
      const vaaHeader = Buffer.from(getHeaderECDSATestMessage(testECDSAKeyIndex))
    const digest = [...vaaDigest(new Uint8Array(100))]
    const verifyIx = await coreV2.methods.verifyVaaHeaderWithDigest(vaaHeader, digest).accounts({
        keyAccount: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      const txid = await $.sendAndConfirm(verifyIx, payer)
      const tx = await $.getTransaction(txid);
      console.log(`${this.test?.title}: CUs consumed: ${tx?.meta?.computeUnitsConsumed}`)
    })

    it("v3 VAA header and digest verification fails for an invalid signature", async function() {
      const vaaHeader = Buffer.from(getHeaderECDSATestMessageInvalidSignature(testECDSAKeyIndex))
      const digest = [...vaaDigest(new Uint8Array(100))]
      const verifyIx = await coreV2.methods.verifyVaaHeaderWithDigest(vaaHeader, digest).accounts({
        keyAccount: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
    }).instruction()

    expectFailure(
      () => $.sendAndConfirm(verifyIx, payer),
      expectFailedSignatureVerification
    )
    })

    it("ECDSA signature validation: zero r value fails", async function() {
      const invalidSig = {
        r: new Uint8Array(32), // All zeros
        s: encoding.hex.decode("0xfb5fa64887c4a05818b02afa7483e5115f19a93739c4b9ce4e92bae191a2ef4b"),
        v: 0
      }
      const header: HeaderV3 = {
        ecdsaKeyIndex: testECDSAKeyIndex,
        signature: invalidSig,
      }
      const vaa = Uint8Array.from([
        ...serializeLayout(headerV3Layout, header),
        ...new Uint8Array(100)
      ])

      const verifyIx = await coreV2.methods.verifyVaa(Buffer.from(vaa)).accounts({
        keyAccount: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      expectFailure(
        () => $.sendAndConfirm(verifyIx, payer),
        expectInvalidSignature
      )
    })

    it("ECDSA signature validation: zero s value fails", async function() {
      const invalidSig = {
        r: encoding.hex.decode("0x41CF8d30EBCc800b655eAD15cC96014d36c4246B41CF8d30EBCc800b655eAD15"),
        s: new Uint8Array(32), // All zeros
        v: 0
      }
      const header: HeaderV3 = {
        ecdsaKeyIndex: testECDSAKeyIndex,
        signature: invalidSig,
      }
      const vaa = Uint8Array.from([
        ...serializeLayout(headerV3Layout, header),
        ...new Uint8Array(100)
      ])

      const verifyIx = await coreV2.methods.verifyVaa(Buffer.from(vaa)).accounts({
        keyAccount: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      expectFailure(
        () => $.sendAndConfirm(verifyIx, payer),
        expectInvalidSignature
      )
    })

    it("ECDSA signature validation: invalid v value fails", async function() {
      const invalidSig = {
        r: encoding.hex.decode("0x41CF8d30EBCc800b655eAD15cC96014d36c4246B41CF8d30EBCc800b655eAD15"),
        s: encoding.hex.decode("0xfb5fa64887c4a05818b02afa7483e5115f19a93739c4b9ce4e92bae191a2ef4b"),
        v: 2 // Invalid v value (must be 0 or 1)
      }
      const header: HeaderV3 = {
        ecdsaKeyIndex: testECDSAKeyIndex,
        signature: invalidSig,
      }
      const vaa = Uint8Array.from([
        ...serializeLayout(headerV3Layout, header),
        ...new Uint8Array(100)
      ])

      const verifyIx = await coreV2.methods.verifyVaa(Buffer.from(vaa)).accounts({
        keyAccount: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      expectFailure(
        () => $.sendAndConfirm(verifyIx, payer),
        expectInvalidSignature
      )
    })

    it("ECDSA signature validation: r >= n fails", async function() {
      // Use a value >= secp256k1 curve order n
      const nHex = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
      const invalidSig = {
        r: encoding.hex.decode(nHex),
        s: encoding.hex.decode("0xfb5fa64887c4a05818b02afa7483e5115f19a93739c4b9ce4e92bae191a2ef4b"),
        v: 0
      }
      const header: HeaderV3 = {
        ecdsaKeyIndex: testECDSAKeyIndex,
        signature: invalidSig,
      }
      const vaa = Uint8Array.from([
        ...serializeLayout(headerV3Layout, header),
        ...new Uint8Array(100)
      ])

      const verifyIx = await coreV2.methods.verifyVaa(Buffer.from(vaa)).accounts({
        keyAccount: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      expectFailure(
        () => $.sendAndConfirm(verifyIx, payer),
        expectInvalidSignature
      )
    })

    it("ECDSA signature validation: s >= n fails", async function() {
      // Use a value >= secp256k1 curve order n
      const nHex = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
      const invalidSig = {
        r: encoding.hex.decode("0x41CF8d30EBCc800b655eAD15cC96014d36c4246B41CF8d30EBCc800b655eAD15"),
        s: encoding.hex.decode(nHex),
        v: 0
      }
      const header: HeaderV3 = {
        ecdsaKeyIndex: testECDSAKeyIndex,
        signature: invalidSig,
      }
      const vaa = Uint8Array.from([
        ...serializeLayout(headerV3Layout, header),
        ...new Uint8Array(100)
      ])

      const verifyIx = await coreV2.methods.verifyVaa(Buffer.from(vaa)).accounts({
        keyAccount: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      expectFailure(
        () => $.sendAndConfirm(verifyIx, payer),
        expectInvalidSignature
      )
    })

    it("ECDSA verification fails when key is expired", async function() {
      // Append a new key with expirationDelaySeconds = 0 to expire the old key immediately
      const newKeyIndex = testECDSAKeyIndex + 1
      let message = createAppendECDSAKeyMessage({
        keyIndex: newKeyIndex,
        address: testECDSAAddress,
        previousSetExpirationTime: 0, // expire old key now
        oldKeyIndex: testECDSAKeyIndex,
      })

      const {postedVaa: postedVaaAddress, signatureSet} = await postVaaV1(message)

      const ix = await coreV2.methods.appendEcdsaKey().accountsPartial({
        vaa: postedVaaAddress,
        signatureSet,
        latestEcdsaKey: deriveLatestECDSAKeyPda()[0],
        newEcdsaKey: deriveECDSAKeyPda(newKeyIndex)[0],
        oldEcdsaKey: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      await $.sendAndConfirm(ix, payer)

      // Now verification using the expired old key should fail
      const vaa = Buffer.from(getTestECDSAMessage100Zeroed(testECDSAKeyIndex))
      const verifyIx = await coreV2.methods.verifyVaa(vaa).accounts({
        keyAccount: deriveECDSAKeyPda(testECDSAKeyIndex)[0],
      }).instruction()

      expectFailure(
        () => $.sendAndConfirm(verifyIx, payer),
        expectECDSAKeyExpired,
      )
    })
  })
});

function generateMockPubkey() {
  const halfQ = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1n;
  let key = randomBytes(32)

  const parity = BigInt((key[0] & 0x80) >> 7)
  const x = encoding.bignum.decode(key) % halfQ
  key = encoding.bignum.toBytes((x << 1n) | parity, 32)

  return key
}

function generateInvalidMockPubkey() {
  const key = new Uint8Array(32)
  key.fill(0xff)

  return key
}

function expectInvalidPayload(error: Error) {
  expectAtLeastOneLog(error, "Error Message: IO Error: Invalid payload.")
}

function expectFailedSignatureVerification(error: Error) {
  expectAtLeastOneLog(error, "Error Code: SignatureVerificationFailed.")
}

function expectInvalidOldSchnorrKey(error: Error) {
  expectAtLeastOneLog(error, "Error Code: InvalidOldSchnorrKey.")
}

function expectInvalidGovernanceChain(error: Error) {
  expectAtLeastOneLog(error, "Error Code: InvalidGovernanceChainId.")
}

function expectInvalidGovernanceContract(error: Error) {
  expectAtLeastOneLog(error, "Error Code: InvalidGovernanceAddress.")
}

function expectInvalidSchnorrKey(error: Error) {
  expectAtLeastOneLog(error, "Error Code: AccountDidNotSerialize.")
}

function expectInvalidECDSAKey(error: Error) {
  expectAtLeastOneLog(error, "Error Code: AccountDidNotSerialize.")
}

function expectInvalidSignature(error: Error) {
  expectAtLeastOneLog(error, "Error Code: InvalidSignature.")
}

function expectECDSAKeyExpired(error: Error) {
  expectAtLeastOneLog(error, "Error Code: ECDSAKeyExpired.")
}

function expectNewKeyIndexNotDirectSuccessor(error: Error) {
  expectAtLeastOneLog(error, "Error Code: NewKeyIndexNotDirectSuccessor.")
}

function expectOldKeyIndexNotPrevious(error: Error) {
  expectAtLeastOneLog(error, "Error Code: InvalidOldECDSAKey.")
}

function expectInvalidGuardianSet(error: Error) {
  expectAtLeastOneLog(error, "Error Code: InvalidGuardianSet.")
}

function expectAllocateAccountError(account: string) {
  return (error: Error) => expectAtLeastOneLog(error, `Allocate: account Address { address: ${account}, base: None } already in use`)
}

function expectAtLeastOneLog(error: Error, message: string) {
  assert((error as any).transactionLogs.find(
    (log: string) => log.includes(message)
  ))
}