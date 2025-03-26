import { it, expect } from "vitest"
import { fromHex, toHex } from "./hex.js"
import {
  BinCode,
  decode,
  encode,
  Enum,
  Int8,
  String,
  Struct,
} from "./bincode.ts"
import { BinaryData, DataContractCreateTransition, DataContractInSerializationFormat, StateTransition, IdentityPublicKeyV0, KeyType, Purpose, SecurityLevel, Identifier, IdentifierBytes32, IdentityPublicKey, OutPoint } from "./2.0.0/generated_bincode"
import { toJsonCamelCase } from "./dash_bincode"

import * as secp from "@noble/secp256k1"
import * as KeyUtils from "./key-utils"
import { doubleSha256 } from "../DashTx.js/dashtx.js"
import { signTransitionWithRawKey } from "./sign.ts"

const Enum1 = Enum("Enum1", {
  Foo: { F0: String },
  Bar: { F0: Int8 },
})

type Enum1 = typeof Enum1.$$type
namespace Enum1 {
  export type Foo = ReturnType<typeof Enum1.Foo>
}

it("should create enums correctly", () => {

  expect(Enum1.Foo).toBeDefined()
  expect(Enum1.Bar).toBeDefined()

  const x: Enum1.Foo = Enum1.Foo({ F0: "hello" })

  const _xenum: Enum1 = x
  expect(x.F0).toBe("hello")
  expect(x).toBeInstanceOf(Enum1.Foo)
  expect(x).toBeInstanceOf(Enum1)

  const y = Enum1.Bar({ F0: 5 })
  expect(y.F0).toBe(5)
  expect(y).toBeInstanceOf(Enum1.Bar)
  expect(y).toBeInstanceOf(Enum1)

  const x_bytes = encode(Enum1, x)
  expect(toHex(x_bytes)).toStrictEqual("000568656c6c6f")
})

it("should encode/decode DataContractCreateTransitions", async () => {
  /*
  const data_contract_create_json = {
    "dataContract": {
      "$format_version": "1",
      "id": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
      "config": {
        "$format_version": "0",
        "canBeDeleted": true,
        "readonly": false,
        "keepsHistory": true,
        "documentsKeepHistoryContractDefault": false,
        "documentsMutableContractDefault": false,
        "documentsCanBeDeletedContractDefault": false,
        "requiresIdentityEncryptionBoundedKey": null,
        "requiresIdentityDecryptionBoundedKey": null
      }, "version": 2,
      "ownerId": [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5],
      "schemaDefs": {},
      "documentSchemas": {
        "asdf": { "foo": 34 }
      },
      "createdAt": 100000,
      "updatedAt": 100001,
      "createdAtBlockHeight": 100002,
      "updatedAtBlockHeight": 100003,
      "createdAtEpoch": 10004,
      "updatedAtEpoch": 10005,
      "groups": {
        "12": {
          "V0": {
            "members": {
              "21nS9Wz9sUTQ6MkcYUtnN8aSfPA26xJJP7zqshfzCzqc": 1
            },
            "required_power": 1
          }
        }
      },
      "tokens": {
        "0": {
          "$format_version": "0",
          "conventions": {
            "$format_version": "0",
            "localizations": {
              "US": {
                "$format_version": "0",
                "shouldCapitalize": true,
                "singularForm": "x",
                "pluralForm": "xs"
              }
            }, "decimals": 2
          },
          "conventionsChangeRules": {
            "V0": {
              "authorized_to_make_change": "MainGroup",
              "admin_action_takers": "ContractOwner",
              "changing_authorized_action_takers_to_no_one_allowed": false, 
              "changing_admin_action_takers_to_no_one_allowed": false, 
              "self_changing_admin_action_takers_allowed": true
            }
          },
          "baseSupply": 12345678901234567890n,
          "maxSupply": 18446744073709551615n,
          "keepsHistory": {
            "$format_version": "0",
            "keepsTransferHistory": false,
            "keepsFreezingHistory": false,
            "keepsMintingHistory": true,
            "keepsBurningHistory": true
          },
          "startAsPaused": false,
          "maxSupplyChangeRules": {
            "V0": {
              "authorized_to_make_change": "MainGroup",
              "admin_action_takers": "ContractOwner",
              "changing_authorized_action_takers_to_no_one_allowed": false,
              "changing_admin_action_takers_to_no_one_allowed": false,
              "self_changing_admin_action_takers_allowed": true
            }
          },
          "distributionRules": {
            "$format_version": "0",
            "perpetualDistribution": {
              "$format_version": "0",
              "distributionType": {
                "EpochBasedDistribution": {
                  "interval": 16,
                  "function": {
                    "InvertedLogarithmic": { "a": 1, "d": 2, "m": 3, "n": 4, "o": 5, "start_moment": 1235678, "b": 0, "min_value": null, "max_value": 112233445566 }
                  }
                }
              },
              "distributionRecipient": "EvonodesByParticipation"
            },
            "perpetualDistributionRules": {
              "V0": {
                "authorized_to_make_change": "MainGroup",
                "admin_action_takers": "ContractOwner",
                "changing_authorized_action_takers_to_no_one_allowed": false,
                "changing_admin_action_takers_to_no_one_allowed": false, "self_changing_admin_action_takers_allowed": true
              }
            },
            "preProgrammedDistribution": { "$format_version": "0", "distributions": {} },
            "newTokensDestinationIdentity": [18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18],
            "newTokensDestinationIdentityRules": {
              "V0": {
                "authorized_to_make_change": "MainGroup",
                "admin_action_takers": "ContractOwner",
                "changing_authorized_action_takers_to_no_one_allowed": false,
                "changing_admin_action_takers_to_no_one_allowed": false,
                "self_changing_admin_action_takers_allowed": true
              }
            },
            "mintingAllowChoosingDestination": true,
            "mintingAllowChoosingDestinationRules": {
              "V0": {
                "authorized_to_make_change": "MainGroup",
                "admin_action_takers": "ContractOwner",
                "changing_authorized_action_takers_to_no_one_allowed": false,
                "changing_admin_action_takers_to_no_one_allowed": false,
                "self_changing_admin_action_takers_allowed": true
              }
            }
          },
          "manualMintingRules": {
            "V0": {
              "authorized_to_make_change": "MainGroup",
              "admin_action_takers": "ContractOwner",
              "changing_authorized_action_takers_to_no_one_allowed": false,
              "changing_admin_action_takers_to_no_one_allowed": false,
              "self_changing_admin_action_takers_allowed": true
            }
          },
          "manualBurningRules": {
            "V0": {
              "authorized_to_make_change": "MainGroup",
              "admin_action_takers": "ContractOwner",
              "changing_authorized_action_takers_to_no_one_allowed": false,
              "changing_admin_action_takers_to_no_one_allowed": false,
              "self_changing_admin_action_takers_allowed": true
            }
          },
          "freezeRules": {
            "V0": {
              "authorized_to_make_change": "MainGroup",
              "admin_action_takers": "ContractOwner",
              "changing_authorized_action_takers_to_no_one_allowed": false,
              "changing_admin_action_takers_to_no_one_allowed": false,
              "self_changing_admin_action_takers_allowed": true
            }
          },
          "unfreezeRules": {
            "V0": {
              "authorized_to_make_change": "MainGroup",
              "admin_action_takers": "ContractOwner",
              "changing_authorized_action_takers_to_no_one_allowed": false,
              "changing_admin_action_takers_to_no_one_allowed": false,
              "self_changing_admin_action_takers_allowed": true
            }
          }, "destroyFrozenFundsRules": {
            "V0": {
              "authorized_to_make_change": "MainGroup",
              "admin_action_takers": "ContractOwner",
              "changing_authorized_action_takers_to_no_one_allowed": false,
              "changing_admin_action_takers_to_no_one_allowed": false,
              "self_changing_admin_action_takers_allowed": true
            }
          },
          "emergencyActionRules": {
            "V0": {
              "authorized_to_make_change": "MainGroup",
              "admin_action_takers": "ContractOwner",
              "changing_authorized_action_takers_to_no_one_allowed": false,
              "changing_admin_action_takers_to_no_one_allowed": false,
              "self_changing_admin_action_takers_allowed": true
            }
          },
          "mainControlGroup": 2,
          "mainControlGroupCanBeModified": "NoOne"
        }
      }
    },
    "identityNonce": 83838,
    "userFeeIncrease": 15,
    "signaturePublicKeyId": 1,
    "signature": [42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42], 
    "$version": 0
  }
  */

  // From Rust
  const data_contract_create_bytes = fromHex("000101010101010101010101010101010101010101010101010101010101010101010001000100000000000205050505050505050505050505050505050505050505050505050505050505050100010461736466160312047479706512066f626a656374120a70726f70657274696573160112047465737416021204747970651206737472696e671208706f736974696f6e040012146164646974696f6e616c50726f70657274696573130001fc000186a001fc000186a101fc000186a201fc000186a301fb271401fb2715010c00010f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f010101000000010255530001017802787302000301000001fdab54a98ceb1f0ad201fdffffffffffffffff000000010100000301000001000100021008020203040a01fc0012dade000001fd0000001a21a278be0200030100000101000001121212121212121212121212121212121212121212121212121212121212121200030100000101000301000001000301000001000301000001000301000001000301000001000301000001000301000001010200fc0001477e0001202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a")
  const data_contract_create_signable_bytes = fromHex("000101010101010101010101010101010101010101010101010101010101010101010001000100000000000205050505050505050505050505050505050505050505050505050505050505050100010461736466160312047479706512066f626a656374120a70726f70657274696573160112047465737416021204747970651206737472696e671208706f736974696f6e040012146164646974696f6e616c50726f70657274696573130001fc000186a001fc000186a101fc000186a201fc000186a301fb271401fb2715010c00010f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f010101000000010255530001017802787302000301000001fdab54a98ceb1f0ad201fdffffffffffffffff000000010100000301000001000100021008020203040a01fc0012dade000001fd0000001a21a278be0200030100000101000001121212121212121212121212121212121212121212121212121212121212121200030100000101000301000001000301000001000301000001000301000001000301000001000301000001000301000001010200fc0001477e00")

  // test that decode then encode returns the same bytes
  const data_contract_create = decode(DataContractCreateTransition, data_contract_create_bytes.buffer)
  const data_contract_create_bytes2 = encode(DataContractCreateTransition, data_contract_create)
  expect(toHex(data_contract_create_bytes2)).toStrictEqual(toHex(data_contract_create_bytes))

  const data_contract_create_signable_bytes2 = encode(DataContractCreateTransition, data_contract_create, { signable: true })
  expect(toHex(data_contract_create_signable_bytes2)).toStrictEqual(toHex(data_contract_create_signable_bytes))


  // Now sign it

  const private_key = fromHex(
    "6c554775029f960891e3edf2d36b26a30d9a4b10034bb49f3a6c4617f557f7bc",
  )
  const publicKey = await KeyUtils.toPublicKey(private_key)
  console.log('publicKey', toHex(publicKey))

  const identityPubKey = IdentityPublicKey.V0(IdentityPublicKeyV0({
    id: 0,
    purpose: Purpose.AUTHENTICATION(),
    security_level: SecurityLevel.CRITICAL(),
    key_type: KeyType.ECDSA_SECP256K1(),
    read_only: true,
    data: BinaryData(publicKey),
  }))

  const state_transition_signed = StateTransition.DataContractCreate(data_contract_create)
  await signTransitionWithRawKey(state_transition_signed, identityPubKey, private_key)

  // We have to check the "signable" bytes AFTER signing because signing also sets the contract_id and other mutations
  // that alter the signable bytes.
  const state_transition_signable_bytes = fromHex("000001fc399a05bcf7e416f4e57fd9870da2539b333e390ed76c0b0a16c017c11660790001000100000000000205050505050505050505050505050505050505050505050505050505050505050100010461736466160312047479706512066f626a656374120a70726f70657274696573160112047465737416021204747970651206737472696e671208706f736974696f6e040012146164646974696f6e616c50726f70657274696573130001fc000186a001fc000186a101fc000186a201fc000186a301fb271401fb2715010c00010f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f010101000000010255530001017802787302000301000001fdab54a98ceb1f0ad201fdffffffffffffffff000000010100000301000001000100021008020203040a01fc0012dade000001fd0000001a21a278be0200030100000101000001121212121212121212121212121212121212121212121212121212121212121200030100000101000301000001000301000001000301000001000301000001000301000001000301000001000301000001010200fc0001477e00")
  const state_transition_signable_bytes2 = encode(StateTransition, state_transition_signed, { signable: true })
  expect(toHex(state_transition_signable_bytes2)).toStrictEqual(toHex(state_transition_signable_bytes))

  const state_transition_signed_bytes = fromHex("000001fc399a05bcf7e416f4e57fd9870da2539b333e390ed76c0b0a16c017c11660790001000100000000000205050505050505050505050505050505050505050505050505050505050505050100010461736466160312047479706512066f626a656374120a70726f70657274696573160112047465737416021204747970651206737472696e671208706f736974696f6e040012146164646974696f6e616c50726f70657274696573130001fc000186a001fc000186a101fc000186a201fc000186a301fb271401fb2715010c00010f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f010101000000010255530001017802787302000301000001fdab54a98ceb1f0ad201fdffffffffffffffff000000010100000301000001000100021008020203040a01fc0012dade000001fd0000001a21a278be0200030100000101000001121212121212121212121212121212121212121212121212121212121212121200030100000101000301000001000301000001000301000001000301000001000301000001000301000001000301000001010200fc0001477e0000411f3b6ee69cca6e9c7dda79e5a571b7bc9de307c5e27754c652ec62b22f7e6ff91966bd5e5db151484f1c81d766053154ed1a2f58a07303edf9f9a8cffe41891506")
  const state_transition_signed_bytes2 = encode(StateTransition, state_transition_signed)
  expect(toHex(state_transition_signed_bytes2)).toStrictEqual(toHex(state_transition_signed_bytes))

})

it("should encode/decode IdentityPublicKey", () => {
  const master_key_bytes = fromHex(
    "0000000000000021033a9a8b1e4c581a1987724c6697135d31c07ee7ac827e6a59cec022b04d51055f00",
  )
  const master_key = decode(IdentityPublicKey, master_key_bytes.buffer)

  // const master_key_json = {
  //   $version: "0",
  //   id: 0,
  //   purpose: 0,
  //   securityLevel: 0,
  //   contractBounds: null,
  //   type: 0,
  //   readOnly: false,
  //   data: [
  //     3, 58, 154, 139, 30, 76, 88, 26, 25, 135, 114, 76, 102, 151, 19, 93, 49,
  //     192, 126, 231, 172, 130, 126, 106, 89, 206, 192, 34, 176, 77, 81, 5, 95,
  //   ],
  //   disabledAt: null,
  // };
  // expect(master_key_json).toEqual(JSON.parse(toJsonCamelCase(master_key)));
  console.log('master_key data (public_key)', ((master_key as IdentityPublicKey.V0)[0].data[0].buffer))
  expect(master_key_bytes).toStrictEqual(
    new Uint8Array(encode(IdentityPublicKey, master_key)),
  )

  const master_private_key = fromHex(
    "6c554775029f960891e3edf2d36b26a30d9a4b10034bb49f3a6c4617f557f7bc",
  )

  const other_key_bytes = fromHex(
    "000100010000002102014603018dc437642dda16f4c7fc50e482dd23e24680bcb3a5966c3b343848e200",
  )
  const other_key = decode(IdentityPublicKey, other_key_bytes.buffer)

  // const other_key_json = {
  //   $version: "0",
  //   id: 1,
  //   purpose: 0,
  //   securityLevel: 1,
  //   contractBounds: null,
  //   type: 0,
  //   readOnly: false,
  //   data: [
  //     2, 1, 70, 3, 1, 141, 196, 55, 100, 45, 218, 22, 244, 199, 252, 80, 228,
  //     130, 221, 35, 226, 70, 128, 188, 179, 165, 150, 108, 59, 52, 56, 72, 226,
  //   ],
  //   disabledAt: null,
  // };
  // expect(other_key_json).toEqual(JSON.parse(toJsonCamelCase(other_key)));

  const other_private_key = fromHex(
    "426ae4838204206cacdfc7a2e04ac6a2d9e3c2e94df935878581c552f22b0096",
  )
})

it("should encode/decode OutPoint", () => {
  // WARNING: There are many versions of OutPoint, this one is the bincode::serde::encode_to_vec
  // representation which uses length-prefixed txid and varuint encoding for vout (same as used in IdentityCreateTransitionV0)
  const op_hex = '200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20fb3039'

  const op = decode(OutPoint, fromHex(op_hex).buffer)
  const op_bytes = encode(OutPoint, op)
  expect(toHex(op_bytes)).toStrictEqual(op_hex)
})

it("should encode/decode IdentityCreateTransition", () => {
  const ic_chain_hex = '03000001fc0012d687200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20fb303942001212121212121212121212121212121212121212121212121212121212121212';
  const ic_instant_hex = '03000000a200000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2012121212121212121212121212121212121212121212121212121212121212124848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848484848480c0200000000010000000000000042001212121212121212121212121212121212121212121212121212121212121212';

  const ic_chain = decode(StateTransition, fromHex(ic_chain_hex).buffer)
  const ic_chain_bytes = encode(StateTransition, ic_chain)
  expect(toHex(ic_chain_bytes)).toStrictEqual(ic_chain_hex)

  const ic_instant = decode(StateTransition, fromHex(ic_instant_hex).buffer)
  const ic_instant_bytes = encode(StateTransition, ic_instant)
  expect(toHex(ic_instant_bytes)).toStrictEqual(ic_instant_hex)
})

// it("should encode/decode Identifier", () => {
//   const identifier_bytes = fromHex(
//     "3dc908599ef8a5a3c510c430a27d4211c805556d99e5c06ffc3ca86a5feb55c3",
//   );
//   const identifier = decode(Identifier, identifier_bytes.buffer);

//   // expect(master_key_json).toEqual(JSON.parse(toJsonCamelCase(master_key)))
//   expect(identifier_bytes).toEqual(
//     new Uint8Array(encode(Identifier, identifier)),
//   );
// });

// it("should encode/decode StateTransition", () => {
//   // const key_signable_bytes = fromHex('0300020000000000000021033a9a8b1e4c581a1987724c6697135d31c07ee7ac827e6a59cec022b04d51055f000100000100002102014603018dc437642dda16f4c7fc50e482dd23e24680bcb3a5966c3b343848e200c601011dbbda5861b12d7523f20aa5e0d42f52de3dcd2d5c2fe919ba67b59f050d206e0000000058c444dd0957767db2c0adea69fd861792bfa75c7e364d83fe85bebebc2a08b436a56617591a6a89237bada6af1f9b46eba47b5d89a8c4e49ff2d0236182307c8967c46529a967b3822e1ba8a173066296d02593f0f59b3a78a30a7eef9c8a120847729e62e4a32954339286b79fe7590221331cd28d576887a263f45b595d499272f656c3f5176987c976239cac16f972d796ad82931d532102a4f95eec7d809e00000800015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4000000001976a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac000000000200e1f50500000000026a0088130000000000001976a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac0000000024000100e1f505000000001976a914271c99481ce1460e4fd62d5a11eecc123d78ee3288ac0000')
//   const asset_lock_private_key = fromHex(
//     "33a9f0603ba69b97dff83e08b4ee36cebbc987739e9749615e1727754f2bf2d2",
//   );

//   const state_transition_signable_bytes = fromHex(
//     "0300020000000000000021033a9a8b1e4c581a1987724c6697135d31c07ee7ac827e6a59cec022b04d51055f000100000100002102014603018dc437642dda16f4c7fc50e482dd23e24680bcb3a5966c3b343848e200c601011dbbda5861b12d7523f20aa5e0d42f52de3dcd2d5c2fe919ba67b59f050d206e0000000058c444dd0957767db2c0adea69fd861792bfa75c7e364d83fe85bebebc2a08b436a56617591a6a89237bada6af1f9b46eba47b5d89a8c4e49ff2d0236182307c8967c46529a967b3822e1ba8a173066296d02593f0f59b3a78a30a7eef9c8a120847729e62e4a32954339286b79fe7590221331cd28d576887a263f45b595d499272f656c3f5176987c976239cac16f972d796ad82931d532102a4f95eec7d809e00000800015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4000000001976a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac000000000200e1f50500000000026a0088130000000000001976a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac0000000024000100e1f505000000001976a914271c99481ce1460e4fd62d5a11eecc123d78ee3288ac0000",
//   );
//   const state_transition_signable = decode(
//     StateTransition,
//     state_transition_signable_bytes.buffer,
//     { signable: true },
//   );
//   expect(state_transition_signable_bytes).toEqual(
//     new Uint8Array(
//       encode(StateTransition, state_transition_signable, { signable: true }),
//     ),
//   );

//   // asset_lock_proof
//   //
//   // ```json
//   // asset_lock_proof {"instantLock":[1,1,29,187,218,88,97,177,45,117,35,242,10,165,224,212,47,82,222,61,205,45,92,47,233,25,186,103,181,159,5,13,32,110,0,0,0,0,88,196,68,221,9,87,118,125,178,192,173,234,105,253,134,23,146,191,167,92,126,54,77,131,254,133,190,190,188,42,8,180,54,165,102,23,89,26,106,137,35,123,173,166,175,31,155,70,235,164,123,93,137,168,196,228,159,242,208,35,97,130,48,124,137,103,196,101,41,169,103,179,130,46,27,168,161,115,6,98,150,208,37,147,240,245,155,58,120,163,10,126,239,156,138,18,8,71,114,158,98,228,163,41,84,51,146,134,183,159,231,89,2,33,51,28,210,141,87,104,135,162,99,244,91,89,93,73,146,114,246,86,195,245,23,105,135,201,118,35,156,172,22,249,114,215,150,173,130,147,29,83,33,2,164,249,94,236,125,128],"transaction":[0,0,8,0,1,88,132,229,219,157,226,24,35,134,113,87,35,64,178,7,238,133,182,40,7,78,126,70,112,150,194,103,38,107,175,119,164,0,0,0,0,25,118,169,20,136,217,147,30,167,61,96,234,247,229,103,30,252,5,82,185,18,145,31,42,136,172,0,0,0,0,2,0,225,245,5,0,0,0,0,2,106,0,136,19,0,0,0,0,0,0,25,118,169,20,136,217,147,30,167,61,96,234,247,229,103,30,252,5,82,185,18,145,31,42,136,172,0,0,0,0,36,0,1,0,225,245,5,0,0,0,0,25,118,169,20,39,28,153,72,28,225,70,14,79,214,45,90,17,238,204,18,61,120,238,50,136,172],"outputIndex":0}
//   // ```
//   //
//   const state_transition_bytes = fromHex(
//     "0300020000000000000021033a9a8b1e4c581a1987724c6697135d31c07ee7ac827e6a59cec022b04d51055f411f6ca4070bc91c2e21f785113a4669fa32bdf24f9e0e67966b5186254265b5d2fd52ef7a9ca7e6ed03ef9838c56bbeb32bf0722f11a95982bfa14a61f56d7c523e000100000100002102014603018dc437642dda16f4c7fc50e482dd23e24680bcb3a5966c3b343848e2411f6776128925163122c68e4ad230cf59c5a8444e518d6a5592d242e9f48e85498e371b78520812536a57ef4400a5e7a43307283c5da62ba343d8f23574c15a2db700c601011dbbda5861b12d7523f20aa5e0d42f52de3dcd2d5c2fe919ba67b59f050d206e0000000058c444dd0957767db2c0adea69fd861792bfa75c7e364d83fe85bebebc2a08b436a56617591a6a89237bada6af1f9b46eba47b5d89a8c4e49ff2d0236182307c8967c46529a967b3822e1ba8a173066296d02593f0f59b3a78a30a7eef9c8a120847729e62e4a32954339286b79fe7590221331cd28d576887a263f45b595d499272f656c3f5176987c976239cac16f972d796ad82931d532102a4f95eec7d809e00000800015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4000000001976a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac000000000200e1f50500000000026a0088130000000000001976a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac0000000024000100e1f505000000001976a914271c99481ce1460e4fd62d5a11eecc123d78ee3288ac0000411fea1c5e3b0c92c8d02fd52c47fe5f215a828d05c317a997a4a3419a17b9260b9717ccee2603bf5ae411bba1ab8e1d0bbc31cbd73d7d6fefcdb4feb34657b2e5093dc908599ef8a5a3c510c430a27d4211c805556d99e5c06ffc3ca86a5feb55c3",
//   );
//   const state_transition = decode(
//     StateTransition,
//     state_transition_bytes.buffer,
//     { signable: false },
//   );
//   console.log(state_transition);
//   expect(state_transition_bytes).toEqual(
//     new Uint8Array(
//       encode(StateTransition, state_transition, { signable: false }),
//     ),
//   );

//   /*
//     IdentityCreate(V0(IdentityCreateTransitionV0 {
//         public_keys: [
//             V0(IdentityPublicKeyInCreationV0 {
//                 id: 0,
//                 key_type: ECDSA_SECP256K1,
//                 purpose: AUTHENTICATION,
//                 security_level: MASTER,
//                 contract_bounds: None,
//                 read_only: false,
//                 data: BinaryData(0x033a9a8b1e4c581a1987724c6697135d31c07ee7ac827e6a59cec022b04d51055f),
//                 signature: BinaryData(0x1f6ca4070bc91c2e21f785113a4669fa32bdf24f9e0e67966b5186254265b5d2fd52ef7a9ca7e6ed03ef9838c56bbeb32bf0722f11a95982bfa14a61f56d7c523e)
//             }),
//             V0(IdentityPublicKeyInCreationV0 {
//                 id: 1,
//                 key_type: ECDSA_SECP256K1,
//                 purpose: AUTHENTICATION,
//                 security_level: CRITICAL,
//                 contract_bounds: None,
//                 read_only: false,
//                 data: BinaryData(0x02014603018dc437642dda16f4c7fc50e482dd23e24680bcb3a5966c3b343848e2),
//                 signature: BinaryData(0x1f6776128925163122c68e4ad230cf59c5a8444e518d6a5592d242e9f48e85498e371b78520812536a57ef4400a5e7a43307283c5da62ba343d8f23574c15a2db7)
//             })
//         ],
//         asset_lock_proof: Instant(InstantAssetLockProof {
//             instant_lock: InstantLock {
//                 version: 1,
//                 inputs: [
//                     OutPoint {
//                         txid: 0x6e200d059fb567ba19e92f5c2dcd3dde522fd4e0a50af223752db16158dabb1d,
//                         vout: 0
//                     }
//                 ],
//                 txid: b4082abcbebe85fe834d367e5ca7bf921786fd69eaadc0b27d765709dd44c458,
//                 cyclehash: 0x7c30826123d0f29fe4c4a8895d7ba4eb469b1fafa6ad7b23896a1a591766a536,
//                 signature: [137, 103, 196, 101, 41, 169, 103, 179, 130, 46, 27, 168, 161, 115, 6, 98, 150, 208,
//                     37, 147, 240, 245, 155, 58, 120, 163, 10, 126, 239, 156, 138, 18, 8, 71, 114, 158, 98, 228, 163,
//                     41, 84, 51, 146, 134, 183, 159, 231, 89, 2, 33, 51, 28, 210, 141, 87, 104, 135, 162, 99, 244, 91,
//                     89, 93, 73, 146, 114, 246, 86, 195, 245, 23, 105, 135, 201, 118, 35, 156, 172, 22, 249, 114, 215,
//                     150, 173, 130, 147, 29, 83, 33, 2, 164, 249, 94, 236, 125, 128]
//             },
//             transaction: Transaction {
//                 version: 0,
//                 lock_time: 0,
//                 input: [
//                     TxIn {
//                         previous_output: OutPoint {
//                             txid: 0xa477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458,
//                             vout: 0
//                         },
//                         script_sig: Script(OP_DUP OP_HASH160 OP_PUSHBYTES_20 88d9931ea73d60eaf7e5671efc0552b912911f2a OP_EQUALVERIFY OP_CHECKSIG),
//                         sequence: 0,
//                         witness: Witness { content: [], witness_elements: 0, indices_start: 0 }
//                     }
//                 ],
//                 output: [
//                     TxOut {
//                         value: 100000000,
//                         script_pubkey: Script(OP_RETURN OP_0)
//                     },
//                     TxOut {
//                         value: 5000,
//                         script_pubkey: Script(OP_DUP OP_HASH160 OP_PUSHBYTES_20 88d9931ea73d60eaf7e5671efc0552b912911f2a OP_EQUALVERIFY OP_CHECKSIG)
//                     }
//                 ],
//                 special_transaction_payload: Some(AssetLockPayloadType(AssetLockPayload {
//                     version: 0,
//                     credit_outputs: [
//                         TxOut {
//                             value: 100000000,
//                             script_pubkey: Script(OP_DUP OP_HASH160 OP_PUSHBYTES_20 271c99481ce1460e4fd62d5a11eecc123d78ee32 OP_EQUALVERIFY OP_CHECKSIG)
//                         }
//                     ]
//                 }))
//             },
//             output_index: 0
//         }),
//         user_fee_increase: 0,
//         signature: BinaryData(0x),
//         identity_id: Identifier(IdentifierBytes32([61, 201, 8, 89, 158, 248, 165, 163, 197, 16, 196, 48, 162, 125, 66, 17, 200, 5, 85, 109, 153, 229, 192, 111, 252, 60, 168, 106, 95, 235, 85, 195]))
//     }))
//     */
// });

// it('should encode/decode Identity', () => {
//     const identity_json = {
//         "$version": "0",
//         "id": [61, 201, 8, 89, 158, 248, 165, 163, 197, 16, 196, 48, 162, 125, 66, 17, 200, 5, 85, 109, 153, 229, 192, 111, 252, 60, 168, 106, 95, 235, 85, 195],
//         "publicKeys": [
//             {
//                 "$version": "0",
//                 "id": 0,
//                 "purpose": 0,
//                 "securityLevel": 0,
//                 "contractBounds": null,
//                 "type": 0,
//                 "readOnly": false,
//                 "data": [3, 58, 154, 139, 30, 76, 88, 26, 25, 135, 114, 76, 102, 151, 19, 93, 49, 192, 126, 231, 172, 130, 126, 106, 89, 206, 192, 34, 176, 77, 81, 5, 95],
//                 "disabledAt": null
//             }, {
//                 "$version": "0",
//                 "id": 1,
//                 "purpose": 0,
//                 "securityLevel": 1,
//                 "contractBounds": null,
//                 "type": 0,
//                 "readOnly": false,
//                 "data": [2, 1, 70, 3, 1, 141, 196, 55, 100, 45, 218, 22, 244, 199, 252, 80, 228, 130, 221, 35, 226, 70, 128, 188, 179, 165, 150, 108, 59, 52, 56, 72, 226],
//                 "disabledAt": null
//             }
//         ],
//         "balance": 1000000000,
//         "revision": 0
//     }
//     //
//     // ```
//     // identity V0(IdentityV0 { id: Identifier(IdentifierBytes32([61, 201, 8, 89, 158, 248, 165, 163, 197, 16, 196, 48, 162, 125, 66, 17, 200, 5, 85, 109, 153, 229, 192, 111, 252, 60, 168, 106, 95, 235, 85, 195])), public_keys: {0: V0(IdentityPublicKeyV0 { id: 0, purpose: AUTHENTICATION, security_level: MASTER, contract_bounds: None, key_type: ECDSA_SECP256K1, read_only: false, data: BinaryData(0x033a9a8b1e4c581a1987724c6697135d31c07ee7ac827e6a59cec022b04d51055f), disabled_at: None }), 1: V0(IdentityPublicKeyV0 { id: 1, purpose: AUTHENTICATION, security_level: CRITICAL, contract_bounds: None, key_type: ECDSA_SECP256K1, read_only: false, data: BinaryData(0x02014603018dc437642dda16f4c7fc50e482dd23e24680bcb3a5966c3b343848e2), disabled_at: None })}, balance: 1000000000, revision: 0 })
//     // ```
//     //
//     // ```
//     // identity_create_transition
//     //             .public_keys
//     //             .iter_mut()
//     //             .zip(identity.public_keys().iter())
//     //             .try_for_each(|(public_key_with_witness, (_, public_key))| {
//     //                 if public_key.key_type().is_unique_key_type() {
//     //                     let signature = signer.sign(public_key, &key_signable_bytes)?;
//     //                     public_key_with_witness.set_signature(signature);
//     //                 }
//     //                 Ok::<(), ProtocolError>(())
//     //             })?;
//     // ```
// })