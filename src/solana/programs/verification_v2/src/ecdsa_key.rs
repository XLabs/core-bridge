use anchor_lang::prelude::*;
use anchor_lang::solana_program::{keccak::hash, secp256k1_recover};
#[cfg(feature = "idl-build")]
use anchor_lang::{
  IdlBuild,
  idl::types::{
    IdlArrayLen,
    IdlDefinedFields,
    IdlField,
    IdlSerialization,
    IdlType,
    IdlTypeDef,
    IdlTypeDefTy,
  },
};
use primitive_types::U256;
use std::io::{Read, Write};

use crate::ecdsa_signature::VAAECDSASignature;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECDSAKey {
  pub address: [u8; 20],
}

#[cfg(feature = "idl-build")]
impl IdlBuild for ECDSAKey {
  fn create_type() -> Option<IdlTypeDef> {
    Some(IdlTypeDef {
      name: "ECDSAKey".to_string(),
      docs: vec![],
      serialization: IdlSerialization::Borsh,
      repr: None,
      generics: vec![],
      ty: IdlTypeDefTy::Struct {
        fields: Some(IdlDefinedFields::Named(vec![
          IdlField {
            name: "address".to_string(),
            docs: vec![],
            ty: IdlType::Array(Box::new(IdlType::U8), IdlArrayLen::Value(20)),
          },
        ])),
      },
    })
  }
}

#[error_code]
pub enum ECDSAKeyError {
  #[msg("Signature does not satisfy preconditions")]
  InvalidSignature,
  #[msg("Signature verification failed")]
  SignatureVerificationFailed,
  #[msg("Public key recovery failed")]
  RecoveryFailed,
}

impl ECDSAKey {
  /// Verify an ECDSA signature against a message digest
  #[inline(always)]
  pub fn check_signature(&self, digest: &[u8; 32], signature: &VAAECDSASignature) -> Result<()> {
    if !signature.is_valid() {
      return Err(ECDSAKeyError::InvalidSignature.into());
    }

    // Prepare signature bytes for secp256k1_recover (r || s format)
    let mut signature_bytes = [0u8; 64];
    signature_bytes[0..32].copy_from_slice(&signature.r.to_big_endian());
    signature_bytes[32..64].copy_from_slice(&signature.s.to_big_endian());

    let recovery_id = signature.recovery_id();

    // Recover the public key from the signature
    let recovered_pubkey = secp256k1_recover::secp256k1_recover(
      digest,
      recovery_id,
      &signature_bytes
    ).map_err(|_| ECDSAKeyError::RecoveryFailed)?;

    // Compute Ethereum-style address from public key: keccak256(pubkey)[12..32]
    let recovered_address = &hash(&recovered_pubkey.to_bytes()).to_bytes()[12..];

    if recovered_address != self.address {
      return Err(ECDSAKeyError::SignatureVerificationFailed.into());
    }

    Ok(())
  }

  // N is the curve order of secp256k1
  pub fn n() -> U256 {
    U256([
      0xBFD25E8CD0364141,
      0xBAAEDCE6AF48A03B,
      0xFFFFFFFFFFFFFFFE,
      0xFFFFFFFFFFFFFFFF
    ])
  }

  fn is_valid(&self) -> bool {
    // Address must not be all zeros
    !self.address.iter().all(|&b| b == 0)
  }
}

impl Space for ECDSAKey {
  const INIT_SPACE: usize = 20;
}

impl AnchorSerialize for ECDSAKey {
  fn serialize<W: Write>(&self, writer: &mut W) -> std::result::Result<(), std::io::Error> {
    if !self.is_valid() {
      return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid ECDSA key"));
    }

    writer.write_all(&self.address)?;
    Ok(())
  }
}

impl AnchorDeserialize for ECDSAKey {
  fn deserialize_reader<R: Read>(reader: &mut R) -> std::result::Result<Self, std::io::Error> {
    let mut address = [0u8; 20];
    reader.read_exact(&mut address)?;
    let key = Self { address };

    Ok(key)
  }
}

#[account]
#[derive(InitSpace)]
pub struct ECDSAKeyAccount {
  pub index: u32,
  pub ecdsa_key: ECDSAKey,
  pub expiration_timestamp: u64,
}

impl ECDSAKeyAccount {
  pub const SEED_PREFIX: &'static [u8] = b"ecdsakey";

  pub fn is_unexpired(&self) -> bool {
    self.expiration_timestamp == 0 || self.expiration_timestamp > Clock::get().unwrap().unix_timestamp as u64
  }

  pub fn update_expiration_timestamp(&mut self, time_lapse: u64) {
    let current_timestamp = Clock::get().unwrap().unix_timestamp as u64;
    self.expiration_timestamp = current_timestamp + time_lapse;
  }
}

#[cfg(test)]
mod ecdsa_tests {
  use super::*;
  use primitive_types::U256;
  use crate::ecdsa_signature::VAAECDSASignature;

  #[test]
  fn n_is_correct() {
    let n = U256::from_str_radix(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
      16
    ).unwrap();
    assert_eq!(ECDSAKey::n(), n);
  }

  #[test]
  fn key_validation() {
    // Valid key
    let key1 = ECDSAKey {
      address: [1u8; 20],
    };
    assert!(key1.is_valid());

    // Invalid key (all zeros)
    let key2 = ECDSAKey {
      address: [0u8; 20],
    };
    assert!(!key2.is_valid());
  }
}
