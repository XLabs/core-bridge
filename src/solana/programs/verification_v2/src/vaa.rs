use anchor_lang::prelude::AnchorDeserialize;
use std::io::{Read, Error, ErrorKind};
use byteorder::{BigEndian, ReadBytesExt};

use crate::schnorr_signature::VAASchnorrSignature;
use crate::ecdsa_signature::VAAECDSASignature;

pub enum VAASignature {
  Schnorr(VAASchnorrSignature),
  ECDSA(VAAECDSASignature),
}

pub struct VAAHeader {
  pub version: u8,
  pub key_index: u32,
  pub signature: VAASignature,
}

impl AnchorDeserialize for VAAHeader {
  #[inline(always)]
  fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
    let version = reader.read_u8()?;
    let key_index = reader.read_u32::<BigEndian>()?;
  
    match version {
      2 => {
        // Schnorr signature
        let signature = VAASchnorrSignature::deserialize_reader(reader)?;
        Ok(Self { 
          version, 
          key_index, 
          signature: VAASignature::Schnorr(signature) 
        })
      },
      3 => {
        // ECDSA signature
        let signature = VAAECDSASignature::deserialize_reader(reader)?;
        Ok(Self { 
          version, 
          key_index, 
          signature: VAASignature::ECDSA(signature) 
        })
      },
      _ => Err(Error::new(ErrorKind::InvalidData, "Invalid version (must be 2 or 3)"))
    }
  }
}

#[cfg(test)]
mod vaa_tests {
  use super::*;
  use crate::hex;

  // Schnorr header size: version(1) + key_index(4) + r(20) + s(32) = 57 bytes
  const SCHNORR_HEADER_SIZE: usize = 1 + 4 + 20 + 32;
  // ECDSA header size: version(1) + key_index(4) + r(32) + s(32) + v(1) = 70 bytes
  const ECDSA_HEADER_SIZE: usize = 1 + 4 + 32 + 32 + 1;

  #[test]
  fn schnorr_header_deserializes() {
    let mut header_raw = [0u8; SCHNORR_HEADER_SIZE];
    header_raw[0] = 2; // version 2 for Schnorr
    header_raw[5..25].copy_from_slice(hex!("636a8688ef4b82e5a121f7c74d821a5b07d695f3").as_slice());
    header_raw[25..57].copy_from_slice(hex!("aa6d485b7d7b536442ea7777127d35af43ac539a491c0d85ee0f635eb7745b29").as_slice());

    let header = VAAHeader::deserialize(&mut header_raw.as_slice());
    assert!(header.is_ok());
    if let Ok(h) = header {
      assert_eq!(h.version, 2);
      assert!(matches!(h.signature, VAASignature::Schnorr(_)));
    }
  }

  #[test]
  fn ecdsa_header_deserializes() {
    let mut header_raw = [0u8; ECDSA_HEADER_SIZE];
    header_raw[0] = 3; // version 3 for ECDSA
    // r and s should be valid (non-zero and less than curve order)
    header_raw[5..37].copy_from_slice(hex!("aa6d485b7d7b536442ea7777127d35af43ac539a491c0d85ee0f635eb7745b29").as_slice());
    header_raw[37..69].copy_from_slice(hex!("bb6d485b7d7b536442ea7777127d35af43ac539a491c0d85ee0f635eb7745b29").as_slice());
    header_raw[69] = 0; // v = 0

    let header = VAAHeader::deserialize(&mut header_raw.as_slice());
    assert!(header.is_ok());
    if let Ok(h) = header {
      assert_eq!(h.version, 3);
      assert!(matches!(h.signature, VAASignature::ECDSA(_)));
    }
  }

  #[test]
  fn header_size_is_correct() {
    let header_raw = [0u8; SCHNORR_HEADER_SIZE - 1];
    let header = VAAHeader::deserialize(&mut header_raw.as_slice());
    assert!(header.is_err());
  }

  #[test]
  fn invalid_version_rejected() {
    let mut header_raw = [0u8; SCHNORR_HEADER_SIZE];
    header_raw[0] = 1; // version 1 is deprecated
    let header = VAAHeader::deserialize(&mut header_raw.as_slice());
    assert!(header.is_err());

    header_raw[0] = 4; // version 4 doesn't exist
    let header = VAAHeader::deserialize(&mut header_raw.as_slice());
    assert!(header.is_err());
  }
}


