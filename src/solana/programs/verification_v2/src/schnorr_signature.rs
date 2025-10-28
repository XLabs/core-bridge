use anchor_lang::prelude::AnchorDeserialize;
use primitive_types::U256;
use std::io::{Read, Error, ErrorKind};

use crate::schnorr_key::SchnorrKey;

pub struct VAASchnorrSignature {
  pub r: [u8; 20],
  pub s: U256,
}

impl VAASchnorrSignature {
  #[inline(always)]
  pub fn is_valid(&self) -> bool {
    !self.s.is_zero() && self.s.lt(&SchnorrKey::q()) && !self.r.iter().all(|r| *r == 0)
  }
}

impl AnchorDeserialize for VAASchnorrSignature {
  #[inline(always)]
  fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
    let mut r = [0u8; 20];
    reader.read_exact(&mut r)?;
    let mut s = [0u8; 32];
    reader.read_exact(&mut s)?;
    let signature = Self { r, s: U256::from_big_endian(&s) };
    if !signature.is_valid() {
      return Err(Error::new(ErrorKind::InvalidData, "Invalid Schnorr signature"));
    }
    Ok(signature)
  }
}

