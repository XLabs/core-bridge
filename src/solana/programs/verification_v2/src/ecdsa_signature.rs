use anchor_lang::prelude::AnchorDeserialize;
use primitive_types::U256;
use std::io::{Read, Error, ErrorKind};

use crate::ecdsa_key::ECDSAKey;

pub struct VAAECDSASignature {
  pub r: U256,
  pub s: U256,
  pub v: u8,
}

impl VAAECDSASignature {
  #[inline(always)]
  pub fn is_valid(&self) -> bool {
    let n = ECDSAKey::n();
    !self.r.is_zero() && self.r.lt(&n) && 
    !self.s.is_zero() && self.s.lt(&n) && 
    (self.v == 0 || self.v == 1)
  }

  #[inline(always)]
  pub fn recovery_id(&self) -> u8 {
      self.v
  }
}

impl AnchorDeserialize for VAAECDSASignature {
  #[inline(always)]
  fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
    let mut r = [0u8; 32];
    reader.read_exact(&mut r)?;
    let mut s = [0u8; 32];
    reader.read_exact(&mut s)?;
    let mut v = [0u8; 1];
    reader.read_exact(&mut v)?;
    let signature = Self { r: U256::from_big_endian(&r), s: U256::from_big_endian(&s), v: v[0] };
    if !signature.is_valid() {
      return Err(Error::new(ErrorKind::InvalidData, "Invalid ECDSA signature"));
    }
    Ok(signature)
  }
}
