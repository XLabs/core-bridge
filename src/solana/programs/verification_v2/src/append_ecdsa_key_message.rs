use anchor_lang::prelude::{AnchorSerialize, AnchorDeserialize};
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Write, Read, Error, ErrorKind};

use crate::ecdsa_key::ECDSAKey;
use crate::{MODULE_VERIFICATION_V2, ACTION_APPEND_ECDSA_KEY};

#[derive(Clone)]
pub struct AppendECDSAKeyMessage {
  pub ecdsa_key_index: u32,
  pub expected_mss_index: u32,
  pub ecdsa_key: ECDSAKey,
  pub expiration_delay_seconds: u32,
}

impl AnchorSerialize for AppendECDSAKeyMessage {
  fn serialize<W: Write>(&self, _writer: &mut W) -> std::io::Result<()> {
    panic!("Deliberately not implemented, but trait is required by PostedVaa's generic parameter");
  }
}

impl AnchorDeserialize for AppendECDSAKeyMessage {
  fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
    let mut module = [0; 32];
    reader.read_exact(&mut module)?;
    let action = reader.read_u8()?;

    let ecdsa_key_index = reader.read_u32::<BigEndian>()?;
    let expected_mss_index = reader.read_u32::<BigEndian>()?;
    let ecdsa_key = ECDSAKey::deserialize_reader(reader)?;
    let expiration_delay_seconds = reader.read_u32::<BigEndian>()?;

    // Validate the module and action
    if module != MODULE_VERIFICATION_V2 {
      return Err(Error::new(ErrorKind::InvalidData, "Invalid module"));
    }

    if action != ACTION_APPEND_ECDSA_KEY {
      return Err(Error::new(ErrorKind::InvalidData, "Invalid action"));
    }

    // We check that the rest of the VAA is fine but we don't really need the shards here.
    let mut remaining_bytes = [0; 32];
    if reader.read_exact(&mut remaining_bytes).is_err() {
      return Err(Error::new(ErrorKind::InvalidData, "Invalid payload"));
    }

    if reader.read_u8().is_ok() {
      return Err(Error::new(ErrorKind::InvalidData, "Invalid payload"));
    }

    Ok(Self {
      ecdsa_key_index,
      expected_mss_index,
      ecdsa_key,
      expiration_delay_seconds,
    })
  }
}
