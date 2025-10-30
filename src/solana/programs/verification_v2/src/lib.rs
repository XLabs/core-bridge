#![allow(unexpected_cfgs)]

declare_id!("GbFfTqMqKDgAMRH8VmDmoLTdvDd1853TnkkEwpydv3J6");

mod vaa;
mod append_schnorr_key_message;
mod append_ecdsa_key_message;
mod schnorr_key;
mod ecdsa_key;
mod schnorr_signature;
mod ecdsa_signature;
mod hex_literal;

use anchor_lang::prelude::*;
#[cfg(feature = "idl-build")]
use anchor_lang::IdlBuild;

use wormhole_anchor_sdk::wormhole::{constants::CHAIN_ID_SOLANA, PostedVaa, SignatureSetData};

use vaa::{VAAHeader, VAASignature};
use append_schnorr_key_message::AppendSchnorrKeyMessage;
use append_ecdsa_key_message::AppendECDSAKeyMessage;
use schnorr_key::SchnorrKeyAccount;
use ecdsa_key::ECDSAKeyAccount;
use schnorr_signature::VAASchnorrSignature;
use ecdsa_signature::VAAECDSASignature;
use hex_literal::hex;

pub const DIGEST_SIZE: usize = 32;

const GOVERNANCE_ADDRESS: [u8; 32] =
  hex!("0000000000000000000000000000000000000000000000000000000000000004");

// Module ID for the VerificationV2 contract, ASCII "TSS"
pub const MODULE_VERIFICATION_V2: [u8; 32] =
  hex!("0000000000000000000000000000000000000000000000000000000000545353");

// Action IDs for appending keys
pub const ACTION_APPEND_SCHNORR_KEY: u8 = 0x01;
pub const ACTION_APPEND_ECDSA_KEY: u8 = 0x02;

#[error_code]
pub enum VerificationV2Error {
  InvalidGovernanceChainId,
  InvalidGovernanceAddress,
  InvalidSignatureSet,
  InvalidGuardianSet,
  InvalidOldSchnorrKey,
  InvalidOldECDSAKey,
  SchnorrKeyExpired,
  ECDSAKeyExpired,
  InvalidAccounts,
  NewKeyIndexNotDirectSuccessor,
  IndexMismatch,
}

// Generic trait for key accounts to eliminate duplication
pub trait KeyAccount {
  fn index(&self) -> u32;
  fn is_unexpired(&self) -> bool;
  fn update_expiration_timestamp(&mut self, time_lapse: u64);
}

// Macro to implement KeyAccount trait for types with index and expiration_timestamp fields
macro_rules! impl_key_account {
  ($type:ty) => {
    impl KeyAccount for $type {
      fn index(&self) -> u32 {
        self.index
      }

      fn is_unexpired(&self) -> bool {
        self.expiration_timestamp == 0 || self.expiration_timestamp > Clock::get().unwrap().unix_timestamp as u64
      }

      fn update_expiration_timestamp(&mut self, time_lapse: u64) {
        let current_timestamp = Clock::get().unwrap().unix_timestamp as u64;
        self.expiration_timestamp = current_timestamp + time_lapse;
      }
    }
  };
}

impl_key_account!(SchnorrKeyAccount);
impl_key_account!(ECDSAKeyAccount);

#[account]
#[derive(InitSpace)]
pub struct LatestSchnorrKeyAccount {
  pub account: Pubkey,
}

impl LatestSchnorrKeyAccount {
  const SEED_PREFIX: &'static [u8] = b"latestschnorrkey";
}

#[account]
#[derive(InitSpace)]
pub struct LatestECDSAKeyAccount {
  pub account: Pubkey,
}

impl LatestECDSAKeyAccount {
  const SEED_PREFIX: &'static [u8] = b"latestecdsakey";
}

#[derive(Accounts)]
pub struct AppendSchnorrKey<'info> {
  #[account(mut)]
  pub payer: Signer<'info>,

  #[account(
    constraint = vaa.meta.emitter_chain == CHAIN_ID_SOLANA
      @ VerificationV2Error::InvalidGovernanceChainId,
    constraint = vaa.meta.emitter_address == GOVERNANCE_ADDRESS
      @ VerificationV2Error::InvalidGovernanceAddress,
    constraint = vaa.meta.signature_set == signature_set.key()
      @ VerificationV2Error::InvalidSignatureSet,
  )]
  pub vaa: Account<'info, PostedVaa::<AppendSchnorrKeyMessage>>,

  /// CHECK: need to deserialize manually because Anchor 0.31.1 does not support empty discriminators.
  pub signature_set: UncheckedAccount<'info>,

  #[account(
    init_if_needed,
    payer = payer,
    space = 8 + LatestSchnorrKeyAccount::INIT_SPACE,
    seeds = [LatestSchnorrKeyAccount::SEED_PREFIX],
    bump
  )]
  pub latest_schnorr_key: Account<'info, LatestSchnorrKeyAccount>,

  #[account(
    init,
    payer = payer,
    space = 8 + SchnorrKeyAccount::INIT_SPACE,
    seeds = [SchnorrKeyAccount::SEED_PREFIX, &vaa.data().schnorr_key_index.to_le_bytes()],
    bump
  )]
  pub new_schnorr_key: Account<'info, SchnorrKeyAccount>,

  #[account(
    mut,
    constraint = old_schnorr_key.key() == latest_schnorr_key.account
      @ VerificationV2Error::InvalidOldSchnorrKey,
  )]
  pub old_schnorr_key: Option<Account<'info, SchnorrKeyAccount>>,

  pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AppendECDSAKey<'info> {
  #[account(mut)]
  pub payer: Signer<'info>,

  #[account(
    constraint = vaa.meta.emitter_chain == CHAIN_ID_SOLANA
      @ VerificationV2Error::InvalidGovernanceChainId,
    constraint = vaa.meta.emitter_address == GOVERNANCE_ADDRESS
      @ VerificationV2Error::InvalidGovernanceAddress,
    constraint = vaa.meta.signature_set == signature_set.key()
      @ VerificationV2Error::InvalidSignatureSet,
  )]
  pub vaa: Account<'info, PostedVaa::<AppendECDSAKeyMessage>>,

  /// CHECK: need to deserialize manually because Anchor 0.31.1 does not support empty discriminators.
  pub signature_set: UncheckedAccount<'info>,

  #[account(
    init_if_needed,
    payer = payer,
    space = 8 + LatestECDSAKeyAccount::INIT_SPACE,
    seeds = [LatestECDSAKeyAccount::SEED_PREFIX],
    bump
  )]
  pub latest_ecdsa_key: Account<'info, LatestECDSAKeyAccount>,

  #[account(
    init,
    payer = payer,
    space = 8 + ECDSAKeyAccount::INIT_SPACE,
    seeds = [ECDSAKeyAccount::SEED_PREFIX, &vaa.data().ecdsa_key_index.to_le_bytes()],
    bump
  )]
  pub new_ecdsa_key: Account<'info, ECDSAKeyAccount>,

  #[account(
    mut,
    constraint = old_ecdsa_key.key() == latest_ecdsa_key.account
      @ VerificationV2Error::InvalidOldECDSAKey,
  )]
  pub old_ecdsa_key: Option<Account<'info, ECDSAKeyAccount>>,

  pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(raw_vaa: Vec<u8>)]
pub struct VerifyVaa<'info> {
  #[account(
    constraint = {
      let version = raw_vaa.first().copied().unwrap_or(0);
      version == 2 || version == 3
    } @ VerificationV2Error::InvalidAccounts,
  )]
  /// CHECK: need to deserialize manually because its type depends on the version
  pub key_account: UncheckedAccount<'info>,
}

#[program]
pub mod verification_v2 {
  use super::*;

  pub fn append_schnorr_key(ctx: Context<AppendSchnorrKey>) -> Result<()> {
    validate_signature_set(
      &ctx.accounts.signature_set,
      ctx.accounts.vaa.data().expected_mss_index
    )?;

    let new_key_index = ctx.accounts.vaa.data().schnorr_key_index;
    
    // Validate index succession
    if let Some(old) = &ctx.accounts.old_schnorr_key {
      require_eq!(
        old.index + 1,
        new_key_index,
        VerificationV2Error::NewKeyIndexNotDirectSuccessor,
      );
    }

    update_expiration_timestamp(
      ctx.accounts.latest_schnorr_key.account == Pubkey::default(),
      ctx.accounts.old_schnorr_key.as_deref_mut(),
      ctx.accounts.vaa.data().expiration_delay_seconds,
    )?;

    ctx.accounts.new_schnorr_key.set_inner(SchnorrKeyAccount {
      index: new_key_index,
      schnorr_key: ctx.accounts.vaa.data().schnorr_key.clone(),
      expiration_timestamp: 0,
    });

    ctx.accounts.latest_schnorr_key.account = ctx.accounts.new_schnorr_key.key();

    Ok(())
  }

  pub fn append_ecdsa_key(ctx: Context<AppendECDSAKey>) -> Result<()> {
    validate_signature_set(
      &ctx.accounts.signature_set,
      ctx.accounts.vaa.data().expected_mss_index
    )?;

    let new_key_index = ctx.accounts.vaa.data().ecdsa_key_index;
    
    // Validate index succession
    if let Some(old) = &ctx.accounts.old_ecdsa_key {
      require_eq!(
        old.index + 1,
        new_key_index,
        VerificationV2Error::NewKeyIndexNotDirectSuccessor,
      );
    }

    update_expiration_timestamp(
      ctx.accounts.latest_ecdsa_key.account == Pubkey::default(),
      ctx.accounts.old_ecdsa_key.as_deref_mut(),
      ctx.accounts.vaa.data().expiration_delay_seconds,
    )?;

    ctx.accounts.new_ecdsa_key.set_inner(ECDSAKeyAccount {
      index: new_key_index,
      ecdsa_key: ctx.accounts.vaa.data().ecdsa_key.clone(),
      expiration_timestamp: 0,
    });

    ctx.accounts.latest_ecdsa_key.account = ctx.accounts.new_ecdsa_key.key();

    Ok(())
  }

  pub fn verify_vaa(ctx: Context<VerifyVaa>, raw_vaa: Vec<u8>) -> Result<()> {
    verify_vaa_impl(ctx, raw_vaa)?;
    Ok(())
  }

  pub fn verify_vaa_and_decode(ctx: Context<VerifyVaa>, raw_vaa: Vec<u8>) -> Result<Vec<u8>> {
    verify_vaa_impl(ctx, raw_vaa)
  }

  #[inline(always)]
  pub fn verify_vaa_header_with_digest(
    ctx: Context<VerifyVaa>,
    raw_vaa_header: Vec<u8>,
    digest: [u8; DIGEST_SIZE]
  ) -> Result<()> {
    let mut reader = raw_vaa_header.as_slice();
    let header = VAAHeader::deserialize(&mut reader)
      .map_err(|_| VerificationV2Error::InvalidAccounts)?;
    
    verify_signature_by_version(ctx, header.version, header.key_index, header.signature, digest)
  }
}

fn validate_signature_set(signature_set: &UncheckedAccount, expected_mss_index: u32) -> Result<()> {
  let buf = signature_set.try_borrow_data()?;
  let signature_set_data: Vec<u8> = buf.to_vec();
  let signature_set: SignatureSetData = AccountDeserialize::try_deserialize_unchecked(&mut signature_set_data.as_slice())?;
  require_gte!(
    signature_set.guardian_set_index,
    expected_mss_index,
    VerificationV2Error::InvalidGuardianSet,
  );
  Ok(())
}

fn update_expiration_timestamp<T: KeyAccount>(
  latest_account_is_default: bool,
  old_key: Option<&mut T>,
  expiration_delay_seconds: u32,
) -> Result<()> {
  require_eq!(
    latest_account_is_default,
    old_key.is_none(),
    VerificationV2Error::InvalidAccounts,
  );

  if let Some(old) = old_key {
    old.update_expiration_timestamp(expiration_delay_seconds as u64);
  }

  Ok(())
}

fn verify_signature_by_version(
  ctx: Context<VerifyVaa>,
  version: u8,
  key_index: u32,
  signature: VAASignature,
  digest: [u8; DIGEST_SIZE]
) -> Result<()> {
  match version {
    2 => {
      // Schnorr signature (version 2)
      if let VAASignature::Schnorr(sig) = signature {
        verify_schnorr(ctx, key_index, &sig, digest)
      } else {
        Err(VerificationV2Error::InvalidAccounts.into())
      }
    },
    3 => {
      // ECDSA signature (version 3)
      if let VAASignature::ECDSA(sig) = signature {
        verify_ecdsa(ctx, key_index, &sig, digest)
      } else {
        Err(VerificationV2Error::InvalidAccounts.into())
      }
    },
    _ => Err(VerificationV2Error::InvalidAccounts.into())
  }
}

fn verify_vaa_impl(ctx: Context<VerifyVaa>, raw_vaa: Vec<u8>) -> Result<Vec<u8>> {
  use anchor_lang::solana_program::keccak::hash;
  use std::io::Read;
  
  let mut reader = raw_vaa.as_slice();
  
  // Parse header
  let header = VAAHeader::deserialize(&mut reader)
    .map_err(|_| VerificationV2Error::InvalidAccounts)?;
  
  // Read the body
  let mut body = Vec::new();
  reader.read_to_end(&mut body)?;
  
  // Compute digest: keccak256(keccak256(body))
  let first_hash = hash(&body);
  let digest = hash(&first_hash.to_bytes());
  
  verify_signature_by_version(ctx, header.version, header.key_index, header.signature, digest.to_bytes())?;
  
  Ok(body)
}

#[inline(always)]
fn verify_schnorr(
  ctx: Context<VerifyVaa>,
  index: u32,
  signature: &VAASchnorrSignature,
  digest: [u8; DIGEST_SIZE]
) -> Result<()> {
  let data = ctx.accounts.key_account.try_borrow_data()?;
  let schnorr_key = SchnorrKeyAccount::try_deserialize(&mut data.as_ref())?;
  
  require!(schnorr_key.is_unexpired(), VerificationV2Error::SchnorrKeyExpired);
  require_eq!(index, schnorr_key.index, VerificationV2Error::IndexMismatch);
  schnorr_key.schnorr_key.check_signature(&digest, signature)?;
  Ok(())
}

#[inline(always)]
fn verify_ecdsa(
  ctx: Context<VerifyVaa>,
  index: u32,
  signature: &VAAECDSASignature,
  digest: [u8; DIGEST_SIZE]
) -> Result<()> {
  let data = ctx.accounts.key_account.try_borrow_data()?;
  let ecdsa_key = ECDSAKeyAccount::try_deserialize(&mut data.as_ref())?;
  
  require!(ecdsa_key.is_unexpired(), VerificationV2Error::ECDSAKeyExpired);
  require_eq!(index, ecdsa_key.index, VerificationV2Error::IndexMismatch);
  ecdsa_key.ecdsa_key.check_signature(&digest, signature)?;
  Ok(())
}





