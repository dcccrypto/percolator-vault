//! CPI helpers for calling the current percolator wrapper ABI.
//!
//! We construct raw instruction data manually since this crate intentionally
//! avoids depending on percolator-prog. Keep these tags/wire layouts aligned
//! with dcccrypto/percolator-prog `origin/main:src/v16_program.rs`.
#![allow(clippy::too_many_arguments)]

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
    program_error::ProgramError,
};

// Current wrapper instruction tags.
pub const TAG_TOP_UP_INSURANCE: u8 = 9;
pub const TAG_RESOLVE_MARKET: u8 = 19;
pub const TAG_UPDATE_AUTHORITY: u8 = 32;
pub const TAG_UPDATE_ASSET_AUTHORITY: u8 = 65;
pub const TAG_WITHDRAW_INSURANCE: u8 = 41;

// Current wrapper asset-authority kind values.
pub const ASSET_AUTH_INSURANCE: u8 = 1;
pub const ASSET_AUTH_ORACLE: u8 = 4;

fn push_u128_from_u64(out: &mut Vec<u8>, amount: u64) {
    out.extend_from_slice(&(amount as u128).to_le_bytes());
}

// ═══════════════════════════════════════════════════════════════
// TopUpInsurance (tag 9)
// ═══════════════════════════════════════════════════════════════
// Accounts: [authority(signer), market(w), source_token(w), vault_token(w), token_program]
// Data: tag(1) + amount(16)

pub fn cpi_top_up_insurance<'a>(
    percolator_program: &AccountInfo<'a>,
    signer: &AccountInfo<'a>, // vault_auth PDA once asset-0 insurance authority is rotated
    slab: &AccountInfo<'a>,
    signer_ata: &AccountInfo<'a>, // stake vault, owned by vault_auth
    wrapper_vault: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    amount: u64,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = Vec::with_capacity(17);
    data.push(TAG_TOP_UP_INSURANCE);
    push_u128_from_u64(&mut data, amount);

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*signer.key, true),
            AccountMeta::new(*slab.key, false),
            AccountMeta::new(*signer_ata.key, false),
            AccountMeta::new(*wrapper_vault.key, false),
            AccountMeta::new_readonly(*token_program.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            signer.clone(),
            slab.clone(),
            signer_ata.clone(),
            wrapper_vault.clone(),
            token_program.clone(),
        ],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// UpdateAuthority (tag 32)
// ═══════════════════════════════════════════════════════════════
// Accounts: [current_authority(signer), new_authority(signer), market(w)]
// Data: tag(1) + new_authority(32)

pub fn cpi_update_authority<'a>(
    percolator_program: &AccountInfo<'a>,
    current_admin: &AccountInfo<'a>,
    new_authority: &AccountInfo<'a>,
    slab: &AccountInfo<'a>,
    new_authority_seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = Vec::with_capacity(33);
    data.push(TAG_UPDATE_AUTHORITY);
    data.extend_from_slice(new_authority.key.as_ref());

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*current_admin.key, true),
            AccountMeta::new_readonly(*new_authority.key, true),
            AccountMeta::new(*slab.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[current_admin.clone(), new_authority.clone(), slab.clone()],
        &[new_authority_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// UpdateAssetAuthority (tag 65)
// ═══════════════════════════════════════════════════════════════
// Accounts: [current_authority(signer), new_authority(signer), market(w)]
// Data: tag(1) + asset_index(2) + kind(1) + new_authority(32)

pub fn cpi_update_asset_authority<'a>(
    percolator_program: &AccountInfo<'a>,
    current_authority: &AccountInfo<'a>,
    new_authority: &AccountInfo<'a>,
    slab: &AccountInfo<'a>,
    asset_index: u16,
    kind: u8,
    signer_seeds: &[&[&[u8]]],
) -> ProgramResult {
    let mut data = Vec::with_capacity(36);
    data.push(TAG_UPDATE_ASSET_AUTHORITY);
    data.extend_from_slice(&asset_index.to_le_bytes());
    data.push(kind);
    data.extend_from_slice(new_authority.key.as_ref());

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*current_authority.key, true),
            AccountMeta::new_readonly(*new_authority.key, true),
            AccountMeta::new(*slab.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            current_authority.clone(),
            new_authority.clone(),
            slab.clone(),
        ],
        signer_seeds,
    )
}

// ═══════════════════════════════════════════════════════════════
// Retired wrapper admin paths
// ═══════════════════════════════════════════════════════════════

pub fn cpi_set_risk_threshold<'a>(
    _percolator_program: &AccountInfo<'a>,
    _admin_pda: &AccountInfo<'a>,
    _slab: &AccountInfo<'a>,
    _new_threshold: u128,
    _admin_seeds: &[&[u8]],
) -> ProgramResult {
    Err(ProgramError::InvalidInstructionData)
}

pub fn cpi_set_maintenance_fee<'a>(
    _percolator_program: &AccountInfo<'a>,
    _admin_pda: &AccountInfo<'a>,
    _slab: &AccountInfo<'a>,
    _new_fee: u128,
    _admin_seeds: &[&[u8]],
) -> ProgramResult {
    Err(ProgramError::InvalidInstructionData)
}

// ═══════════════════════════════════════════════════════════════
// ResolveMarket (tag 19)
// ═══════════════════════════════════════════════════════════════
// Accounts: [admin(signer), market(w)]
// Data: tag(1)

pub fn cpi_resolve_market<'a>(
    percolator_program: &AccountInfo<'a>,
    admin_pda: &AccountInfo<'a>,
    slab: &AccountInfo<'a>,
    admin_seeds: &[&[u8]],
) -> ProgramResult {
    let data = vec![TAG_RESOLVE_MARKET];

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin_pda.key, true),
            AccountMeta::new(*slab.key, false),
        ],
        data,
    };

    invoke_signed(&ix, &[admin_pda.clone(), slab.clone()], &[admin_seeds])
}

// ═══════════════════════════════════════════════════════════════
// WithdrawInsurance (tag 41)
// ═══════════════════════════════════════════════════════════════
// Accounts: [authority(signer), market(w), dest_token(w), vault_token(w),
//            wrapper_vault_authority, token_program]
// Data: tag(1) + amount(16)

pub fn cpi_withdraw_insurance<'a>(
    percolator_program: &AccountInfo<'a>,
    authority: &AccountInfo<'a>, // vault_auth PDA after asset-0 insurance authority is rotated
    slab: &AccountInfo<'a>,
    dest_token: &AccountInfo<'a>, // stake vault, owned by vault_auth
    wrapper_vault: &AccountInfo<'a>,
    wrapper_vault_authority: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    amount: u64,
    authority_seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = Vec::with_capacity(17);
    data.push(TAG_WITHDRAW_INSURANCE);
    push_u128_from_u64(&mut data, amount);

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*authority.key, true),
            AccountMeta::new(*slab.key, false),
            AccountMeta::new(*dest_token.key, false),
            AccountMeta::new(*wrapper_vault.key, false),
            AccountMeta::new_readonly(*wrapper_vault_authority.key, false),
            AccountMeta::new_readonly(*token_program.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            authority.clone(),
            slab.clone(),
            dest_token.clone(),
            wrapper_vault.clone(),
            wrapper_vault_authority.clone(),
            token_program.clone(),
        ],
        &[authority_seeds],
    )
}
