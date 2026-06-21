//! CPI tag verification tests.
//!
//! Cross-references the standalone vault CPI wire data with the current
//! percolator-prog wrapper ABI in `origin/main:src/v16_program.rs`.

use percolator_vault::cpi::{
    ASSET_AUTH_INSURANCE, ASSET_AUTH_ORACLE, TAG_RESOLVE_MARKET, TAG_TOP_UP_INSURANCE,
    TAG_UPDATE_ASSET_AUTHORITY, TAG_UPDATE_AUTHORITY, TAG_WITHDRAW_INSURANCE,
};

#[test]
fn test_cpi_tag_top_up_insurance_uses_current_u128_wire() {
    let data = build_cpi_data_top_up(1000);
    assert_eq!(data[0], TAG_TOP_UP_INSURANCE);
    assert_eq!(data.len(), 17, "TopUpInsurance is tag + u128 amount");
    assert_eq!(&data[1..17], &(1000u128).to_le_bytes());
}

#[test]
fn test_cpi_tag_update_authority_replaces_retired_update_admin() {
    let data = build_cpi_data_update_authority();
    assert_eq!(data[0], TAG_UPDATE_AUTHORITY);
    assert_eq!(data.len(), 33);
    assert_ne!(data[0], 12, "tag 12 UpdateAdmin is retired in the current wrapper");
}

#[test]
fn test_cpi_tag_update_asset_oracle_authority() {
    let data = build_cpi_data_update_asset_authority(ASSET_AUTH_ORACLE);
    assert_eq!(data[0], TAG_UPDATE_ASSET_AUTHORITY);
    assert_eq!(&data[1..3], &0u16.to_le_bytes(), "vault rotates asset 0");
    assert_eq!(data[3], ASSET_AUTH_ORACLE);
    assert_eq!(data.len(), 36);
}

#[test]
fn test_cpi_tag_update_asset_insurance_authority() {
    let data = build_cpi_data_update_asset_authority(ASSET_AUTH_INSURANCE);
    assert_eq!(data[0], TAG_UPDATE_ASSET_AUTHORITY);
    assert_eq!(&data[1..3], &0u16.to_le_bytes(), "vault rotates asset 0");
    assert_eq!(data[3], ASSET_AUTH_INSURANCE);
    assert_eq!(data.len(), 36);
}

#[test]
fn test_cpi_tag_resolve_market() {
    let data = build_cpi_data_resolve();
    assert_eq!(data[0], TAG_RESOLVE_MARKET);
    assert_eq!(data.len(), 1);
}

#[test]
fn test_cpi_tag_withdraw_insurance_uses_terminal_current_wire() {
    let data = build_cpi_data_withdraw_insurance(500);
    assert_eq!(data[0], TAG_WITHDRAW_INSURANCE);
    assert_eq!(data.len(), 17, "WithdrawInsurance is tag + u128 amount");
    assert_eq!(&data[1..17], &(500u128).to_le_bytes());
}

#[test]
fn test_retired_policy_tags_are_not_used() {
    assert_ne!(
        TAG_WITHDRAW_INSURANCE, 31,
        "tag 31 is not decoded by current percolator-prog"
    );
    assert_ne!(
        TAG_WITHDRAW_INSURANCE, 30,
        "tag 30 is CloseResolved in current percolator-prog"
    );
}

fn build_cpi_data_top_up(amount: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(17);
    data.push(TAG_TOP_UP_INSURANCE);
    data.extend_from_slice(&(amount as u128).to_le_bytes());
    data
}

fn build_cpi_data_update_authority() -> Vec<u8> {
    let mut data = Vec::with_capacity(33);
    data.push(TAG_UPDATE_AUTHORITY);
    data.extend_from_slice(&[0u8; 32]);
    data
}

fn build_cpi_data_update_asset_authority(kind: u8) -> Vec<u8> {
    let mut data = Vec::with_capacity(36);
    data.push(TAG_UPDATE_ASSET_AUTHORITY);
    data.extend_from_slice(&0u16.to_le_bytes());
    data.push(kind);
    data.extend_from_slice(&[0u8; 32]);
    data
}

fn build_cpi_data_resolve() -> Vec<u8> {
    vec![TAG_RESOLVE_MARKET]
}

fn build_cpi_data_withdraw_insurance(amount: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(17);
    data.push(TAG_WITHDRAW_INSURANCE);
    data.extend_from_slice(&(amount as u128).to_le_bytes());
    data
}
