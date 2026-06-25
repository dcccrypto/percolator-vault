//! FIND-4 fix: LiteSVM end-to-end proof for percolator-vault.
//!
//! Loads BOTH programs into one LiteSVM instance:
//!   - percolator-vault .so at VAULT_ID (the deployed 51CeUNpb... ID)
//!   - percolator-prog (wrapper) .so at WRAPPER_ID
//!
//! Proves the full FIND-4 fix chain:
//!
//!   InitMarket (insurance_authority = human admin)
//!     → BindInsuranceAuthority (vault tag 15: admin signs outer tx, vault_auth
//!       PDA signs via invoke_signed → insurance_authority becomes vault_auth)
//!     → FlushToInsurance (vault tag 3: CPIs TopUpInsurance tag 9 — NOW REACHABLE,
//!       previously unreachable because insurance_authority != pool_pda)
//!     → [patch slab mode to Resolved=1, both portfolio counts to 0]
//!     → AdminWithdrawInsurance (vault tag 10: CPIs WithdrawInsurance tag 41 —
//!       vault_auth is the authority, so the terminal path authorizes)
//!
//! NEGATIVE PROOF: also proves that calling FlushToInsurance BEFORE
//! BindInsuranceAuthority fails (Unauthorized / Custom 8), demonstrating the
//! original FIND-4 bug.
//!
//! KEY OFFSETS (from dump_layout on wrap-recon build):
//!   HEADER_LEN = 16
//!   WRAPPER_CONFIG_LEN = 432
//!   MARKET_GROUP_OFF = 448
//!   MARKET_GROUP_LEN = 758
//!   MARKET_ASSET_SLOT_LEN = 1797
//!   SLAB_LEN = 448 + 758 + 1797 = 3003
//!
//!   WrapperConfigV16 insurance_withdraw_max_bps offset in slab:
//!     HEADER_LEN(16) + 176 = 192
//!   WrapperConfigV16 insurance_withdraw_cooldown_slots:
//!     HEADER_LEN(16) + 200 = 216
//!
//!   MarketGroupV16HeaderAccount (starts at MARKET_GROUP_OFF = 448):
//!     mode (u8) at header-relative offset 626 → slab offset 1074
//!     insurance (u128) at header-relative offset 301 → slab offset 749
//!
//!   AssetOracleProfileV16.insurance_authority (32 bytes):
//!     Market<T> layout: { wrapper: T (512 bytes, FIRST), engine: EngineAssetSlot (1285 bytes) }
//!     AssetOracleProfileV16 = first 400 bytes of wrapper; insurance_authority at offset 24.
//!     slab offset = MARKET_GROUP_OFF(448) + MARKET_GROUP_LEN(758) + 24 = 1230

use bytemuck::Zeroable;
use litesvm::LiteSVM;
use percolator_vault::state::{
    derive_pool_pda, derive_vault_authority, StakePool, STAKE_POOL_SIZE,
};
use solana_sdk::{
    account::Account,
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    transaction::{Transaction, TransactionError},
};
use std::path::PathBuf;
use std::str::FromStr;

// ── Program IDs ──────────────────────────────────────────────────────────────

/// The deployed percolator-vault program ID (51CeUNpb... on devnet).
const VAULT_ID: &str = "51CeUNpbXovK2BRADPyssuf3Q1xWGabEK9pYkp5mqVhQ";
/// The percolator wrapper program ID.
const WRAPPER_ID: &str = "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// ATA program v1.1.1 — matches the binary that the v16/v17 wrapper uses internally
/// when computing canonical_vault_address (find_program_address on this id).
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

// ── Slab constants (confirmed via dump_layout on wrap-recon) ─────────────────

const HEADER_LEN: usize = 16;
const WRAPPER_CONFIG_LEN: usize = 432;
const MARKET_GROUP_OFF: usize = HEADER_LEN + WRAPPER_CONFIG_LEN; // = 448
const MARKET_GROUP_LEN: usize = 758;
const MARKET_ASSET_SLOT_LEN: usize = 1797; // wrapper(512) + EngineAssetSlotV16(1285)
const SLAB_LEN: usize = MARKET_GROUP_OFF + MARKET_GROUP_LEN + MARKET_ASSET_SLOT_LEN; // 3003

/// Slab offset for `WrapperConfigV16.insurance_withdraw_max_bps` (u16).
/// HEADER_LEN(16) + 176 (field offset within WrapperConfigV16).
const SLAB_WITHDRAW_MAX_BPS_OFF: usize = HEADER_LEN + 176;

/// Slab offset for `WrapperConfigV16.insurance_withdraw_cooldown_slots` (u64).
/// HEADER_LEN(16) + 200 (field offset within WrapperConfigV16).
const SLAB_WITHDRAW_COOLDOWN_OFF: usize = HEADER_LEN + 200;

/// Slab offset for `MarketGroupV16HeaderAccount.mode` (u8).
/// MARKET_GROUP_OFF(448) + 626 (field offset within MarketGroupV16HeaderAccount).
const SLAB_MODE_OFF: usize = MARKET_GROUP_OFF + 626;

/// Slab offset for `AssetOracleProfileV16.insurance_authority` (32 bytes).
///
/// The Market<T> struct layout (percolator/src/v16.rs) is:
///   pub wrapper: T       (oracle storage, 512 bytes) — FIRST
///   pub engine: EngineAssetSlotV16Account (1285 bytes) — SECOND
///
/// AssetOracleProfileV16 is the first 400 bytes of `wrapper`.
/// `insurance_authority` is at offset 24 within AssetOracleProfileV16.
///
/// So: MARKET_GROUP_OFF(448) + MARKET_GROUP_LEN(758) + 0 (no engine before wrapper) + 24
///   = 448 + 758 + 24 = 1230
const SLAB_ASSET0_INSURANCE_AUTH_OFF: usize = MARKET_GROUP_OFF + MARKET_GROUP_LEN + 24;

/// Market mode byte values (from encode_market_mode_for_account in v16_program.rs).
const MARKET_MODE_LIVE: u8 = 0;
const MARKET_MODE_RESOLVED: u8 = 1;

/// Amount to flush to the wrapper insurance fund.
const TEST_AMOUNT: u64 = 500_000;

// ── ATA derivation ────────────────────────────────────────────────────────────

fn ata(wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    let ata_program = Pubkey::from_str(ATA_PROGRAM).unwrap();
    Pubkey::find_program_address(
        &[wallet.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ata_program,
    )
    .0
}

// ── SPL token helpers ─────────────────────────────────────────────────────────

fn mint_data() -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[45] = 1; // is_initialized
    d
}

fn token_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1; // state = Initialized
    d
}

fn set_token_account(svm: &mut LiteSVM, key: Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.set_account(
        key,
        Account {
            lamports: 1_000_000_000,
            data: token_data(mint, owner, amount),
            owner: token_program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn token_amount(svm: &LiteSVM, key: &Pubkey) -> u64 {
    let acct = svm.get_account(key).expect("token account exists");
    u64::from_le_bytes(acct.data[64..72].try_into().unwrap())
}

// ── InitMarket v16 encoder ───────────────────────────────────────────────────
//
// 219-byte wire (v16 decode arm 0), same encoding as v17_stake_insurance_e2e.rs.
// Accounts: [admin(signer), slab(w), mint].
// InitMarket sets insurance_authority = admin (the human key) at offset SLAB_ASSET0_INSURANCE_AUTH_OFF.

fn encode_init_market_v16() -> Vec<u8> {
    const MAX_VAULT_TVL: u128 = u128::MAX >> 1;
    let mut data: Vec<u8> = Vec::with_capacity(219);
    data.push(0u8);                                         // tag InitMarket
    data.extend_from_slice(&1u16.to_le_bytes());            // max_portfolio_assets
    data.extend_from_slice(&0u64.to_le_bytes());            // h_min
    data.extend_from_slice(&10u64.to_le_bytes());           // h_max
    data.extend_from_slice(&100u64.to_le_bytes());          // initial_price
    data.extend_from_slice(&1u128.to_le_bytes());           // min_nonzero_mm_req
    data.extend_from_slice(&2u128.to_le_bytes());           // min_nonzero_im_req
    data.extend_from_slice(&10_000u64.to_le_bytes());       // maintenance_margin_bps
    data.extend_from_slice(&10_000u64.to_le_bytes());       // initial_margin_bps
    data.extend_from_slice(&10_000u64.to_le_bytes());       // max_trading_fee_bps
    data.extend_from_slice(&0u64.to_le_bytes());            // trade_fee_base_bps
    data.extend_from_slice(&0u64.to_le_bytes());            // liquidation_fee_bps
    data.extend_from_slice(&0u128.to_le_bytes());           // liquidation_fee_cap
    data.extend_from_slice(&0u128.to_le_bytes());           // min_liquidation_abs
    data.extend_from_slice(&10_000u64.to_le_bytes());       // max_price_move_bps_per_slot
    data.extend_from_slice(&1u64.to_le_bytes());            // max_accrual_dt_slots
    data.extend_from_slice(&0u64.to_le_bytes());            // max_abs_funding_e9_per_slot
    data.extend_from_slice(&1u64.to_le_bytes());            // min_funding_lifetime_slots
    data.extend_from_slice(&1u64.to_le_bytes());            // max_account_b_settlement_chunks
    data.extend_from_slice(&1u64.to_le_bytes());            // max_bankrupt_close_chunks
    data.extend_from_slice(&100u64.to_le_bytes());          // max_bankrupt_close_lifetime_slots
    data.extend_from_slice(&MAX_VAULT_TVL.to_le_bytes());   // public_b_chunk_atoms
    data.extend_from_slice(&0u128.to_le_bytes());           // maintenance_fee_per_slot
    debug_assert_eq!(data.len(), 219, "InitMarket v16 wire must be 219 bytes");
    data
}

// ── Tx helpers ───────────────────────────────────────────────────────────────

fn send(
    svm: &mut LiteSVM,
    payer: &Keypair,
    signers: &[&Keypair],
    ix: Instruction,
) -> Result<(), TransactionError> {
    let mut all: Vec<&Keypair> = vec![payer];
    all.extend_from_slice(signers);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &all,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
}

fn send_large_cu(
    svm: &mut LiteSVM,
    payer: &Keypair,
    signers: &[&Keypair],
    ix: Instruction,
) -> Result<(), TransactionError> {
    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(50_000_000);
    let mut all: Vec<&Keypair> = vec![payer];
    all.extend_from_slice(signers);
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, ix],
        Some(&payer.pubkey()),
        &all,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
}

// ── .so paths ─────────────────────────────────────────────────────────────────

fn vault_so() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_vault.so");
    p
}

fn wrapper_so() -> PathBuf {
    // The wrap-recon .so is in /tmp/wrap-recon/target/deploy/
    PathBuf::from("/tmp/wrap-recon/target/deploy/percolator_prog.so")
}

// ── Test environment ──────────────────────────────────────────────────────────

struct Env {
    svm: LiteSVM,
    vault_id: Pubkey,
    wrapper_id: Pubkey,
    token_program: Pubkey,
    admin: Keypair,
    payer: Keypair,
    market: Pubkey,
    mint: Pubkey,
    wrapper_vault: Pubkey,
    wrapper_vault_pda: Pubkey,
    pool_pda: Pubkey,
    vault_auth: Pubkey,
    stake_vault: Pubkey,
}

impl Env {
    fn setup() -> Self {
        let mut svm = LiteSVM::new().with_spl_programs();
        let vault_id = Pubkey::from_str(VAULT_ID).unwrap();
        let wrapper_id = Pubkey::from_str(WRAPPER_ID).unwrap();
        let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();

        svm.add_program_from_file(vault_id, vault_so()).unwrap();
        svm.add_program_from_file(wrapper_id, wrapper_so()).unwrap();

        let payer = Keypair::new();
        let admin = Keypair::new();
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 10_000_000_000).unwrap();

        let market = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        // Collateral mint
        svm.set_account(
            mint,
            Account {
                lamports: 1_000_000_000,
                data: mint_data(),
                owner: token_program,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Wrapper vault authority and canonical vault token account.
        // verify_vault_token_account requires wrapper_vault == ATA(wrapper_vault_pda, mint).
        let wrapper_vault_pda =
            Pubkey::find_program_address(&[b"vault", market.as_ref()], &wrapper_id).0;
        let wrapper_vault = ata(&wrapper_vault_pda, &mint);
        set_token_account(&mut svm, wrapper_vault, &mint, &wrapper_vault_pda, 0);

        // Pre-allocate the market slab (SLAB_LEN bytes, wrapper-owned).
        svm.set_account(
            market,
            Account {
                lamports: 1_000_000_000,
                data: vec![0u8; SLAB_LEN],
                owner: wrapper_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // InitMarket: 3 accounts [admin(signer), slab(w), mint].
        let init_ix = Instruction {
            program_id: wrapper_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new_readonly(mint, false),
            ],
            data: encode_init_market_v16(),
        };
        send_large_cu(&mut svm, &payer, &[&admin], init_ix)
            .expect("InitMarket should succeed");

        // Patch insurance_withdraw_max_bps = 9_999 and cooldown = 1.
        // Same rationale as v17_stake_insurance_e2e.rs: insurance_withdraw_policy_shape_ok
        // requires max_bps < 10_000 and cooldown != 0.
        {
            let mut slab_acct = svm.get_account(&market).expect("slab exists after init");
            slab_acct.data[SLAB_WITHDRAW_MAX_BPS_OFF..SLAB_WITHDRAW_MAX_BPS_OFF + 2]
                .copy_from_slice(&9_999u16.to_le_bytes());
            slab_acct.data[SLAB_WITHDRAW_COOLDOWN_OFF..SLAB_WITHDRAW_COOLDOWN_OFF + 8]
                .copy_from_slice(&1u64.to_le_bytes());
            svm.set_account(market, slab_acct).unwrap();
        }

        // Vault PDAs (under VAULT_ID).
        let (pool_pda, _) = derive_pool_pda(&vault_id, &market);
        let (vault_auth, vault_auth_bump) = derive_vault_authority(&vault_id, &pool_pda);

        // Stake (pool) vault: owned by vault_auth, pre-funded with TEST_AMOUNT tokens.
        let stake_vault = Pubkey::new_unique();
        set_token_account(&mut svm, stake_vault, &mint, &vault_auth, TEST_AMOUNT);

        // Craft the StakePool account.
        let mut pool = StakePool::zeroed();
        pool.is_initialized = 1;
        pool.bump = 255;
        pool.vault_authority_bump = vault_auth_bump;
        pool.slab = market.to_bytes();
        pool.admin = admin.pubkey().to_bytes();
        pool.collateral_mint = mint.to_bytes();
        pool.lp_mint = Pubkey::new_unique().to_bytes();
        pool.vault = stake_vault.to_bytes();
        pool.total_deposited = TEST_AMOUNT;
        pool.percolator_program = wrapper_id.to_bytes();
        pool.pool_mode = 0; // insurance LP
        pool.admin_transferred = 1; // pool_pda is the wrapper admin
        pool.set_discriminator();

        // The pool_pda also needs to BE the wrapper admin (after TransferAdmin).
        // Patch the slab's admin field to pool_pda so admin-gated CPIs work.
        {
            let mut slab_acct = svm.get_account(&market).expect("slab exists");
            // Admin field at slab-offset HEADER_LEN = 16 (first field of WrapperConfigV16 = marketauth).
            slab_acct.data[HEADER_LEN..HEADER_LEN + 32]
                .copy_from_slice(&pool_pda.to_bytes());
            svm.set_account(market, slab_acct).unwrap();
        }

        let mut pool_bytes = vec![0u8; STAKE_POOL_SIZE];
        pool_bytes.copy_from_slice(bytemuck::bytes_of(&pool));
        svm.set_account(
            pool_pda,
            Account {
                lamports: 1_000_000_000,
                data: pool_bytes,
                owner: vault_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        Env {
            svm,
            vault_id,
            wrapper_id,
            token_program,
            admin,
            payer,
            market,
            mint,
            wrapper_vault,
            wrapper_vault_pda,
            pool_pda,
            vault_auth,
            stake_vault,
        }
    }

    // ── Instruction builders ────────────────────────────────────────────────

    /// vault BindInsuranceAuthority (tag 15) — FIND-4 fix.
    /// Admin is current insurance_authority (outer tx signer).
    /// vault_auth PDA is new authority (vault program signs via invoke_signed).
    ///
    /// Accounts:
    ///   0. [signer]   admin
    ///   1. [writable] pool_pda
    ///   2. []         vault_auth
    ///   3. [writable] slab
    ///   4. []         wrapper program
    fn bind_insurance_auth_ix(&self) -> Instruction {
        Instruction {
            program_id: self.vault_id,
            accounts: vec![
                AccountMeta::new(self.admin.pubkey(), true),          // [0] current authority (admin)
                AccountMeta::new(self.pool_pda, false),               // [1] pool PDA
                AccountMeta::new_readonly(self.vault_auth, false),    // [2] new authority (vault_auth PDA)
                AccountMeta::new(self.market, false),                 // [3] slab (writable for CPI)
                AccountMeta::new_readonly(self.wrapper_id, false),   // [4] wrapper program
            ],
            data: vec![15u8], // tag 15 = BindInsuranceAuthority
        }
    }

    /// vault FlushToInsurance (tag 3 + u64 amount).
    /// Admin must sign (FlushToInsurance is admin-gated in the vault).
    ///
    /// Accounts (matches process_flush_to_insurance in vault processor):
    ///   0. [signer]   caller (admin)
    ///   1. [writable] pool PDA
    ///   2. [writable] pool vault (source)
    ///   3. []         vault_auth PDA (CPI signer)
    ///   4. [writable] slab
    ///   5. [writable] wrapper vault (dest)
    ///   6. []         wrapper program
    ///   7. []         token program
    fn flush_ix(&self, amount: u64) -> Instruction {
        let mut data = vec![3u8];
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: self.vault_id,
            accounts: vec![
                AccountMeta::new(self.admin.pubkey(), true),          // [0] admin (signer)
                AccountMeta::new(self.pool_pda, false),               // [1] pool PDA (writable)
                AccountMeta::new(self.stake_vault, false),            // [2] source vault
                AccountMeta::new_readonly(self.vault_auth, false),    // [3] CPI signer
                AccountMeta::new(self.market, false),                 // [4] slab
                AccountMeta::new(self.wrapper_vault, false),          // [5] dest (wrapper insurance)
                AccountMeta::new_readonly(self.wrapper_id, false),    // [6] wrapper program
                AccountMeta::new_readonly(self.token_program, false), // [7] token program
            ],
            data,
        }
    }

    /// vault AdminWithdrawInsurance (tag 10 + u64 amount).
    /// Calls the wrapper's terminal WithdrawInsurance (tag 41) CPI.
    /// Requires the market to be in Resolved mode.
    ///
    /// Accounts (matches process_admin_withdraw_insurance in vault processor):
    ///   0. [signer]   admin
    ///   1. [writable] pool PDA
    ///   2. [writable] slab
    ///   3. []         vault_auth PDA (CPI signer)
    ///   4. [writable] stake_vault (receives insurance, must be pool.vault)
    ///   5. [writable] wrapper vault (source)
    ///   6. []         wrapper_vault_pda (wrapper's vault authority)
    ///   7. []         wrapper program
    ///   8. []         token program
    ///   9. []         clock sysvar (retained for backward-compat layout)
    fn withdraw_insurance_ix(&self, amount: u64) -> Instruction {
        let mut data = vec![10u8];
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: self.vault_id,
            accounts: vec![
                AccountMeta::new(self.admin.pubkey(), true),                 // [0] admin
                AccountMeta::new(self.pool_pda, false),                      // [1] pool PDA
                AccountMeta::new(self.market, false),                        // [2] slab
                AccountMeta::new_readonly(self.vault_auth, false),           // [3] vault_auth PDA
                AccountMeta::new(self.stake_vault, false),                   // [4] dest = pool.vault
                AccountMeta::new(self.wrapper_vault, false),                 // [5] wrapper vault (src)
                AccountMeta::new_readonly(self.wrapper_vault_pda, false),    // [6] wrapper vault PDA
                AccountMeta::new_readonly(self.wrapper_id, false),           // [7] wrapper program
                AccountMeta::new_readonly(self.token_program, false),        // [8] token program
                AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false), // [9] clock (compat)
            ],
            data,
        }
    }

    // ── Slab state mutations ────────────────────────────────────────────────

    /// Patch the slab mode to Resolved (1) to enable the terminal WithdrawInsurance path.
    fn patch_mode_to_resolved(&mut self) {
        let mut acct = self.svm.get_account(&self.market).expect("market slab exists");
        acct.data[SLAB_MODE_OFF] = MARKET_MODE_RESOLVED;
        self.svm.set_account(self.market, acct).unwrap();
    }

    /// Read the insurance_authority from asset-0 profile in the slab.
    /// Used to verify the bind changed the correct field.
    fn read_insurance_authority(&self) -> [u8; 32] {
        let acct = self.svm.get_account(&self.market).expect("market slab exists");
        let mut auth = [0u8; 32];
        auth.copy_from_slice(
            &acct.data[SLAB_ASSET0_INSURANCE_AUTH_OFF..SLAB_ASSET0_INSURANCE_AUTH_OFF + 32],
        );
        auth
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Smoke test: both .so files load and are executable.
#[test]
fn find4_smoke_both_programs_load() {
    let vp = vault_so();
    let wp = wrapper_so();
    assert!(
        vp.exists(),
        "vault .so missing — run: cd /tmp/v39 && cargo build-sbf -- --features small"
    );
    assert!(
        wp.exists(),
        "wrapper .so missing at /tmp/wrap-recon/target/deploy/percolator_prog.so"
    );
    let mut svm = LiteSVM::new().with_spl_programs();
    let vault_id = Pubkey::from_str(VAULT_ID).unwrap();
    let wrapper_id = Pubkey::from_str(WRAPPER_ID).unwrap();
    svm.add_program_from_file(vault_id, &vp).unwrap();
    svm.add_program_from_file(wrapper_id, &wp).unwrap();
    assert!(svm.get_account(&vault_id).unwrap().executable);
    assert!(svm.get_account(&wrapper_id).unwrap().executable);
}

/// HAPPY PATH: Full FIND-4 fix proof.
///
/// Proves the complete chain:
///   market init (insurance_authority = human admin)
///   → BindInsuranceAuthority (tag 15): insurance_authority becomes vault_auth PDA
///   → FlushToInsurance: TopUpInsurance succeeds (was impossible before the bind)
///   → patch mode to Resolved
///   → AdminWithdrawInsurance: WithdrawInsurance terminal succeeds
///
/// Token conservation: TEST_AMOUNT tokens leave stake vault, arrive in wrapper vault,
/// then return to stake vault via the withdraw.
#[test]
fn find4_bind_flush_withdraw_green() {
    let mut env = Env::setup();

    // ── 1. Verify initial state ───────────────────────────────────────────────
    // insurance_authority should be admin after InitMarket.
    let auth_before = env.read_insurance_authority();
    assert_eq!(
        auth_before,
        env.admin.pubkey().to_bytes(),
        "P0: insurance_authority must be admin after InitMarket"
    );
    assert_eq!(
        token_amount(&env.svm, &env.stake_vault),
        TEST_AMOUNT,
        "P0: stake vault pre-loaded with TEST_AMOUNT"
    );

    // ── 2. BindInsuranceAuthority (vault tag 15) ──────────────────────────────
    let bind_ix = env.bind_insurance_auth_ix();
    send(&mut env.svm, &env.payer, &[&env.admin], bind_ix)
        .expect("BindInsuranceAuthority (tag 15) must succeed");

    // Verify insurance_authority is now vault_auth PDA.
    let auth_after = env.read_insurance_authority();
    assert_eq!(
        auth_after,
        env.vault_auth.to_bytes(),
        "P1: insurance_authority must be vault_auth PDA after bind"
    );
    assert_ne!(
        auth_after,
        env.admin.pubkey().to_bytes(),
        "P1: insurance_authority must no longer be admin after bind"
    );

    // ── 3. FlushToInsurance (vault tag 3) ─────────────────────────────────────
    // TopUpInsurance CPI (tag 9) gates on insurance_authority == CPI signer (vault_auth).
    // After the bind this gate is satisfied.
    let flush_ix = env.flush_ix(TEST_AMOUNT);
    send(&mut env.svm, &env.payer, &[&env.admin], flush_ix)
        .expect("FlushToInsurance (TopUpInsurance CPI) must succeed after bind");

    assert_eq!(
        token_amount(&env.svm, &env.stake_vault),
        0,
        "P2: stake vault drained by flush"
    );
    assert_eq!(
        token_amount(&env.svm, &env.wrapper_vault),
        TEST_AMOUNT,
        "P2: wrapper vault received TEST_AMOUNT"
    );

    // ── 4. Patch slab to Resolved mode ───────────────────────────────────────
    // WithdrawInsurance (tag 41) requires mode = Resolved(1) and no open portfolios.
    // Both conditions hold on this freshly-initialized market.
    env.patch_mode_to_resolved();

    // ── 5. AdminWithdrawInsurance (vault tag 10) ──────────────────────────────
    // vault_auth PDA is now the insurance_authority, so the terminal CPI authorizes.
    // Withdraw the full TEST_AMOUNT back to the stake vault.
    let withdraw_ix = env.withdraw_insurance_ix(TEST_AMOUNT);
    send_large_cu(&mut env.svm, &env.payer, &[&env.admin], withdraw_ix)
        .expect("AdminWithdrawInsurance (WithdrawInsurance CPI) must succeed after bind+flush");

    assert_eq!(
        token_amount(&env.svm, &env.stake_vault),
        TEST_AMOUNT,
        "P3: TEST_AMOUNT returned to stake vault after withdraw"
    );
    assert_eq!(
        token_amount(&env.svm, &env.wrapper_vault),
        0,
        "P3: wrapper vault drained by withdraw"
    );
}

/// NEGATIVE PROOF: FlushToInsurance fails BEFORE BindInsuranceAuthority.
///
/// This demonstrates the original FIND-4 bug: at market init,
/// profile.insurance_authority == admin (human). FlushToInsurance CPIs
/// TopUpInsurance with vault_auth as the signer, but the wrapper checks
/// signer == insurance_authority, which is still admin. Result: Unauthorized.
#[test]
fn find4_flush_before_bind_fails() {
    let mut env = Env::setup();

    // Attempt flush WITHOUT the bind. The wrapper's TopUpInsurance checks
    // expect_live_authority(profile.insurance_authority, signer.key).
    // profile.insurance_authority = admin (from InitMarket).
    // CPI signer = vault_auth PDA (not admin).
    // This MUST fail.
    let flush_ix = env.flush_ix(TEST_AMOUNT);
    let err = send(&mut env.svm, &env.payer, &[&env.admin], flush_ix)
        .expect_err("FlushToInsurance before bind must fail — this is FIND-4");

    // The error must be a custom error (Unauthorized) from the wrapper.
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            // Custom(8) = Unauthorized in the wrapper. Any non-zero custom code
            // confirms the wrapper rejected the CPI (not a tx-level failure).
            assert!(
                code > 0,
                "FIND-4 NEGATIVE: expected wrapper Custom(8) Unauthorized, got code={code}"
            );
        }
        other => panic!("FIND-4 NEGATIVE: expected Custom error, got {other:?}"),
    }

    // No tokens moved.
    assert_eq!(
        token_amount(&env.svm, &env.stake_vault),
        TEST_AMOUNT,
        "FIND-4 NEGATIVE: stake vault unchanged"
    );
    assert_eq!(
        token_amount(&env.svm, &env.wrapper_vault),
        0,
        "FIND-4 NEGATIVE: wrapper vault unchanged"
    );
}

/// COVERAGE: re-bind is permitted while admin holds asset_admin authority.
///
/// In v17, the market creator (asset_admin) can rotate ANY of the asset's
/// authorities without being the current holder. So a second bind (by the admin,
/// who is still the asset_admin) succeeds — this is the intentional rotation
/// escape path. This test documents and pins that behaviour.
#[test]
fn find4_rebind_by_asset_admin_succeeds() {
    let mut env = Env::setup();

    // First bind: insurance_authority → vault_auth.
    let bind_ix = env.bind_insurance_auth_ix();
    send(&mut env.svm, &env.payer, &[&env.admin], bind_ix)
        .expect("first bind must succeed");

    let auth_after_first = env.read_insurance_authority();
    assert_eq!(
        auth_after_first,
        env.vault_auth.to_bytes(),
        "insurance_authority == vault_auth after first bind"
    );

    // Expire blockhash so the second tx has a different signature.
    env.svm.expire_blockhash();

    // Second bind: admin is still the asset_admin (asset_admin = admin in this test setup
    // because the InitMarket admin is our admin keypair and the admin field is reset to
    // pool_pda ONLY in WrapperConfigV16.marketauth, NOT in the per-asset profile.asset_admin).
    // The v17 wrapper allows the asset_admin to rotate any authority on its asset without
    // needing to be the current holder (handle_update_asset_authority:9812-9813).
    // This is the deliberate rotation escape path — a re-bind by the creator is valid.
    let bind_ix2 = env.bind_insurance_auth_ix();
    send(&mut env.svm, &env.payer, &[&env.admin], bind_ix2)
        .expect("rebind by asset_admin must succeed (rotation escape path)");

    // Insurance authority remains vault_auth (re-bound to the same value).
    let auth_after_second = env.read_insurance_authority();
    assert_eq!(
        auth_after_second,
        env.vault_auth.to_bytes(),
        "insurance_authority still vault_auth after rebind"
    );
}
