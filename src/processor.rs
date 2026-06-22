use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::invoke,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::{clock::Clock, Sysvar},
};

/// Verify the token program is the real SPL Token program.
/// CRITICAL: Without this check, an attacker can pass a fake token program,
/// receive PDA signer authority via invoke_signed, and drain the vault.
fn verify_token_program(token_program: &AccountInfo) -> ProgramResult {
    if *token_program.key != spl_token::id() {
        msg!("Error: invalid token program {}", token_program.key);
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}

use solana_program::program_pack::Pack;

use crate::cpi;
use crate::error::StakeError;
use crate::instruction::StakeInstruction;
use crate::state::{
    self, derive_vault_authority, StakeDeposit, StakePool, STAKE_DEPOSIT_SIZE, STAKE_POOL_SIZE,
};

pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = StakeInstruction::unpack(instruction_data)?;

    match instruction {
        StakeInstruction::InitPool {
            cooldown_slots,
            deposit_cap,
        } => process_init_pool(program_id, accounts, cooldown_slots, deposit_cap),
        StakeInstruction::Deposit { amount } => process_deposit(program_id, accounts, amount),
        StakeInstruction::Withdraw { lp_amount } => {
            process_withdraw(program_id, accounts, lp_amount)
        }
        StakeInstruction::FlushToInsurance { amount } => {
            process_flush_to_insurance(program_id, accounts, amount)
        }
        StakeInstruction::UpdateConfig {
            new_cooldown_slots,
            new_deposit_cap,
        } => process_update_config(program_id, accounts, new_cooldown_slots, new_deposit_cap),
        StakeInstruction::TransferAdmin => process_transfer_admin(program_id, accounts),
        StakeInstruction::AdminSetOracleAuthority { new_authority } => {
            process_admin_set_oracle_authority(program_id, accounts, &new_authority)
        }
        StakeInstruction::AdminSetRiskThreshold { new_threshold } => {
            process_admin_set_risk_threshold(program_id, accounts, new_threshold)
        }
        StakeInstruction::AdminSetMaintenanceFee { new_fee } => {
            process_admin_set_maintenance_fee(program_id, accounts, new_fee)
        }
        StakeInstruction::AdminResolveMarket => process_admin_resolve_market(program_id, accounts),
        StakeInstruction::AdminWithdrawInsurance { amount } => {
            process_admin_withdraw_insurance(program_id, accounts, amount)
        }
        StakeInstruction::AdminSetInsurancePolicy {
            authority,
            min_withdraw_base,
            max_withdraw_bps,
            cooldown_slots,
        } => process_admin_set_insurance_policy(
            program_id,
            accounts,
            &authority,
            min_withdraw_base,
            max_withdraw_bps,
            cooldown_slots,
        ),
        StakeInstruction::AccrueFees => process_accrue_fees(program_id, accounts),
        StakeInstruction::InitTradingPool {
            cooldown_slots,
            deposit_cap,
        } => process_init_trading_pool(program_id, accounts, cooldown_slots, deposit_cap),
        StakeInstruction::AdminSetHwmConfig {
            enabled,
            hwm_floor_bps,
        } => process_admin_set_hwm_config(program_id, accounts, enabled, hwm_floor_bps),
    }
}

// ═══════════════════════════════════════════════════════════════
// Helper: read pool, validate, return admin seeds
// ═══════════════════════════════════════════════════════════════

/// Validate pool is initialized, admin is signer, admin is transferred,
/// and percolator program matches stored value.
/// Returns the pool bump for PDA signing.
fn validate_admin_cpi(
    program_id: &Pubkey,
    pool_pda: &AccountInfo,
    admin: &AccountInfo,
    slab: &AccountInfo,
    percolator_program: &AccountInfo,
) -> Result<u8, ProgramError> {
    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let pool_data = pool_pda.try_borrow_data()?;
    let pool: &StakePool = bytemuck::from_bytes(&pool_data[..STAKE_POOL_SIZE]);

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if pool.admin != admin.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }
    if pool.admin_transferred != 1 {
        return Err(StakeError::AdminNotTransferred.into());
    }
    if pool.slab != slab.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }
    if pool.percolator_program != percolator_program.key.to_bytes() {
        return Err(StakeError::InvalidPercolatorProgram.into());
    }

    // Verify pool PDA derivation
    let (expected_pool, bump) = state::derive_pool_pda(program_id, slab.key);
    if *pool_pda.key != expected_pool {
        return Err(StakeError::InvalidPda.into());
    }

    Ok(bump)
}

/// FlushToInsurance moves idle insurance-pool liquidity into the wrapper's
/// insurance fund. Trading LP pools use vault-balance deltas for fee accrual,
/// so allowing them to flush principal makes AccrueFees compare against the
/// wrong baseline and can strand later fees below the flushed amount.
fn validate_flush_pool_mode(pool: &StakePool) -> ProgramResult {
    if pool.pool_mode != 0 {
        msg!("FlushToInsurance: pool is not an insurance LP pool");
        return Err(StakeError::InvalidPoolMode.into());
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 0: InitPool
// ═══════════════════════════════════════════════════════════════

fn process_init_pool(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    cooldown_slots: u64,
    deposit_cap: u64,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let lp_mint = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;
    let collateral_mint = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;
    let rent_sysvar = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Derive and verify pool PDA
    let (expected_pool, pool_bump) = state::derive_pool_pda(program_id, slab.key);
    if *pool_pda.key != expected_pool {
        return Err(StakeError::InvalidPda.into());
    }

    if !pool_pda.data_is_empty() {
        return Err(StakeError::AlreadyInitialized.into());
    }

    // Derive vault authority
    let (expected_vault_auth, vault_auth_bump) =
        state::derive_vault_authority(program_id, &expected_pool);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidPda.into());
    }

    // Validate token program BEFORE any invoke_signed that grants PDA signer authority
    verify_token_program(token_program)?;

    let rent = Rent::from_account_info(rent_sysvar)?;

    // Create pool PDA account
    let pool_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &[pool_bump]];
    invoke_signed(
        &system_instruction::create_account(
            admin.key,
            pool_pda.key,
            rent.minimum_balance(STAKE_POOL_SIZE),
            STAKE_POOL_SIZE as u64,
            program_id,
        ),
        &[admin.clone(), pool_pda.clone(), system_program.clone()],
        &[pool_seeds],
    )?;

    // Create LP mint (authority = vault_auth PDA)
    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];
    invoke_signed(
        &spl_token::instruction::initialize_mint(
            token_program.key,
            lp_mint.key,
            vault_auth.key,
            Some(vault_auth.key),
            6,
        )?,
        &[lp_mint.clone(), rent_sysvar.clone()],
        &[vault_auth_seeds],
    )?;

    // Initialize vault token account (authority = vault_auth PDA)
    invoke_signed(
        &spl_token::instruction::initialize_account(
            token_program.key,
            vault.key,
            collateral_mint.key,
            vault_auth.key,
        )?,
        &[
            vault.clone(),
            collateral_mint.clone(),
            vault_auth.clone(),
            rent_sysvar.clone(),
        ],
        &[vault_auth_seeds],
    )?;

    // Write pool state
    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);

    pool.is_initialized = 1;
    pool.bump = pool_bump;
    pool.vault_authority_bump = vault_auth_bump;
    pool.admin_transferred = 0; // Not yet — must call TransferAdmin
    pool.slab = slab.key.to_bytes();
    pool.admin = admin.key.to_bytes();
    pool.collateral_mint = collateral_mint.key.to_bytes();
    pool.lp_mint = lp_mint.key.to_bytes();
    pool.vault = vault.key.to_bytes();
    pool.total_deposited = 0;
    pool.total_lp_supply = 0;
    pool.cooldown_slots = cooldown_slots;
    pool.deposit_cap = deposit_cap;
    pool.total_flushed = 0;
    pool.total_returned = 0;
    pool.total_withdrawn = 0;
    pool.percolator_program = percolator_program.key.to_bytes();
    pool.set_discriminator();

    msg!(
        "StakePool initialized for slab {} (admin transfer pending)",
        slab.key
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 1: Deposit
// ═══════════════════════════════════════════════════════════════

fn process_deposit(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    if amount == 0 {
        return Err(StakeError::ZeroAmount.into());
    }

    let accounts_iter = &mut accounts.iter();

    let user = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let user_ata = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let lp_mint = next_account_info(accounts_iter)?;
    let user_lp_ata = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;
    let deposit_pda = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;
    let clock_sysvar = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    if !user.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Read and validate pool state
    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    if pool.lp_mint != lp_mint.key.to_bytes() {
        return Err(StakeError::InvalidMint.into());
    }
    if pool.vault != vault.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }

    // H1: Require admin transfer before accepting deposits.
    // Without this, users can deposit into a pool where the stake program
    // doesn't yet have admin control over the wrapper — their funds would
    // be unprotected by the stake program's safety mechanisms.
    if pool.admin_transferred != 1 {
        return Err(StakeError::AdminNotTransferred.into());
    }

    // I7: Block deposits after market resolution
    if pool.is_resolved() {
        return Err(StakeError::MarketResolved.into());
    }

    // I5: Validate vault_auth PDA derivation
    let (expected_vault_auth, _) = derive_vault_authority(program_id, pool_pda.key);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidAccount.into());
    }

    // Check deposit cap against CURRENT pool value, not lifetime deposits.
    // Using total_deposited (monotonically increasing) would permanently lock
    // the pool once lifetime deposits hit the cap, even if 99% was withdrawn.
    // (H6 fix)
    if pool.deposit_cap > 0 {
        let current_value = pool.total_pool_value().unwrap_or(0);
        let new_value = current_value
            .checked_add(amount)
            .ok_or(StakeError::Overflow)?;
        if new_value > pool.deposit_cap {
            return Err(StakeError::DepositCapExceeded.into());
        }
    }

    // Validate token program BEFORE any invoke_signed that grants PDA signer authority.
    // Without this, attacker passes fake program → receives vault_auth signer → drains vault.
    verify_token_program(token_program)?;

    // Calculate LP tokens to mint
    let lp_to_mint = pool
        .calc_lp_for_deposit(amount)
        .ok_or(StakeError::Overflow)?;
    if lp_to_mint == 0 {
        return Err(StakeError::ZeroAmount.into());
    }

    // Transfer collateral: user ATA → stake vault
    invoke(
        &spl_token::instruction::transfer(
            token_program.key,
            user_ata.key,
            vault.key,
            user.key,
            &[],
            amount,
        )?,
        &[
            user_ata.clone(),
            vault.clone(),
            user.clone(),
            token_program.clone(),
        ],
    )?;

    // Mint LP tokens to user
    let (_, vault_auth_bump) = state::derive_vault_authority(program_id, pool_pda.key);
    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];

    invoke_signed(
        &spl_token::instruction::mint_to(
            token_program.key,
            lp_mint.key,
            user_lp_ata.key,
            vault_auth.key,
            &[],
            lp_to_mint,
        )?,
        &[
            lp_mint.clone(),
            user_lp_ata.clone(),
            vault_auth.clone(),
            token_program.clone(),
        ],
        &[vault_auth_seeds],
    )?;

    // Update pool totals
    pool.total_deposited = pool
        .total_deposited
        .checked_add(amount)
        .ok_or(StakeError::Overflow)?;
    pool.total_lp_supply = pool
        .total_lp_supply
        .checked_add(lp_to_mint)
        .ok_or(StakeError::Overflow)?;

    // PERC-313: Refresh high-water mark after deposit (TVL increased)
    let clock = Clock::from_account_info(clock_sysvar)?;
    if pool.hwm_enabled() {
        let current_tvl = pool.total_pool_value().unwrap_or(0);
        pool.refresh_hwm(clock.epoch, current_tvl);
    }

    // Create or update per-user deposit PDA (cooldown tracking)
    let (expected_deposit_pda, deposit_bump) =
        state::derive_deposit_pda(program_id, pool_pda.key, user.key);
    if *deposit_pda.key != expected_deposit_pda {
        return Err(StakeError::InvalidPda.into());
    }

    // I4: Verify deposit PDA ownership for existing accounts
    if !deposit_pda.data_is_empty() && *deposit_pda.owner != *program_id {
        return Err(StakeError::InvalidAccount.into());
    }

    if deposit_pda.data_is_empty() {
        let deposit_seeds: &[&[u8]] = &[
            b"stake_deposit",
            pool_pda.key.as_ref(),
            user.key.as_ref(),
            &[deposit_bump],
        ];
        let rent = Rent::get()?;
        invoke_signed(
            &system_instruction::create_account(
                user.key,
                deposit_pda.key,
                rent.minimum_balance(STAKE_DEPOSIT_SIZE),
                STAKE_DEPOSIT_SIZE as u64,
                program_id,
            ),
            &[user.clone(), deposit_pda.clone(), system_program.clone()],
            &[deposit_seeds],
        )?;
    }

    let mut deposit_data = deposit_pda.try_borrow_mut_data()?;
    let deposit: &mut StakeDeposit =
        bytemuck::from_bytes_mut(&mut deposit_data[..STAKE_DEPOSIT_SIZE]);

    if deposit.is_initialized != 1 {
        deposit.set_discriminator();
    }
    deposit.is_initialized = 1;
    deposit.bump = deposit_bump;
    deposit.pool = pool_pda.key.to_bytes();
    deposit.user = user.key.to_bytes();

    // #8 fix: do NOT reset last_deposit_slot to clock.slot unconditionally.
    // That would re-lock the depositor's ENTIRE existing aged position under
    // the withdrawal cooldown — a tiny top-up could freeze a large, long-aged
    // position for the full cooldown again (a griefing / accidental-lockout
    // vector). Instead, blend the existing position's age with the new deposit,
    // weighted by LP amount, so a small top-up barely moves the unlock slot
    // while a large fresh deposit is still meaningfully covered by the cooldown
    // (anti-flash protection preserved). For a brand-new record (existing
    // lp_amount == 0) this returns exactly clock.slot.
    let existing_lp = deposit.lp_amount;
    let existing_slot = deposit.last_deposit_slot;
    deposit.last_deposit_slot =
        crate::math::weighted_deposit_slot(existing_lp, existing_slot, lp_to_mint, clock.slot);
    deposit.lp_amount = existing_lp
        .checked_add(lp_to_mint)
        .ok_or(StakeError::Overflow)?;

    msg!(
        "Deposited {} collateral, minted {} LP tokens",
        amount,
        lp_to_mint
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 2: Withdraw
// ═══════════════════════════════════════════════════════════════

fn process_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    lp_amount: u64,
) -> ProgramResult {
    if lp_amount == 0 {
        return Err(StakeError::ZeroAmount.into());
    }

    let accounts_iter = &mut accounts.iter();

    let user = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let user_lp_ata = next_account_info(accounts_iter)?;
    let lp_mint = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let user_ata = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;
    let deposit_pda = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;
    let clock_sysvar = next_account_info(accounts_iter)?;

    if !user.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    if pool.lp_mint != lp_mint.key.to_bytes() {
        return Err(StakeError::InvalidMint.into());
    }
    if pool.vault != vault.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }

    // Validate token program BEFORE any invoke_signed that grants PDA signer authority.
    verify_token_program(token_program)?;

    // I5: Validate vault_auth PDA derivation
    let (expected_vault_auth, _) = derive_vault_authority(program_id, pool_pda.key);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidAccount.into());
    }

    // Validate the deposit PDA's derivation AND ownership before trusting any
    // of its bytes. Without this, a withdrawer can pass an attacker-crafted
    // account (owned by any program / System) whose bytes are shaped like a
    // StakeDeposit with last_deposit_slot=0 and lp_amount=u64::MAX, which
    // sails through the in-data checks below and bypasses (a) the withdrawal
    // cooldown and (b) the per-deposit lp_amount accounting — defeating the
    // anti-flash / fee-front-running protection the cooldown exists for, and
    // leaving the real StakeDeposit record (with its live cooldown) untouched.
    // process_deposit already performs exactly these checks; withdraw must too.
    let (expected_deposit_pda, _) = state::derive_deposit_pda(program_id, pool_pda.key, user.key);
    if *deposit_pda.key != expected_deposit_pda {
        return Err(StakeError::InvalidPda.into());
    }
    if *deposit_pda.owner != *program_id {
        return Err(StakeError::InvalidAccount.into());
    }

    // Check cooldown
    let clock = Clock::from_account_info(clock_sysvar)?;
    let deposit_data_ref = deposit_pda.try_borrow_data()?;
    let deposit: &StakeDeposit = bytemuck::from_bytes(&deposit_data_ref[..STAKE_DEPOSIT_SIZE]);

    if deposit.is_initialized != 1
        || deposit.user != user.key.to_bytes()
        || deposit.pool != pool_pda.key.to_bytes()
    {
        return Err(StakeError::Unauthorized.into());
    }
    if clock.slot
        < deposit
            .last_deposit_slot
            .saturating_add(pool.cooldown_slots)
    {
        return Err(StakeError::CooldownNotElapsed.into());
    }
    if lp_amount > deposit.lp_amount {
        return Err(StakeError::InsufficientLpTokens.into());
    }
    drop(deposit_data_ref);

    // Calculate collateral to return (proportional to LP burned)
    let collateral_amount = pool
        .calc_collateral_for_withdraw(lp_amount)
        .ok_or(StakeError::Overflow)?;
    if collateral_amount == 0 {
        return Err(StakeError::ZeroAmount.into());
    }

    // PERC-313: High-water mark floor enforcement
    if pool.hwm_enabled() {
        let current_tvl = pool.total_pool_value().unwrap_or(0);
        let hwm = pool.refresh_hwm(clock.epoch, current_tvl);
        let post_tvl = current_tvl
            .checked_sub(collateral_amount)
            .ok_or(StakeError::Overflow)?;
        if !crate::math::hwm_withdrawal_allowed(post_tvl, hwm, pool.hwm_floor_bps()) {
            msg!(
                "HWM block: post_tvl={} < floor(hwm={}, bps={})",
                post_tvl,
                hwm,
                pool.hwm_floor_bps()
            );
            return Err(StakeError::WithdrawalBelowHwmFloor.into());
        }
    }

    // Burn LP tokens from user
    invoke(
        &spl_token::instruction::burn(
            token_program.key,
            user_lp_ata.key,
            lp_mint.key,
            user.key,
            &[],
            lp_amount,
        )?,
        &[
            user_lp_ata.clone(),
            lp_mint.clone(),
            user.clone(),
            token_program.clone(),
        ],
    )?;

    // Transfer collateral: vault → user ATA
    let (_, vault_auth_bump) = state::derive_vault_authority(program_id, pool_pda.key);
    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];

    invoke_signed(
        &spl_token::instruction::transfer(
            token_program.key,
            vault.key,
            user_ata.key,
            vault_auth.key,
            &[],
            collateral_amount,
        )?,
        &[
            vault.clone(),
            user_ata.clone(),
            vault_auth.clone(),
            token_program.clone(),
        ],
        &[vault_auth_seeds],
    )?;

    // Update pool totals
    pool.total_withdrawn = pool
        .total_withdrawn
        .checked_add(collateral_amount)
        .ok_or(StakeError::Overflow)?;
    pool.total_lp_supply = pool
        .total_lp_supply
        .checked_sub(lp_amount)
        .ok_or(StakeError::Overflow)?;

    // Update deposit PDA
    let mut deposit_data_mut = deposit_pda.try_borrow_mut_data()?;
    let deposit_mut: &mut StakeDeposit =
        bytemuck::from_bytes_mut(&mut deposit_data_mut[..STAKE_DEPOSIT_SIZE]);
    deposit_mut.lp_amount = deposit_mut
        .lp_amount
        .checked_sub(lp_amount)
        .ok_or(StakeError::InsufficientLpTokens)?;

    msg!(
        "Withdrew {} collateral, burned {} LP tokens",
        collateral_amount,
        lp_amount
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 3: FlushToInsurance — CPI into wrapper TopUpInsurance
// ═══════════════════════════════════════════════════════════════

fn process_flush_to_insurance(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    if amount == 0 {
        return Err(StakeError::ZeroAmount.into());
    }

    let accounts_iter = &mut accounts.iter();

    let caller = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let wrapper_vault = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;

    if !caller.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Read pool
    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    validate_flush_pool_mode(pool)?;

    // CRITICAL (C10): FlushToInsurance must be admin-only.
    // Without this, ANY signer can drain the stake vault to wrapper insurance,
    // locking all LP holder withdrawals until market resolution.
    // This is a DoS vector that freezes depositor funds indefinitely.
    if pool.admin != caller.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }

    if pool.slab != slab.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }
    if pool.vault != vault.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }
    if pool.percolator_program != percolator_program.key.to_bytes() {
        return Err(StakeError::InvalidPercolatorProgram.into());
    }

    // Verify vault balance — can't flush more than what's physically in vault.
    // Available = total_deposited + total_returned - total_withdrawn - total_flushed
    //
    // #9 fix: total_returned (insurance pulled back into the vault after
    // resolution via AdminWithdrawInsurance) is real collateral sitting in the
    // stake vault. The previous formula omitted it, so any returned insurance
    // was permanently un-flushable even though the tokens were in the vault and
    // counted toward total_pool_value(). Add returned to the inflows so the
    // flush ceiling matches the vault's true balance.
    //
    // Sum the positive inflows BEFORE subtracting the negatives so a legitimate
    // intermediate state cannot underflow mid-computation. Use checked_* for
    // defense-in-depth (saturating_sub would hide a genuine accounting bug).
    let available = pool
        .total_deposited
        .checked_add(pool.total_returned)
        .and_then(|v| v.checked_sub(pool.total_withdrawn))
        .and_then(|v| v.checked_sub(pool.total_flushed))
        .ok_or(StakeError::Overflow)?;
    if amount > available {
        return Err(ProgramError::InsufficientFunds);
    }

    // Derive vault authority for signing
    let (expected_vault_auth, vault_auth_bump) =
        state::derive_vault_authority(program_id, pool_pda.key);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidPda.into());
    }

    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];

    // CPI TopUpInsurance: vault_auth PDA signs, stake vault is the "signer_ata"
    // TopUpInsurance checks: verify_token_account(a_user_ata, a_user.key, &mint)
    // Our vault's owner (in SPL token terms) = vault_auth PDA = signer. ✓
    cpi::cpi_top_up_insurance(
        percolator_program,
        vault_auth, // signer (PDA, we invoke_signed)
        slab,
        vault,         // signer_ata (owned by vault_auth PDA)
        wrapper_vault, // percolator vault
        token_program,
        amount,
        vault_auth_seeds,
    )?;

    // Update pool tracking
    pool.total_flushed = pool
        .total_flushed
        .checked_add(amount)
        .ok_or(StakeError::Overflow)?;

    msg!(
        "Flushed {} collateral to percolator insurance via CPI",
        amount
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 4: UpdateConfig
// ═══════════════════════════════════════════════════════════════

fn process_update_config(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_cooldown_slots: Option<u64>,
    new_deposit_cap: Option<u64>,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if pool.admin != admin.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }

    if let Some(cooldown) = new_cooldown_slots {
        pool.cooldown_slots = cooldown;
    }
    if let Some(cap) = new_deposit_cap {
        pool.deposit_cap = cap;
    }

    msg!("Pool config updated");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 5: TransferAdmin — one-time setup, transfers wrapper admin to pool PDA
// ═══════════════════════════════════════════════════════════════

fn process_transfer_admin(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let current_admin = next_account_info(accounts_iter)?; // Human (current wrapper admin)
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    if !current_admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the pool PDA is correctly derived
    let (expected_pool, pool_bump) = state::derive_pool_pda(program_id, slab.key);
    if *pool_pda.key != expected_pool {
        return Err(StakeError::InvalidPda.into());
    }

    {
        let pool_data = pool_pda.try_borrow_data()?;
        let pool: &StakePool = bytemuck::from_bytes(&pool_data[..STAKE_POOL_SIZE]);

        if pool.is_initialized != 1 {
            return Err(StakeError::NotInitialized.into());
        }
        // M7: Verify caller is pool admin (defense-in-depth).
        // The wrapper CPI will also check, but we should reject early if the
        // caller isn't even our admin.
        if pool.admin != current_admin.key.to_bytes() {
            return Err(StakeError::Unauthorized.into());
        }
        if pool.admin_transferred == 1 {
            return Err(StakeError::AdminAlreadyTransferred.into());
        }
        if pool.slab != slab.key.to_bytes() {
            return Err(StakeError::InvalidPda.into());
        }
        if pool.percolator_program != percolator_program.key.to_bytes() {
            return Err(StakeError::InvalidPercolatorProgram.into());
        }
    }

    // Current wrapper ABI: UpdateAuthority (tag 32) requires BOTH the current
    // market authority and the incoming authority to sign. The incoming
    // authority is this program's pool PDA, so the vault program must co-sign it
    // via invoke_signed.
    let pool_bump_arr = [pool_bump];
    let pool_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &pool_bump_arr];
    cpi::cpi_update_authority(
        percolator_program,
        current_admin,
        pool_pda,
        slab,
        pool_seeds,
    )?;

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);

    pool.admin_transferred = 1;

    msg!(
        "Wrapper admin transferred to pool PDA {} for slab {}",
        pool_pda.key,
        slab.key,
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 6: AdminSetOracleAuthority
// ═══════════════════════════════════════════════════════════════

fn process_admin_set_oracle_authority(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_authority: &Pubkey,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;
    let new_authority_ai = next_account_info(accounts_iter)?;

    if new_authority_ai.key != new_authority {
        return Err(StakeError::InvalidAccount.into());
    }
    if !new_authority_ai.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let bump = validate_admin_cpi(program_id, pool_pda, admin, slab, percolator_program)?;
    let bump_arr = [bump];
    let admin_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &bump_arr];

    cpi::cpi_update_asset_authority(
        percolator_program,
        pool_pda,
        new_authority_ai,
        slab,
        0,
        cpi::ASSET_AUTH_ORACLE,
        &[admin_seeds],
    )?;

    msg!("Asset-0 oracle authority rotated via CPI");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 7: AdminSetRiskThreshold
// ═══════════════════════════════════════════════════════════════

fn process_admin_set_risk_threshold(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_threshold: u128,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    let bump = validate_admin_cpi(program_id, pool_pda, admin, slab, percolator_program)?;
    let admin_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &[bump]];

    msg!("SetRiskThreshold has no current wrapper CPI equivalent");
    cpi::cpi_set_risk_threshold(
        percolator_program,
        pool_pda,
        slab,
        new_threshold,
        admin_seeds,
    )
}

// ═══════════════════════════════════════════════════════════════
// 8: AdminSetMaintenanceFee
// ═══════════════════════════════════════════════════════════════

fn process_admin_set_maintenance_fee(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_fee: u128,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    let bump = validate_admin_cpi(program_id, pool_pda, admin, slab, percolator_program)?;
    let admin_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &[bump]];

    msg!("SetMaintenanceFee has no current wrapper CPI equivalent");
    cpi::cpi_set_maintenance_fee(percolator_program, pool_pda, slab, new_fee, admin_seeds)
}

// ═══════════════════════════════════════════════════════════════
// 9: AdminResolveMarket
// ═══════════════════════════════════════════════════════════════

fn process_admin_resolve_market(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    let bump = validate_admin_cpi(program_id, pool_pda, admin, slab, percolator_program)?;
    let admin_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &[bump]];

    cpi::cpi_resolve_market(percolator_program, pool_pda, slab, admin_seeds)?;

    // I7: Set resolved flag to block future deposits
    {
        let mut pool_data = pool_pda.try_borrow_mut_data()?;
        let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);
        pool.set_resolved();
    }

    msg!("ResolveMarket forwarded via CPI");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 10: AdminWithdrawInsurance — after resolution, get insurance back to vault
// ═══════════════════════════════════════════════════════════════

fn process_admin_withdraw_insurance(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?; // vault_auth PDA (signer for CPI)
    let stake_vault = next_account_info(accounts_iter)?; // receives insurance (owned by vault_auth ✓)
    let wrapper_vault = next_account_info(accounts_iter)?; // wrapper insurance vault
    let wrapper_vault_pda = next_account_info(accounts_iter)?; // wrapper's vault authority PDA
    let percolator_program = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;
    let _clock = next_account_info(accounts_iter)?; // retained for backward-compatible account layout

    // Validate admin authority
    let pool_bump = validate_admin_cpi(program_id, pool_pda, admin, slab, percolator_program)?;
    let _ = pool_bump; // pool_pda not signing this CPI

    // Derive vault_auth PDA and its seeds
    // vault_auth = PDA([b"vault_auth", pool_pda])
    let (expected_vault_auth, vault_auth_bump) =
        Pubkey::find_program_address(&[b"vault_auth", pool_pda.key.as_ref()], program_id);
    if vault_auth.key != &expected_vault_auth {
        return Err(solana_program::program_error::ProgramError::InvalidArgument);
    }

    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];

    // Current wrapper ABI: terminal WithdrawInsurance (tag 41). vault_auth is
    // the asset-0 insurance authority (configured through AdminSetInsurancePolicy
    // below) and stake_vault is its destination token account.
    cpi::cpi_withdraw_insurance(
        percolator_program,
        vault_auth,
        slab,
        stake_vault,
        wrapper_vault,
        wrapper_vault_pda,
        token_program,
        amount,
        vault_auth_seeds,
    )?;

    // Update pool accounting — returned insurance increases pool value for LP holders
    {
        let mut pool_data = pool_pda.try_borrow_mut_data()?;
        let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);
        pool.total_returned = pool
            .total_returned
            .checked_add(amount)
            .ok_or(StakeError::Overflow)?;
    }

    msg!(
        "Insurance {} tokens withdrawn from wrapper to stake_vault via vault_auth CPI",
        amount
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 11: AdminSetInsurancePolicy
// ═══════════════════════════════════════════════════════════════

fn process_admin_set_insurance_policy(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    authority: &Pubkey,
    min_withdraw_base: u64,
    max_withdraw_bps: u16,
    cooldown_slots: u64,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;
    let authority_ai = next_account_info(accounts_iter)?;

    if authority_ai.key != authority {
        return Err(StakeError::InvalidAccount.into());
    }

    // The current wrapper removed the old bps/cooldown policy setter. Keep this
    // instruction as the standalone vault setup hook for the only authority it
    // needs: asset-0 insurance authority. Nonzero legacy policy fields would be
    // silently ignored, so fail closed instead.
    if min_withdraw_base != 0 || max_withdraw_bps != 0 || cooldown_slots != 0 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let bump = validate_admin_cpi(program_id, pool_pda, admin, slab, percolator_program)?;
    let bump_arr = [bump];
    let admin_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &bump_arr];

    if authority_ai.is_signer {
        cpi::cpi_update_asset_authority(
            percolator_program,
            pool_pda,
            authority_ai,
            slab,
            0,
            cpi::ASSET_AUTH_INSURANCE,
            &[admin_seeds],
        )?;
    } else {
        // Common setup path: rotate asset-0 insurance authority to this vault's
        // vault_auth PDA so it can sign TopUpInsurance and terminal
        // WithdrawInsurance while owning the stake vault token account.
        let (expected_vault_auth, vault_auth_bump) =
            state::derive_vault_authority(program_id, pool_pda.key);
        if *authority_ai.key != expected_vault_auth {
            return Err(ProgramError::MissingRequiredSignature);
        }
        let vault_auth_bump_arr = [vault_auth_bump];
        let vault_auth_seeds: &[&[u8]] = &[
            b"vault_auth",
            pool_pda.key.as_ref(),
            &vault_auth_bump_arr,
        ];
        cpi::cpi_update_asset_authority(
            percolator_program,
            pool_pda,
            authority_ai,
            slab,
            0,
            cpi::ASSET_AUTH_INSURANCE,
            &[admin_seeds, vault_auth_seeds],
        )?;
    }

    msg!("Asset-0 insurance authority rotated via CPI");
    Ok(())
}

// ============================================================================
// PERC-272: LP Vault — Fee Accrual & Trading Pool Init
// ============================================================================

/// Accrue trading fees from the percolator engine to the LP vault.
/// Permissionless: reads vault token account balance and updates pool state.
///
/// Fee delta = current_vault_balance - last_vault_snapshot - net_deposits_since_last
/// To keep it simple and trustless: we track the vault token account balance directly.
/// Any increase in vault balance beyond deposits is fee revenue.
fn process_accrue_fees(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let caller = next_account_info(accounts_iter)?; // signer, permissionless
    if !caller.is_signer {
        msg!("AccrueFees: caller must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }
    let pool_ai = next_account_info(accounts_iter)?;
    let vault_ai = next_account_info(accounts_iter)?;
    let clock_ai = next_account_info(accounts_iter)?;

    // Validate pool PDA
    let mut pool_data = pool_ai.try_borrow_mut_data()?;
    let pool = bytemuck::try_from_bytes_mut::<state::StakePool>(&mut pool_data[..STAKE_POOL_SIZE])
        .map_err(|_| ProgramError::InvalidAccountData)?;

    if pool.is_initialized != 1 {
        return Err(ProgramError::UninitializedAccount);
    }

    // Only trading LP mode pools accrue fees
    if pool.pool_mode != 1 {
        msg!("AccrueFees: pool is not in trading LP mode");
        return Err(StakeError::InvalidPoolMode.into());
    }

    // Read vault token account balance
    let vault_data = vault_ai.try_borrow_data()?;
    let vault_state = spl_token::state::Account::unpack(&vault_data)?;
    let current_balance = vault_state.amount;

    // Verify vault matches pool
    if vault_ai.key.to_bytes() != pool.vault {
        return Err(ProgramError::InvalidAccountData);
    }

    let clock = Clock::from_account_info(clock_ai)?;

    // Compute fee delta: any balance increase beyond the accrual baseline
    // (total_deposited + total_fees_earned - total_withdrawn) is new fees.
    // Routed through StakePool::accrual_baseline, which sums positives before
    // subtracting total_withdrawn so a fee-appreciated mode-1 pool (where
    // total_withdrawn legitimately exceeds total_deposited) does NOT underflow
    // and revert this permissionless crank forever. Still fails closed (None)
    // on a truly over-withdrawn state.
    let pool_value = pool.accrual_baseline().ok_or(StakeError::Overflow)?;

    if current_balance > pool_value {
        let fee_delta = current_balance - pool_value;
        pool.total_fees_earned = pool
            .total_fees_earned
            .checked_add(fee_delta)
            .ok_or(StakeError::Overflow)?;
        msg!(
            "AccrueFees: accrued {} fees, total_fees_earned={}",
            fee_delta,
            pool.total_fees_earned
        );
    }

    pool.last_fee_accrual_slot = clock.slot;
    pool.last_vault_snapshot = current_balance;

    Ok(())
}

/// Initialize a pool in trading LP vault mode (PERC-272).
/// Same mechanics as InitPool but sets pool_mode = 1.
fn process_init_trading_pool(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    cooldown_slots: u64,
    deposit_cap: u64,
) -> ProgramResult {
    // Reuse InitPool logic
    process_init_pool(program_id, accounts, cooldown_slots, deposit_cap)?;

    // Now update pool_mode to 1 (trading LP)
    let pool_ai = &accounts[2]; // Pool PDA is account [2] in InitPool
    let mut pool_data = pool_ai.try_borrow_mut_data()?;
    let pool = bytemuck::try_from_bytes_mut::<state::StakePool>(&mut pool_data[..STAKE_POOL_SIZE])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    pool.pool_mode = 1;

    msg!("InitTradingPool: pool_mode set to 1 (trading LP vault)");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 14: AdminSetHwmConfig — PERC-313
// ═══════════════════════════════════════════════════════════════

fn process_admin_set_hwm_config(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    enabled: bool,
    hwm_floor_bps: u16,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    if pool.admin != admin.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }

    // Validate floor bps: 0–10000 (0% to 100%)
    if hwm_floor_bps > 10_000 {
        return Err(ProgramError::InvalidInstructionData);
    }

    pool.set_hwm_enabled(enabled);
    pool.set_hwm_floor_bps(hwm_floor_bps);

    msg!(
        "AdminSetHwmConfig: enabled={}, floor_bps={}",
        enabled,
        hwm_floor_bps
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytemuck::Zeroable;

    #[test]
    fn flush_pool_mode_guard_allows_insurance_pools() {
        let mut pool = StakePool::zeroed();
        pool.pool_mode = 0;

        assert!(validate_flush_pool_mode(&pool).is_ok());
    }

    #[test]
    fn flush_pool_mode_guard_rejects_trading_pools() {
        let mut pool = StakePool::zeroed();
        pool.pool_mode = 1;

        assert_eq!(
            validate_flush_pool_mode(&pool).unwrap_err(),
            StakeError::InvalidPoolMode.into()
        );
    }
}
