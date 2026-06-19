//! Unit tests for percolator-stake LP math, state, and instruction decoding.

use bytemuck::Zeroable;
use percolator_vault::instruction::StakeInstruction;
use percolator_vault::state::{StakeDeposit, StakePool, STAKE_DEPOSIT_SIZE, STAKE_POOL_SIZE};

// ═══════════════════════════════════════════════════════════════
// Helper: create a zeroed StakePool with basic fields set
// ═══════════════════════════════════════════════════════════════

fn new_pool() -> StakePool {
    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.bump = 255;
    pool.vault_authority_bump = 254;
    pool
}

// ═══════════════════════════════════════════════════════════════
// LP Math Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_first_depositor_gets_1_to_1() {
    let pool = new_pool();
    assert_eq!(pool.total_lp_supply, 0);
    assert_eq!(pool.total_deposited, 0);

    let lp = pool.calc_lp_for_deposit(1_000_000).unwrap();
    assert_eq!(lp, 1_000_000, "First depositor should get 1:1 LP tokens");
}

#[test]
fn test_second_depositor_pro_rata() {
    let mut pool = new_pool();
    // First depositor: 1M collateral → 1M LP
    pool.total_deposited = 1_000_000;
    pool.total_lp_supply = 1_000_000;

    // Second depositor: 500K collateral → should get 500K LP (same ratio)
    let lp = pool.calc_lp_for_deposit(500_000).unwrap();
    assert_eq!(lp, 500_000);
}

#[test]
fn test_pro_rata_with_appreciation() {
    let mut pool = new_pool();
    // Initial: 1M deposited, 1M LP
    pool.total_deposited = 1_000_000;
    pool.total_lp_supply = 1_000_000;

    // Simulate insurance returns: total_deposited stays same but pool value grows
    // Actually in our model, pool_value = total_deposited - total_withdrawn
    // So appreciation happens when insurance returns increase deposited
    // Let's simulate: 1M deposited, 500K withdrawn = 500K pool value, 500K LP
    pool.total_withdrawn = 500_000;
    pool.total_lp_supply = 500_000; // 500K LP outstanding

    // pool_value = 1M - 500K = 500K
    // New deposit of 250K → LP = 250K * 500K / 500K = 250K
    let lp = pool.calc_lp_for_deposit(250_000).unwrap();
    assert_eq!(lp, 250_000);
}

#[test]
fn test_withdraw_returns_proportional() {
    let mut pool = new_pool();
    pool.total_deposited = 2_000_000;
    pool.total_lp_supply = 2_000_000;

    // Withdraw half LP → should get half collateral
    let collateral = pool.calc_collateral_for_withdraw(1_000_000).unwrap();
    assert_eq!(collateral, 1_000_000);
}

#[test]
fn test_withdraw_after_partial_withdrawal() {
    let mut pool = new_pool();
    pool.total_deposited = 2_000_000;
    pool.total_withdrawn = 500_000; // Someone already withdrew 500K
    pool.total_lp_supply = 1_500_000; // 1.5M LP remaining

    // pool_value = 2M - 500K = 1.5M
    // Withdraw 750K LP → collateral = 750K * 1.5M / 1.5M = 750K
    let collateral = pool.calc_collateral_for_withdraw(750_000).unwrap();
    assert_eq!(collateral, 750_000);
}

#[test]
fn test_zero_lp_supply_returns_none_on_withdraw() {
    let pool = new_pool();
    assert_eq!(pool.total_lp_supply, 0);
    assert!(pool.calc_collateral_for_withdraw(100).is_none());
}

#[test]
fn test_zero_deposit_amount() {
    let pool = new_pool();
    // Zero amount should return 0 (caller checks for zero)
    let lp = pool.calc_lp_for_deposit(0).unwrap();
    assert_eq!(lp, 0);
}

#[test]
fn test_large_amounts_no_overflow() {
    let mut pool = new_pool();
    pool.total_deposited = u64::MAX / 2;
    pool.total_lp_supply = u64::MAX / 2;

    // Large deposit should still work via u128 intermediate
    let lp = pool.calc_lp_for_deposit(u64::MAX / 4).unwrap();
    assert_eq!(lp, u64::MAX / 4);
}

#[test]
fn test_rounding_favors_pool() {
    let mut pool = new_pool();
    pool.total_deposited = 1_000_000;
    pool.total_lp_supply = 999_999; // Slightly less LP than deposits

    // Deposit 1 unit: 1 * 999_999 / 1_000_000 = 0 (rounds down)
    let lp = pool.calc_lp_for_deposit(1).unwrap();
    assert_eq!(
        lp, 0,
        "Tiny deposit should round down to 0 LP (pool-favoring)"
    );
}

#[test]
fn test_withdraw_rounding_favors_pool() {
    let mut pool = new_pool();
    pool.total_deposited = 1_000_001;
    pool.total_lp_supply = 1_000_000;

    // Withdraw 1 LP: 1 * 1_000_001 / 1_000_000 = 1 (rounds down from 1.000001)
    let collateral = pool.calc_collateral_for_withdraw(1).unwrap();
    assert_eq!(collateral, 1, "Rounding should favor pool (rounds down)");
}

// ═══════════════════════════════════════════════════════════════
// Pool Value Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_pool_value_basic() {
    let mut pool = new_pool();
    pool.total_deposited = 5_000_000;
    pool.total_withdrawn = 1_000_000;

    assert_eq!(pool.total_pool_value().unwrap(), 4_000_000);
}

#[test]
fn test_pool_value_with_flush() {
    let mut pool = new_pool();
    pool.total_deposited = 5_000_000;
    pool.total_withdrawn = 0;
    pool.total_flushed = 3_000_000; // Flushed to insurance

    // Pool value = deposited - withdrawn - flushed + returned = 5M - 0 - 3M + 0 = 2M
    // Flushed reduces accessible value. LP tokens reflect vault balance only.
    // Insurance portion tracked separately; returned after resolution.
    assert_eq!(pool.total_pool_value().unwrap(), 2_000_000);
}

#[test]
fn test_pool_value_flush_return_roundtrip() {
    let mut pool = new_pool();
    pool.total_deposited = 5_000_000;
    pool.total_withdrawn = 0;
    pool.total_flushed = 3_000_000;
    pool.total_returned = 3_000_000; // Full return after resolution

    // Full return: back to deposited - withdrawn
    assert_eq!(pool.total_pool_value().unwrap(), 5_000_000);
}

#[test]
fn test_pool_value_flush_partial_return() {
    let mut pool = new_pool();
    pool.total_deposited = 5_000_000;
    pool.total_withdrawn = 0;
    pool.total_flushed = 3_000_000;
    pool.total_returned = 1_000_000; // 2M lost to insurance payouts

    // Partial: 5M - 0 - 3M + 1M = 3M (lost 2M to insurance)
    assert_eq!(pool.total_pool_value().unwrap(), 3_000_000);
}

#[test]
fn test_pool_value_mode1_fee_appreciated_withdrawal_does_not_brick() {
    // Regression: a mode-1 (trading) pool earns fees, then an LP withdraws
    // the fee-appreciated amount. The withdraw handler adds the full
    // (principal + fee) payout to total_withdrawn without decrementing
    // total_fees_earned, so total_withdrawn legitimately exceeds
    // total_deposited. The TRUE pool value is still >= 0 (the fees cover the
    // gap), and total_pool_value() must return it rather than underflow to
    // None — otherwise the pool bricks for every remaining LP.
    let mut pool = new_pool();
    pool.pool_mode = 1;
    pool.total_deposited = 1_000_000;
    pool.total_fees_earned = 1_000_000; // share price doubled via fees
    pool.total_withdrawn = 2_000_000; // one LP exited at 2x (1M principal + 1M fees)

    // 1M deposited + 1M fees - 2M withdrawn = 0, NOT None.
    assert_eq!(
        pool.total_pool_value(),
        Some(0),
        "fee-appreciated full exit must compute to 0, not underflow-brick the pool"
    );

    // And a pool that is still solvent after such an exit reports the remainder.
    pool.total_fees_earned = 1_500_000; // 1M deposit + 1.5M fees = 2.5M, 2M withdrawn
    assert_eq!(pool.total_pool_value(), Some(500_000));
}

#[test]
fn test_accrual_baseline_mode1_fee_appreciated_does_not_brick_crank() {
    // Regression for the AccrueFees crank: process_accrue_fees previously
    // computed its baseline inline as total_deposited.checked_sub(total_withdrawn)
    // + total_fees_earned, which returned None (→ StakeError::Overflow → revert)
    // once total_withdrawn exceeded total_deposited on a fee-appreciated mode-1
    // pool — permanently freezing fee booking. accrual_baseline() sums positives
    // first so the identical net value computes without underflow.
    let mut pool = new_pool();
    pool.pool_mode = 1;
    pool.total_deposited = 1_000_000;
    pool.total_fees_earned = 1_000_000;
    pool.total_withdrawn = 2_000_000; // > total_deposited (old inline math → None → crank bricked)

    // 1M deposited + 1M fees - 2M withdrawn = 0, NOT None.
    assert_eq!(
        pool.accrual_baseline(),
        Some(0),
        "accrual baseline must compute to 0 (not underflow-revert the AccrueFees crank)"
    );

    // Still solvent → reports the remainder; matches total_pool_value when no flush/return.
    pool.total_fees_earned = 1_500_000;
    assert_eq!(pool.accrual_baseline(), Some(500_000));
    assert_eq!(pool.accrual_baseline(), pool.total_pool_value(),
        "with no flush/return, accrual baseline equals total_pool_value");

    // Fails closed on a genuinely over-withdrawn state (negatives exceed positives).
    pool.total_fees_earned = 0;
    pool.total_withdrawn = 2_000_000; // 1M deposited + 0 fees < 2M withdrawn
    assert_eq!(pool.accrual_baseline(), None, "truly over-withdrawn state still fails closed");
}

#[test]
fn test_pool_value_underflow_returns_zero() {
    let mut pool = new_pool();
    pool.total_deposited = 100;
    pool.total_withdrawn = 200; // Should not happen but test safety

    // checked_sub returns None on underflow — which is correct behavior
    // (this state is invalid, so None signals an error)
    assert!(
        pool.total_pool_value().is_none(),
        "Over-withdrawn pool should return None (invalid state)"
    );
}

// ═══════════════════════════════════════════════════════════════
// Flush Accounting Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_flush_available_calculation() {
    let mut pool = new_pool();
    pool.total_deposited = 10_000_000;
    pool.total_withdrawn = 2_000_000;
    pool.total_flushed = 3_000_000;

    // Available for flush = deposited - withdrawn - flushed
    let available = pool
        .total_deposited
        .saturating_sub(pool.total_withdrawn)
        .saturating_sub(pool.total_flushed);
    assert_eq!(available, 5_000_000);
}

#[test]
fn test_flush_available_zero_when_fully_flushed() {
    let mut pool = new_pool();
    pool.total_deposited = 10_000_000;
    pool.total_withdrawn = 0;
    pool.total_flushed = 10_000_000;

    let available = pool
        .total_deposited
        .saturating_sub(pool.total_withdrawn)
        .saturating_sub(pool.total_flushed);
    assert_eq!(available, 0);
}

// ═══════════════════════════════════════════════════════════════
// #9: returned insurance is re-flushable (FlushToInsurance available formula)
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_flush_available_includes_returned_insurance() {
    // Mirrors the corrected FlushToInsurance `available` formula:
    // available = deposited + returned - withdrawn - flushed.
    //
    // Lifecycle: deposit 1000, flush 500 to insurance, then 300 is returned to
    // the vault after resolution. The vault now physically holds
    // 1000 - 500 + 300 = 800 collateral. The OLD formula
    // (deposited - withdrawn - flushed = 500) made the returned 300 permanently
    // un-flushable. The corrected formula must expose all 800.
    let mut pool = new_pool();
    pool.total_deposited = 1000;
    pool.total_flushed = 500;
    pool.total_withdrawn = 0;
    pool.total_returned = 300;

    let available = pool
        .total_deposited
        .checked_add(pool.total_returned)
        .and_then(|v| v.checked_sub(pool.total_withdrawn))
        .and_then(|v| v.checked_sub(pool.total_flushed))
        .unwrap();

    assert_eq!(
        available, 800,
        "returned insurance sitting in the vault must be re-flushable"
    );
    // And it equals what total_pool_value() reports as the vault balance for a
    // mode-0 (insurance) pool — the two views are consistent.
    assert_eq!(available, pool.total_pool_value().unwrap());
}

// ═══════════════════════════════════════════════════════════════
// #8: deposit cooldown — stake-weighted-average last_deposit_slot
// ═══════════════════════════════════════════════════════════════

/// Replicates the exact StakeDeposit update that process_deposit performs on a
/// top-up, then exercises the withdraw cooldown gate against the resulting
/// slot. Proves a tiny top-up onto a large aged position does NOT re-lock the
/// whole position for the full cooldown.
#[test]
fn test_topup_does_not_relock_large_aged_position() {
    use percolator_vault::math::weighted_deposit_slot;

    let cooldown_slots: u64 = 1_000;

    // Large aged position: 1_000_000 LP deposited at slot 0, cooldown already
    // long elapsed by the time of the top-up.
    let mut deposit = StakeDeposit::zeroed();
    deposit.is_initialized = 1;
    deposit.lp_amount = 1_000_000;
    deposit.last_deposit_slot = 0;

    // Tiny top-up of 1 LP at slot 10_000 (well past the cooldown for the
    // original deposit).
    let topup_slot: u64 = 10_000;
    let topup_lp: u64 = 1;

    // ── exact processor update sequence (#8 fix) ──
    let existing_lp = deposit.lp_amount;
    let existing_slot = deposit.last_deposit_slot;
    deposit.last_deposit_slot =
        weighted_deposit_slot(existing_lp, existing_slot, topup_lp, topup_slot);
    deposit.lp_amount = existing_lp.checked_add(topup_lp).unwrap();

    // Weighted slot rounds down to ~0 (the 1-LP top-up is negligible), so the
    // position remains immediately withdrawable — NOT re-locked for 1000 slots.
    assert_eq!(deposit.last_deposit_slot, 0);

    // Cooldown gate (same comparison as process_withdraw): a withdraw at the
    // top-up slot is allowed because the unlock slot did not jump forward.
    let unlock_at = deposit.last_deposit_slot.saturating_add(cooldown_slots);
    assert!(
        topup_slot >= unlock_at,
        "tiny top-up must not re-lock the aged position under the cooldown"
    );
}

/// The OLD (buggy) behavior, kept as a contrast assertion: unconditionally
/// resetting last_deposit_slot to the current slot WOULD have re-locked the
/// whole aged position. Documents what the fix prevents.
#[test]
fn test_old_unconditional_reset_would_have_relocked() {
    let cooldown_slots: u64 = 1_000;
    let topup_slot: u64 = 10_000;

    // OLD code: deposit.last_deposit_slot = clock.slot;
    let old_last_slot = topup_slot;
    let unlock_at = old_last_slot.saturating_add(cooldown_slots);

    // The whole position would be locked until slot 11_000 — a full cooldown
    // after a 1-LP top-up. This is exactly the lockout the #8 fix removes.
    assert!(
        topup_slot < unlock_at,
        "old unconditional reset re-locked the entire position (the bug)"
    );
    assert_eq!(unlock_at, 11_000);
}

/// A large fresh deposit onto a small aged position still pulls the unlock slot
/// forward, so the cooldown meaningfully covers the new funds (anti-flash
/// protection preserved — the fix does not weaken the cooldown's purpose).
#[test]
fn test_large_fresh_deposit_still_covered_by_cooldown() {
    use percolator_vault::math::weighted_deposit_slot;

    let cooldown_slots: u64 = 1_000;

    let mut deposit = StakeDeposit::zeroed();
    deposit.is_initialized = 1;
    deposit.lp_amount = 1; // negligible aged position
    deposit.last_deposit_slot = 0;

    let deposit_slot: u64 = 10_000;
    let new_lp: u64 = 1_000_000;

    let existing_lp = deposit.lp_amount;
    let existing_slot = deposit.last_deposit_slot;
    deposit.last_deposit_slot =
        weighted_deposit_slot(existing_lp, existing_slot, new_lp, deposit_slot);
    deposit.lp_amount = existing_lp.checked_add(new_lp).unwrap();

    // Weighted slot ≈ 9_999 → unlock at ≈ 10_999, so an immediate withdraw at
    // slot 10_000 is still blocked by the cooldown.
    let unlock_at = deposit.last_deposit_slot.saturating_add(cooldown_slots);
    assert!(
        deposit_slot < unlock_at,
        "a large fresh deposit must remain locked for ~the full cooldown"
    );
    assert_eq!(deposit.last_deposit_slot, 9_999);
}

// ═══════════════════════════════════════════════════════════════
// Conservation Property Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_deposit_withdraw_conservation() {
    let mut pool = new_pool();

    // Deposit 1M
    let deposit_amount = 1_000_000u64;
    let lp = pool.calc_lp_for_deposit(deposit_amount).unwrap();
    pool.total_deposited += deposit_amount;
    pool.total_lp_supply += lp;

    // Withdraw all LP
    let collateral_back = pool.calc_collateral_for_withdraw(lp).unwrap();

    // Should get back exactly what was deposited (first depositor, 1:1)
    assert_eq!(
        collateral_back, deposit_amount,
        "First depositor should get exact amount back"
    );
}

#[test]
fn test_two_depositors_conservation() {
    let mut pool = new_pool();

    // Depositor A: 1M
    let a_amount = 1_000_000u64;
    let a_lp = pool.calc_lp_for_deposit(a_amount).unwrap();
    pool.total_deposited += a_amount;
    pool.total_lp_supply += a_lp;

    // Depositor B: 500K
    let b_amount = 500_000u64;
    let b_lp = pool.calc_lp_for_deposit(b_amount).unwrap();
    pool.total_deposited += b_amount;
    pool.total_lp_supply += b_lp;

    // A withdraws
    let a_back = pool.calc_collateral_for_withdraw(a_lp).unwrap();
    pool.total_withdrawn += a_back;
    pool.total_lp_supply -= a_lp;

    // B withdraws
    let b_back = pool.calc_collateral_for_withdraw(b_lp).unwrap();
    pool.total_withdrawn += b_back;
    pool.total_lp_supply -= b_lp;

    // Total withdrawn should equal total deposited (no value created or destroyed)
    assert_eq!(a_back + b_back, a_amount + b_amount);
    assert_eq!(pool.total_lp_supply, 0);
}

#[test]
fn test_three_depositors_fairness() {
    let mut pool = new_pool();

    // Three depositors: 1M, 2M, 3M = 6M total
    let amounts = [1_000_000u64, 2_000_000, 3_000_000];
    let mut lps = [0u64; 3];

    for (i, &amt) in amounts.iter().enumerate() {
        lps[i] = pool.calc_lp_for_deposit(amt).unwrap();
        pool.total_deposited += amt;
        pool.total_lp_supply += lps[i];
    }

    // Each should get back proportional to deposit
    for (i, &lp) in lps.iter().enumerate() {
        let back = pool.calc_collateral_for_withdraw(lp).unwrap();
        // Allow 1 unit rounding error
        assert!(
            back >= amounts[i] - 1 && back <= amounts[i] + 1,
            "Depositor {} deposited {} but would get back {}",
            i,
            amounts[i],
            back
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// State Size Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_stake_pool_size() {
    // Verify the struct is a known size and bytemuck-compatible
    assert!(STAKE_POOL_SIZE > 0);
    assert_eq!(STAKE_POOL_SIZE, core::mem::size_of::<StakePool>());
    // Verify Pod alignment
    let _pool = StakePool::zeroed();
}

#[test]
fn test_stake_deposit_size() {
    assert!(STAKE_DEPOSIT_SIZE > 0);
    assert_eq!(STAKE_DEPOSIT_SIZE, core::mem::size_of::<StakeDeposit>());
    let _deposit = StakeDeposit::zeroed();
}

// ═══════════════════════════════════════════════════════════════
// PDA Derivation Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_pda_derivation_deterministic() {
    use percolator_vault::state::{derive_deposit_pda, derive_pool_pda, derive_vault_authority};
    use solana_program::pubkey::Pubkey;

    let program_id = Pubkey::new_unique();
    let slab = Pubkey::new_unique();
    let user = Pubkey::new_unique();

    let (pool1, bump1) = derive_pool_pda(&program_id, &slab);
    let (pool2, bump2) = derive_pool_pda(&program_id, &slab);
    assert_eq!(pool1, pool2);
    assert_eq!(bump1, bump2);

    let (auth1, abump1) = derive_vault_authority(&program_id, &pool1);
    let (auth2, abump2) = derive_vault_authority(&program_id, &pool1);
    assert_eq!(auth1, auth2);
    assert_eq!(abump1, abump2);

    let (dep1, dbump1) = derive_deposit_pda(&program_id, &pool1, &user);
    let (dep2, dbump2) = derive_deposit_pda(&program_id, &pool1, &user);
    assert_eq!(dep1, dep2);
    assert_eq!(dbump1, dbump2);
}

#[test]
fn test_different_slabs_different_pools() {
    use percolator_vault::state::derive_pool_pda;
    use solana_program::pubkey::Pubkey;

    let program_id = Pubkey::new_unique();
    let slab_a = Pubkey::new_unique();
    let slab_b = Pubkey::new_unique();

    let (pool_a, _) = derive_pool_pda(&program_id, &slab_a);
    let (pool_b, _) = derive_pool_pda(&program_id, &slab_b);
    assert_ne!(
        pool_a, pool_b,
        "Different slabs must have different pool PDAs"
    );
}

#[test]
fn test_different_users_different_deposits() {
    use percolator_vault::state::{derive_deposit_pda, derive_pool_pda};
    use solana_program::pubkey::Pubkey;

    let program_id = Pubkey::new_unique();
    let slab = Pubkey::new_unique();
    let (pool, _) = derive_pool_pda(&program_id, &slab);

    let user_a = Pubkey::new_unique();
    let user_b = Pubkey::new_unique();

    let (dep_a, _) = derive_deposit_pda(&program_id, &pool, &user_a);
    let (dep_b, _) = derive_deposit_pda(&program_id, &pool, &user_b);
    assert_ne!(
        dep_a, dep_b,
        "Different users must have different deposit PDAs"
    );
}

// ═══════════════════════════════════════════════════════════════
// Instruction Decoding Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_decode_init_pool() {
    let mut data = vec![0u8]; // tag = 0
    data.extend_from_slice(&100u64.to_le_bytes()); // cooldown_slots
    data.extend_from_slice(&5_000_000u64.to_le_bytes()); // deposit_cap

    let ix = StakeInstruction::unpack(&data).unwrap();
    match ix {
        StakeInstruction::InitPool {
            cooldown_slots,
            deposit_cap,
        } => {
            assert_eq!(cooldown_slots, 100);
            assert_eq!(deposit_cap, 5_000_000);
        }
        _ => panic!("Expected InitPool"),
    }
}

#[test]
fn test_decode_deposit() {
    let mut data = vec![1u8]; // tag = 1
    data.extend_from_slice(&1_000_000u64.to_le_bytes());

    let ix = StakeInstruction::unpack(&data).unwrap();
    match ix {
        StakeInstruction::Deposit { amount } => assert_eq!(amount, 1_000_000),
        _ => panic!("Expected Deposit"),
    }
}

#[test]
fn test_decode_withdraw() {
    let mut data = vec![2u8];
    data.extend_from_slice(&500_000u64.to_le_bytes());

    let ix = StakeInstruction::unpack(&data).unwrap();
    match ix {
        StakeInstruction::Withdraw { lp_amount } => assert_eq!(lp_amount, 500_000),
        _ => panic!("Expected Withdraw"),
    }
}

#[test]
fn test_decode_flush() {
    let mut data = vec![3u8];
    data.extend_from_slice(&250_000u64.to_le_bytes());

    let ix = StakeInstruction::unpack(&data).unwrap();
    match ix {
        StakeInstruction::FlushToInsurance { amount } => assert_eq!(amount, 250_000),
        _ => panic!("Expected FlushToInsurance"),
    }
}

#[test]
fn test_decode_update_config_both() {
    let mut data = vec![4u8];
    data.push(1); // has_cooldown = true
    data.extend_from_slice(&200u64.to_le_bytes());
    data.push(1); // has_cap = true
    data.extend_from_slice(&10_000_000u64.to_le_bytes());

    let ix = StakeInstruction::unpack(&data).unwrap();
    match ix {
        StakeInstruction::UpdateConfig {
            new_cooldown_slots,
            new_deposit_cap,
        } => {
            assert_eq!(new_cooldown_slots, Some(200));
            assert_eq!(new_deposit_cap, Some(10_000_000));
        }
        _ => panic!("Expected UpdateConfig"),
    }
}

#[test]
fn test_decode_update_config_none() {
    let mut data = vec![4u8];
    data.push(0); // has_cooldown = false
    data.extend_from_slice(&0u64.to_le_bytes());
    data.push(0); // has_cap = false
    data.extend_from_slice(&0u64.to_le_bytes());

    let ix = StakeInstruction::unpack(&data).unwrap();
    match ix {
        StakeInstruction::UpdateConfig {
            new_cooldown_slots,
            new_deposit_cap,
        } => {
            assert_eq!(new_cooldown_slots, None);
            assert_eq!(new_deposit_cap, None);
        }
        _ => panic!("Expected UpdateConfig"),
    }
}

#[test]
fn test_decode_transfer_admin() {
    let data = vec![5u8];
    let ix = StakeInstruction::unpack(&data).unwrap();
    assert!(matches!(ix, StakeInstruction::TransferAdmin));
}

#[test]
fn test_decode_admin_resolve_market() {
    let data = vec![9u8];
    let ix = StakeInstruction::unpack(&data).unwrap();
    assert!(matches!(ix, StakeInstruction::AdminResolveMarket));
}

#[test]
fn test_decode_admin_withdraw_insurance() {
    let mut data = vec![10u8];
    data.extend_from_slice(&5_000_000u64.to_le_bytes()); // amount = 5M tokens
    let ix = StakeInstruction::unpack(&data).unwrap();
    assert!(matches!(
        ix,
        StakeInstruction::AdminWithdrawInsurance { amount: 5_000_000 }
    ));
}

#[test]
fn test_decode_invalid_tag() {
    let data = vec![99u8];
    assert!(StakeInstruction::unpack(&data).is_err());
}

#[test]
fn test_decode_empty_data() {
    let data: Vec<u8> = vec![];
    assert!(StakeInstruction::unpack(&data).is_err());
}

#[test]
fn test_decode_truncated_deposit() {
    let data = vec![1u8, 0, 0, 0]; // Only 4 bytes of amount (need 8)
    assert!(StakeInstruction::unpack(&data).is_err());
}

// ═══════════════════════════════════════════════════════════════
// Admin Transfer Flag Tests (state-level)
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_admin_transferred_flag() {
    let mut pool = new_pool();
    assert_eq!(pool.admin_transferred, 0);

    pool.admin_transferred = 1;
    assert_eq!(pool.admin_transferred, 1);
}

// ═══════════════════════════════════════════════════════════════
// Edge Case: Multiple Deposit/Withdraw Cycles
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_multiple_cycles_conservation() {
    let mut pool = new_pool();
    let mut total_in = 0u64;
    let mut total_out = 0u64;

    // 10 cycles of deposit + withdraw
    for i in 1..=10 {
        let amount = i * 100_000;

        // Deposit
        let lp = pool.calc_lp_for_deposit(amount).unwrap();
        if lp == 0 {
            continue;
        } // Skip if rounding kills it
        pool.total_deposited += amount;
        pool.total_lp_supply += lp;
        total_in += amount;

        // Immediately withdraw
        let back = pool.calc_collateral_for_withdraw(lp).unwrap();
        pool.total_withdrawn += back;
        pool.total_lp_supply -= lp;
        total_out += back;
    }

    // Conservation: total out ≤ total in (rounding favors pool)
    assert!(
        total_out <= total_in,
        "total_out={} > total_in={}",
        total_out,
        total_in
    );
    // Rounding dust should be tiny
    assert!(
        total_in - total_out <= 10,
        "Too much rounding dust: {}",
        total_in - total_out
    );
}
