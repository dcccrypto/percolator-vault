//! Pure LP math — extracted for Kani formal verification.
//!
//! No Solana/Pubkey dependencies. Just arithmetic.
//! Kani can verify these functions exhaustively.

/// Calculate LP tokens for a deposit.
///
/// # Arguments
/// * `total_lp_supply` - Current total LP tokens in circulation
/// * `total_pool_value` - Current total pool value (deposited - withdrawn)
/// * `deposit_amount` - Amount of collateral being deposited
///
/// # Returns
/// * `Some(lp_tokens)` - LP tokens to mint (rounds DOWN — pool-favoring)
/// * `None` - Arithmetic overflow
///
/// # Invariant
/// First depositor (supply == 0): gets 1:1 LP tokens.
/// Subsequent: `lp = amount * supply / pool_value` (pro-rata, rounded down).
pub fn calc_lp_for_deposit(
    total_lp_supply: u64,
    total_pool_value: u64,
    deposit_amount: u64,
) -> Option<u64> {
    if total_lp_supply == 0 && total_pool_value == 0 {
        // True first depositor — 1:1
        Some(deposit_amount)
    } else if total_lp_supply == 0 {
        // CRITICAL: LP supply is 0 but pool has orphaned value (e.g., returned insurance
        // after all LP holders withdrew). Allowing 1:1 deposits here would let the
        // depositor withdraw the entire orphaned value. Block deposits.
        None
    } else if total_pool_value == 0 {
        // LP tokens exist but pool value is 0 (fully flushed to insurance).
        // Existing holders have a claim on future insurance returns.
        // Allowing deposits would dilute that claim. Block deposits.
        None
    } else {
        // Pro-rata via u128 to prevent overflow
        let lp = (deposit_amount as u128)
            .checked_mul(total_lp_supply as u128)?
            .checked_div(total_pool_value as u128)?;
        if lp > u64::MAX as u128 {
            None
        } else {
            Some(lp as u64)
        }
    }
}

/// Calculate collateral for an LP token burn.
///
/// # Arguments
/// * `total_lp_supply` - Current total LP tokens
/// * `total_pool_value` - Current pool value
/// * `lp_amount` - LP tokens being burned
///
/// # Returns
/// * `Some(collateral)` - Collateral to return (rounds DOWN — pool-favoring)
/// * `None` - Division by zero or overflow
///
/// # Invariant
/// `collateral = lp_amount * pool_value / lp_supply` (rounded down).
/// Full burn returns ≤ pool_value (never more).
pub fn calc_collateral_for_withdraw(
    total_lp_supply: u64,
    total_pool_value: u64,
    lp_amount: u64,
) -> Option<u64> {
    if total_lp_supply == 0 {
        return None;
    }
    let collateral = (lp_amount as u128)
        .checked_mul(total_pool_value as u128)?
        .checked_div(total_lp_supply as u128)?;
    if collateral > u64::MAX as u128 {
        None
    } else {
        Some(collateral as u64)
    }
}

/// Calculate pool value from accounting state.
///
/// # Returns
/// * `Some(value)` if deposited + fees >= withdrawn
/// * `None` if accounting is broken (withdrawn > deposited + fees)
pub fn pool_value(total_deposited: u64, total_withdrawn: u64) -> Option<u64> {
    total_deposited.checked_sub(total_withdrawn)
}

/// Calculate pool value including accrued trading fees (PERC-272).
///
/// # Returns
/// * `Some(value)` if deposited + fees >= withdrawn
/// * `None` if accounting overflow or underflow
pub fn pool_value_with_fees(
    total_deposited: u64,
    total_withdrawn: u64,
    total_fees_earned: u64,
) -> Option<u64> {
    total_deposited
        .checked_sub(total_withdrawn)?
        .checked_add(total_fees_earned)
}

/// Calculate available flush amount.
///
/// `available = deposited + returned - withdrawn - flushed`
/// Uses saturating arithmetic (can't go negative).
///
/// `total_returned` (insurance withdrawn back into the vault after resolution)
/// is real collateral physically sitting in the vault, so it is re-flushable.
/// Omitting it (the previous formula) made returned insurance permanently
/// un-flushable even though the tokens were in the vault. Positives are summed
/// (saturating) before the negatives so a valid intermediate state cannot clamp
/// to 0 mid-computation.
pub fn flush_available(
    total_deposited: u64,
    total_returned: u64,
    total_withdrawn: u64,
    total_flushed: u64,
) -> u64 {
    total_deposited
        .saturating_add(total_returned)
        .saturating_sub(total_withdrawn)
        .saturating_sub(total_flushed)
}

/// Stake-weighted-average deposit slot for the withdrawal cooldown.
///
/// When a depositor tops up an existing LP position, resetting
/// `last_deposit_slot` to the current slot unconditionally would re-lock the
/// depositor's ENTIRE aged position under the cooldown — a tiny top-up could
/// freeze a large, long-aged position for the full cooldown again.
///
/// Instead, blend the existing position's age with the new deposit, weighted by
/// LP amount:
///
/// `blended = (existing_lp * existing_slot + new_lp * current_slot)
///              / (existing_lp + new_lp)`
///
/// then apply a **proportional freshness floor** (fix for issue #39):
///
/// `aged_credit = cooldown_slots * existing_lp / total_lp`  (integer, rounded down)
/// `floor       = current_slot.saturating_sub(aged_credit)`
/// `new_slot    = max(blended, floor)`
///
/// ## Why the proportional floor (issue #39 bypass — and why a flat floor fails)
///
/// Without any floor, an attacker who holds a very old (already-unlocked)
/// position can deposit a large fresh amount and still withdraw immediately.
/// The naive blended slot for a 9× fresh deposit onto a 10×-cooldown-aged
/// position (existing=1M LP @ slot 0, cooldown=10k, current=100k) is:
///
///   blended = 9M * 100k / 10M = 90_000
///   unlock_at = 90_000 + 10_000 = 100_000 = current_slot → gate passes → BYPASS
///
/// A **flat** floor `current - cooldown` = 90_000 is identical to the bypass
/// threshold, so `max(blended, 90_000) = 90_000` — the bypass is unchanged.
///
/// The **proportional** floor awards "aged credit" only for the fraction of
/// the total LP that was already old:
///
///   aged_credit = cooldown * existing_lp / total_lp
///               = 10_000 * 1M / 10M = 1_000
///   floor       = 100_000 - 1_000 = 99_000
///   unlock_at   = 99_000 + 10_000 = 109_000 > 100_000 → gate BLOCKS → FIXED
///
/// ## Properties preserved
///
/// * **100%-fresh deposit** (`existing_lp = 0`): aged_credit = 0, floor =
///   current_slot, new_slot = current_slot → full cooldown. Correct.
/// * **Tiny top-up onto a large aged position**: f_existing ≈ 1, aged_credit ≈
///   cooldown_slots, floor ≈ current_slot − cooldown_slots. The raw blended
///   slot is barely above existing_slot (the tiny new deposit barely moves it),
///   so the floor lifts it to current_slot − cooldown, meaning unlock =
///   current_slot. This is the minimum fair bound — the tiny top-up does NOT
///   re-lock for an extra full cooldown. No griefing.
/// * **Large fresh deposit onto small aged position**: f_existing ≈ 0,
///   aged_credit ≈ 0, floor ≈ current_slot. Raw blended is already near
///   current_slot; max is a near-no-op. Full cooldown for fresh capital.
/// * **No new LP** (`new_lp = 0`): floor guard skipped; blended = existing_slot
///   (pure weighted average with 0 new weight = identity). No change.
///
/// ## Overflow safety
///
/// * Blended: offset form (`lo + weighted_span / total_lp`), single u128
///   product per side, saturating_add on final sum.
/// * aged_credit: `(cooldown as u128) * (existing_lp as u128)` — both ≤ 2^64,
///   product ≤ 2^128 − 2 (fits u128). Divided by total_lp ≥ 1. Clipped to u64
///   via saturating cast before saturating_sub.
pub fn weighted_deposit_slot(
    existing_lp: u64,
    existing_slot: u64,
    new_lp: u64,
    current_slot: u64,
    cooldown_slots: u64,
) -> u64 {
    let total_lp = (existing_lp as u128) + (new_lp as u128);
    if total_lp == 0 {
        // No LP on either side — nothing aged, nothing new. Anchor to now.
        return current_slot;
    }
    // Anchor at the lower of the two slots and blend only the spans above it.
    // Exactly one side contributes a nonzero span, so there is no sum of two
    // large products and thus no u128 overflow even at u64::MAX inputs.
    let lo = existing_slot.min(current_slot);
    let existing_span = (existing_slot - lo) as u128; // 0 if existing is the lower
    let current_span = (current_slot - lo) as u128; // 0 if current is the lower
    let weighted_span = (existing_lp as u128) * existing_span + (new_lp as u128) * current_span;
    let offset = weighted_span / total_lp;
    // Mathematically offset <= max_span <= u64::MAX - lo, so `lo + offset` never
    // wraps. Use saturating_add anyway: it makes panic-freedom obvious without
    // the solver having to reason about the magnitude of a symbolic division,
    // and it fails safe (clamps to u64::MAX) rather than panicking even if some
    // future caller violated the invariant.
    let blended = lo.saturating_add(offset as u64);

    // Issue #39 — proportional freshness floor.
    // Only apply when fresh LP is actually being added.
    if new_lp > 0 {
        // aged_credit = cooldown_slots * existing_lp / total_lp
        // Maximum value: cooldown_slots (u64::MAX) * existing_lp (u64::MAX) = 2^128 - 2^65 + 1
        // which fits u128. Divided by total_lp ≥ 1. Result ≤ cooldown_slots ≤ u64::MAX.
        let aged_credit_u128 =
            (cooldown_slots as u128) * (existing_lp as u128) / total_lp;
        // Saturating cast: aged_credit ≤ cooldown_slots ≤ u64::MAX so this never saturates,
        // but the cast makes the invariant explicit and future-proof.
        let aged_credit = aged_credit_u128.min(u64::MAX as u128) as u64;
        let floor = current_slot.saturating_sub(aged_credit);
        blended.max(floor)
    } else {
        blended
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic Behavior ──

    #[test]
    fn test_first_depositor() {
        assert_eq!(calc_lp_for_deposit(0, 0, 1_000_000), Some(1_000_000));
    }

    #[test]
    fn test_pro_rata() {
        assert_eq!(
            calc_lp_for_deposit(1_000_000, 1_000_000, 500_000),
            Some(500_000)
        );
    }

    #[test]
    fn test_withdraw_proportional() {
        assert_eq!(
            calc_collateral_for_withdraw(2_000_000, 2_000_000, 1_000_000),
            Some(1_000_000)
        );
    }

    #[test]
    fn test_rounding_down() {
        assert_eq!(calc_lp_for_deposit(999_999, 1_000_000, 1), Some(0));
    }

    #[test]
    fn test_zero_supply_withdraw_none() {
        assert_eq!(calc_collateral_for_withdraw(0, 100, 10), None);
    }

    // ── Conservation ──

    #[test]
    fn test_roundtrip_no_profit() {
        // Deposit 1000 into pool with 5000 supply / 10000 value
        let lp = calc_lp_for_deposit(5_000, 10_000, 1_000).unwrap();
        assert_eq!(lp, 500); // 1000 * 5000 / 10000

        // Withdraw those LP tokens from updated pool
        let back = calc_collateral_for_withdraw(5_500, 11_000, 500).unwrap();
        assert_eq!(back, 1_000); // exact roundtrip at 2:1 ratio
    }

    #[test]
    fn test_roundtrip_with_rounding_loss() {
        // Deposit 7 into pool with 3 supply / 10 value → lp = 7*3/10 = 2
        let lp = calc_lp_for_deposit(3, 10, 7).unwrap();
        assert_eq!(lp, 2);

        // Withdraw 2 LP from pool (5 supply, 17 value) → col = 2*17/5 = 6
        let back = calc_collateral_for_withdraw(5, 17, 2).unwrap();
        assert_eq!(back, 6);
        assert!(back <= 7); // Can't profit
    }

    #[test]
    fn test_two_depositors_conservation() {
        // A deposits 100 (first depositor, 1:1)
        let a_lp = calc_lp_for_deposit(0, 0, 100).unwrap();
        assert_eq!(a_lp, 100);

        // B deposits 50
        let b_lp = calc_lp_for_deposit(100, 100, 50).unwrap();
        assert_eq!(b_lp, 50);

        // A withdraws
        let a_back = calc_collateral_for_withdraw(150, 150, 100).unwrap();
        assert_eq!(a_back, 100);

        // B withdraws from remaining
        let b_back = calc_collateral_for_withdraw(50, 50, 50).unwrap();
        assert_eq!(b_back, 50);

        assert!(a_back + b_back <= 100 + 50);
    }

    // ── Dilution Protection ──

    #[test]
    fn test_no_dilution_attack() {
        // A deposits 1000 (1:1)
        let a_lp = calc_lp_for_deposit(0, 0, 1000).unwrap();

        // A's value before B
        let a_value_before = calc_collateral_for_withdraw(a_lp, 1000, a_lp).unwrap();
        assert_eq!(a_value_before, 1000);

        // B deposits 1 (tiny amount)
        let b_lp = calc_lp_for_deposit(1000, 1000, 1).unwrap();
        assert_eq!(b_lp, 1); // floor(1*1000/1000) = 1

        // A's value after B deposits
        let a_value_after = calc_collateral_for_withdraw(1001, 1001, 1000).unwrap();
        assert!(a_value_after >= a_value_before); // A not diluted
    }

    // ── Edge Cases ──

    #[test]
    fn test_zero_deposit_zero_lp() {
        assert_eq!(calc_lp_for_deposit(100, 200, 0), Some(0));
    }

    #[test]
    fn test_zero_burn_zero_col() {
        assert_eq!(calc_collateral_for_withdraw(100, 200, 0), Some(0));
    }

    #[test]
    fn test_deposit_into_zero_value_pool_blocked() {
        // Supply > 0 but value = 0 → blocked (C9 fix: protects existing holders'
        // claim on future insurance returns from dilution)
        assert_eq!(calc_lp_for_deposit(100, 0, 50), None);
    }

    #[test]
    fn test_deposit_orphaned_value_blocked() {
        // Supply = 0 but value > 0 → blocked (C9 fix: prevents theft of
        // orphaned insurance returns by first new depositor)
        assert_eq!(calc_lp_for_deposit(0, 500, 1), None);
    }

    #[test]
    fn test_large_values_no_overflow() {
        let max = u64::MAX / 2;
        // Should handle via u128 intermediates
        assert!(calc_lp_for_deposit(max, max, max).is_some());
        assert!(calc_collateral_for_withdraw(max, max, max).is_some());
    }

    #[test]
    fn test_u64_max_deposit() {
        // All three are u64::MAX → pro-rata path (supply > 0, value > 0)
        // u64::MAX as u128 * u64::MAX as u128 = (2^64-1)^2 = 2^128 - 2^65 + 1
        // u128::MAX = 2^128 - 1, so it fits. Result = u64::MAX.
        let result = calc_lp_for_deposit(u64::MAX, u64::MAX, u64::MAX);
        assert_eq!(result, Some(u64::MAX));
    }

    // ── Pool Value ──

    #[test]
    fn test_pool_value_normal() {
        assert_eq!(pool_value(1000, 300), Some(700));
    }

    #[test]
    fn test_pool_value_overdrawn() {
        assert_eq!(pool_value(100, 200), None);
    }

    #[test]
    fn test_pool_value_exact() {
        assert_eq!(pool_value(100, 100), Some(0));
    }

    // ── Flush ──

    #[test]
    fn test_flush_available_normal() {
        // deposited - withdrawn - flushed (no returns) = 1000 - 200 - 300 = 500
        assert_eq!(flush_available(1000, 0, 200, 300), 500);
    }

    #[test]
    fn test_flush_available_overdrawn() {
        // withdrawn > deposited → saturates to 0
        assert_eq!(flush_available(100, 0, 200, 0), 0);
    }

    #[test]
    fn test_flush_available_fully_flushed() {
        assert_eq!(flush_available(1000, 0, 200, 800), 0);
    }

    #[test]
    fn test_flush_available_over_flushed() {
        // More flushed than available → saturates to 0
        assert_eq!(flush_available(1000, 0, 200, 900), 0);
    }

    #[test]
    fn test_flush_available_returned_is_reflushable() {
        // #9 regression: deposit 1000, flush 500, then 300 returned from
        // insurance into the vault. The vault physically holds 1000-500+300=800.
        // The old formula (deposited - withdrawn - flushed) returned only 500
        // and left the returned 300 permanently un-flushable. With returns
        // counted, available = 1000 + 300 - 0 - 500 = 800.
        assert_eq!(flush_available(1000, 300, 0, 500), 800);
    }

    #[test]
    fn test_flush_available_full_return_restores_capacity() {
        // Flush everything (500), get all 500 back → fully re-flushable again.
        assert_eq!(flush_available(500, 500, 0, 500), 500);
    }

    // ── Weighted deposit slot (#8 / #39) ──

    #[test]
    fn test_weighted_slot_first_deposit_is_current() {
        // No existing position → anchor exactly to the current slot.
        // cooldown=0: floor = 5_000 - 0 = 5_000; max(5_000, 5_000) = 5_000.
        assert_eq!(weighted_deposit_slot(0, 0, 1_000, 5_000, 0), 5_000);
    }

    #[test]
    fn test_weighted_slot_zero_lp_both_sides() {
        // Degenerate: no LP at all → current slot (no div-by-zero).
        // new_lp == 0 → freshness floor is skipped.
        assert_eq!(weighted_deposit_slot(0, 100, 0, 5_000, 0), 5_000);
    }

    #[test]
    fn test_weighted_slot_tiny_topup_barely_moves_large_aged_position() {
        // Large aged position (1_000_000 LP @ slot 0) + tiny top-up (1 LP @ slot
        // 1_000_000), cooldown = 1_000_000.
        //
        // Proportional floor:
        //   aged_credit = 1_000_000 * 1_000_000 / 1_000_001 = 999_999
        //   floor = 1_000_000 - 999_999 = 1
        //   blended (raw) = 0 (rounds down from 1/1_000_001)
        //   result = max(0, 1) = 1
        //
        // unlock_at = 1 + 1_000_000 = 1_000_001 > current_slot (1_000_000) →
        // NOT immediately withdrawable (the tiny top-up adds just 1 slot of
        // extra wait, not a full re-lock of 1_000_000 extra slots).
        let s = weighted_deposit_slot(1_000_000, 0, 1, 1_000_000, 1_000_000);
        assert_eq!(s, 1, "tiny top-up must not re-lock a large aged position for a full cooldown");
        // Specifically: NOT re-locked for a full cooldown (which would be
        // unlock = 1_000_000 + 1_000_000 = 2_000_000).
        assert!(s + 1_000_000 <= 1_000_000 + 2,
            "unlock must not be a full extra cooldown beyond current_slot");
    }

    #[test]
    fn test_weighted_slot_large_fresh_deposit_pulls_toward_now() {
        // Small aged position (1 LP @ slot 0) + large fresh deposit
        // (1_000_000 LP @ slot 1_000_000), cooldown = 1.
        // aged_credit = 1 * 1 / 1_000_001 = 0; floor = 1_000_000 - 0 = 1_000_000.
        // blended (raw) = 999_999; max(999_999, 1_000_000) = 1_000_000.
        // unlock = 1_000_000 + 1 = 1_000_001 > current (1_000_000) → BLOCKED.
        let s = weighted_deposit_slot(1, 0, 1_000_000, 1_000_000, 1);
        assert_eq!(s, 1_000_000);
    }

    #[test]
    fn test_weighted_slot_equal_weights_floor_applied() {
        // Equal LP on each side (500 each), existing @ slot 100, current = 300, cooldown = 100.
        // blended (raw) = midpoint = 200.
        // aged_credit = 100 * 500 / 1000 = 50; floor = 300 - 50 = 250.
        // max(200, 250) = 250 — floor wins because fresh fraction (50%) is large enough
        // that the blended slot (200) is too old to guarantee the fresh capital waits.
        assert_eq!(weighted_deposit_slot(500, 100, 500, 300, 100), 250);
    }

    #[test]
    fn test_weighted_slot_within_bounds_and_never_future() {
        // Result must never exceed current_slot (cannot produce a future slot).
        // With cooldown=0: aged_credit=0, floor=current_slot=4000.
        // blended raw = 1000 + 456*3000/579 ≈ 3363; max(3363, 4000) = 4000 = current. Fine.
        let existing_slot = 1_000u64;
        let current_slot = 4_000u64;
        let s = weighted_deposit_slot(123, existing_slot, 456, current_slot, 0);
        assert!(s <= current_slot, "result must never be in the future");
    }

    #[test]
    fn test_weighted_slot_no_overflow_at_u64_max() {
        // Extreme magnitudes must not panic/overflow (u128 intermediates).
        // All u64::MAX: aged_credit = MAX * MAX / (MAX+MAX) = MAX/2 (approx).
        // floor = MAX - MAX/2 = MAX/2 + 1 (approx). blended = MAX. max = MAX.
        let s = weighted_deposit_slot(u64::MAX, u64::MAX, u64::MAX, u64::MAX, 0);
        assert_eq!(s, u64::MAX);
        // Also verify no panic with non-zero cooldown at u64::MAX.
        let _ = weighted_deposit_slot(u64::MAX, u64::MAX / 2, u64::MAX, u64::MAX, u64::MAX);
    }

    // ── Rounding Direction ──

    #[test]
    fn test_lp_rounds_down_not_up() {
        // deposit=7, supply=3, pool_value=10 → 7*3/10 = 2.1 → should be 2
        let lp = calc_lp_for_deposit(3, 10, 7).unwrap();
        assert_eq!(lp, 2);
        // Verify: lp * pv <= dep * supply (pool-favoring)
        assert!((lp as u128) * 10 <= (7u128) * 3);
    }

    #[test]
    fn test_withdrawal_rounds_down_not_up() {
        // lp=3, supply=7, pool_value=10 → 3*10/7 = 4.28 → should be 4
        let col = calc_collateral_for_withdraw(7, 10, 3).unwrap();
        assert_eq!(col, 4);
        // Verify: col * supply <= lp * pv (pool-favoring)
        assert!((col as u128) * 7 <= (3u128) * 10);
    }

    // ── C9 Attack Scenarios ──

    #[test]
    fn test_c9_orphaned_insurance_theft_blocked() {
        // Scenario: All LP holders withdrew, then insurance returned to vault.
        // pool_value > 0, LP_supply = 0. Attacker deposits 1 token.
        // OLD behavior: attacker gets 1 LP (1:1), then withdraws entire pool_value.
        // NEW behavior: None — deposits blocked when orphaned value exists.
        assert_eq!(calc_lp_for_deposit(0, 10_000_000, 1), None);
    }

    #[test]
    fn test_c9_dilution_attack_blocked() {
        // Scenario: Pool fully flushed (value=0), LP holders still have tokens.
        // New depositor at 1:1 would dilute existing holders' insurance claims.
        // Blocked: pool_value == 0 with supply > 0.
        assert_eq!(calc_lp_for_deposit(1000, 0, 500), None);
    }

    #[test]
    fn test_c9_true_first_depositor_works() {
        // True first deposit: both supply and value are 0. 1:1 ratio.
        assert_eq!(calc_lp_for_deposit(0, 0, 1000), Some(1000));
    }

    #[test]
    fn test_c9_normal_pro_rata_unaffected() {
        // Normal state: supply > 0, value > 0. Pro-rata works as before.
        assert_eq!(calc_lp_for_deposit(1000, 2000, 500), Some(250));
    }

    // ── Monotonicity ──

    #[test]
    fn test_larger_deposit_more_lp() {
        let small = calc_lp_for_deposit(100, 200, 10).unwrap();
        let large = calc_lp_for_deposit(100, 200, 20).unwrap();
        assert!(large >= small);
    }

    #[test]
    fn test_larger_burn_more_collateral() {
        let small = calc_collateral_for_withdraw(100, 200, 10).unwrap();
        let large = calc_collateral_for_withdraw(100, 200, 20).unwrap();
        assert!(large >= small);
    }

    // ── PERC-272: Fee-inclusive Pool Value ──

    #[test]
    fn test_pool_value_with_fees() {
        assert_eq!(pool_value_with_fees(1000, 200, 100), Some(900));
    }

    #[test]
    fn test_pool_value_with_fees_zero() {
        assert_eq!(pool_value_with_fees(1000, 1000, 0), Some(0));
    }

    #[test]
    fn test_pool_value_with_fees_overflow() {
        assert_eq!(pool_value_with_fees(100, 200, 50), None);
    }

    #[test]
    fn test_fee_appreciation_increases_share_price() {
        let lp_before = calc_collateral_for_withdraw(1000, 1000, 100).unwrap();
        assert_eq!(lp_before, 100);
        let lp_after = calc_collateral_for_withdraw(1000, 1200, 100).unwrap();
        assert_eq!(lp_after, 120);
    }
}

// ═══════════════════════════════════════════════════════════════
// PERC-313: High-Water Mark Protection
// ═══════════════════════════════════════════════════════════════

/// Calculate the HWM floor: epoch_high_water_tvl × hwm_floor_bps / 10_000.
/// Returns None on overflow (conservative deny).
pub fn hwm_floor(epoch_high_water_tvl: u64, hwm_floor_bps: u16) -> Option<u64> {
    let floor = (epoch_high_water_tvl as u128)
        .checked_mul(hwm_floor_bps as u128)?
        .checked_div(10_000)?;
    if floor > u64::MAX as u128 {
        None
    } else {
        Some(floor as u64)
    }
}

/// Check whether a withdrawal is allowed under HWM protection.
/// Returns `true` if post-withdrawal TVL >= floor.
/// Returns `false` if it would push TVL below the HWM floor.
pub fn hwm_withdrawal_allowed(
    post_withdrawal_tvl: u64,
    epoch_high_water_tvl: u64,
    hwm_floor_bps: u16,
) -> bool {
    match hwm_floor(epoch_high_water_tvl, hwm_floor_bps) {
        Some(floor) => post_withdrawal_tvl >= floor,
        None => false, // overflow → conservative deny
    }
}

#[cfg(test)]
mod hwm_tests {
    use super::*;

    #[test]
    fn test_hwm_floor_basic() {
        assert_eq!(hwm_floor(1000, 5000), Some(500)); // 50% of 1000
        assert_eq!(hwm_floor(1000, 10_000), Some(1000)); // 100% of 1000
        assert_eq!(hwm_floor(1000, 0), Some(0)); // 0% floor
    }

    #[test]
    fn test_hwm_withdrawal_allowed_above_floor() {
        assert!(hwm_withdrawal_allowed(600, 1000, 5000));
    }

    #[test]
    fn test_hwm_withdrawal_allowed_at_floor() {
        assert!(hwm_withdrawal_allowed(500, 1000, 5000));
    }

    #[test]
    fn test_hwm_withdrawal_blocked_below_floor() {
        assert!(!hwm_withdrawal_allowed(499, 1000, 5000));
    }

    #[test]
    fn test_hwm_zero_floor_always_allows() {
        assert!(hwm_withdrawal_allowed(0, 1000, 0));
    }

    #[test]
    fn test_hwm_full_floor_requires_full() {
        assert!(!hwm_withdrawal_allowed(999, 1000, 10_000));
        assert!(hwm_withdrawal_allowed(1000, 1000, 10_000));
    }
}

// ═══════════════════════════════════════════════════════════════
// Kani Formal Verification
// ═══════════════════════════════════════════════════════════════
//
// Production-type (u64/u128) proofs live in kani-proofs/ crate with
// u32/u64 mirrors for CBMC tractability. See kani-proofs/src/lib.rs.
//
// Keeping this note here so nobody adds u64 Kani proofs that timeout.

// (PERC-272 tests moved to mod tests above)
