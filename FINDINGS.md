# Percolator Vault Security Findings

**Target:** `dcccrypto/percolator-vault`  
**Primary source:** `src/processor.rs` (1 255 lines), `src/math.rs`, `src/state.rs`, `src/cpi.rs`  
**Audit date:** 2026-06-21  
**Scope:** Manual line-by-line review of all instruction handlers, LP math, state struct, and CPI encoding.  
**Methodology:** Differential comparison against hardened percolator-stake plus independent handler-level read.

---

## VULN-01 — LP Mint Created with Live Freeze Authority (MEDIUM)

**Location:** `src/processor.rs:213`

### Root cause

`process_init_pool` initialises the LP mint with `Some(vault_auth.key)` as the freeze authority:

```rust
// processor.rs:208-218
invoke_signed(
    &spl_token::instruction::initialize_mint(
        token_program.key,
        lp_mint.key,
        vault_auth.key,
        Some(vault_auth.key),   // ← freeze authority retained
        6,
    )?,
    ...
```

`vault_auth` is the program's own PDA. Any future `invoke_signed` path that produces a `vault_auth` signer (e.g., after a malicious upgrade) can call `spl_token::instruction::freeze_account` on any LP holder's ATA, permanently blocking withdrawals for that holder. The freeze authority is never transferred away or burnt after init.

Percolator-stake fixed this as **FINDING-4** by passing `None` at the equivalent line (`percolator-stake/src/processor.rs:289`).

### Impact

LP holders' token accounts can be frozen. Frozen accounts cannot send tokens, so affected holders cannot burn LP and receive their collateral — their funds are permanently locked without any program-level withdrawal path. Trust guarantee violated: LP must always be redeemable.

### Attack path

1. A malicious program upgrade adds a `FreezeHolder` instruction that calls:
   ```rust
   invoke_signed(
       &spl_token::instruction::freeze_account(token_program, target_ata, lp_mint, vault_auth, &[])?,
       ...,
       &[vault_auth_seeds],
   )
   ```
2. Admin (or compromised admin key) sends the instruction targeting any LP holder's ATA.
3. Victim's LP ATA is frozen; `spl_token::transfer` and `spl_token::burn` both revert.
4. Victim cannot call `Withdraw`; funds are permanently locked.

### Fix

Change `Some(vault_auth.key)` → `None` on line 213:

```rust
&spl_token::instruction::initialize_mint(
    token_program.key,
    lp_mint.key,
    vault_auth.key,
    None,   // freeze authority must not be retained
    6,
)?
```

### PoC

`tests/poc_vuln01_freeze_authority.rs` — `cargo test poc_vuln01`

Anti-hollow differential:
- Call `InitPool` → verify LP mint's `freeze_authority` field on-chain is `COption::None`.
- Attempt `freeze_account` via vault_auth signer → must revert with `OwnerMismatch` (no authority).

---

## VULN-02 — Deposit PDA Squatting Permanently Blocks User Deposits (MEDIUM)

**Location:** `src/processor.rs:425-443`

### Root cause

`process_deposit` creates the per-user deposit PDA with a bare `system_instruction::create_account`:

```rust
// processor.rs:425-443
if deposit_pda.data_is_empty() {
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
```

The Solana system program's `create_account` handler returns `SystemError::AccountAlreadyInUse` if the target account has **any lamports at all**, even 1 lamport with no data allocated. `data_is_empty()` is `true` for a bare-lamport account (no data, system-program owner), so the create_account call is attempted and immediately fails.

Percolator-stake fixed this as **#163** with a `create_or_adopt_pda` helper that supplements a pre-funded address to rent-exempt minimum and then reassigns ownership.

### Impact

An attacker can permanently prevent a specific user from depositing into any pool, with a per-victim cost of 1 lamport (~$0.0000001). The attack is irreversible from the victim's perspective — there is no recovery path in the vault program. Existing LP positions are unaffected (withdrawal still works), but no new capital can be added.

At scale, a griefer can grief an entire user base for fractions of a cent.

### Attack path

1. Derive victim's deposit PDA off-chain:
   ```
   PDA = find_program_address(["stake_deposit", pool_pda, victim_wallet], vault_program_id)
   ```
2. Transfer 1 lamport to the derived address from any funded wallet. No program interaction required.
3. Victim calls `Deposit` → `data_is_empty()` is `true` → `create_account` attempted → `AccountAlreadyInUse` → tx reverts.
4. All future deposit attempts by victim against this pool revert with the same error.

### Fix

Replace the bare `create_account` with the squatting-safe pattern from percolator-stake:

```rust
// If account has lamports but no data (squatted), supplement and reassign
if deposit_pda.data_is_empty() {
    let needed = rent.minimum_balance(STAKE_DEPOSIT_SIZE);
    if deposit_pda.lamports() == 0 {
        // Normal first creation
        invoke_signed(&system_instruction::create_account(...), ...)?;
    } else if *deposit_pda.owner == solana_program::system_program::ID {
        // Squatted — fund the gap and assign to this program
        let gap = needed.saturating_sub(deposit_pda.lamports());
        if gap > 0 {
            invoke(&system_instruction::transfer(user.key, deposit_pda.key, gap), ...)?;
        }
        invoke_signed(&system_instruction::assign(deposit_pda.key, program_id), ...)?;
        // Reallocate to STAKE_DEPOSIT_SIZE
        invoke_signed(&system_instruction::allocate(deposit_pda.key, STAKE_DEPOSIT_SIZE as u64), ...)?;
    } else {
        return Err(StakeError::InvalidAccount.into());
    }
}
```

### PoC

`tests/poc_vuln02_deposit_pda_squatting.rs` — `cargo test poc_vuln02`

Anti-hollow differential:
- Pre-fund victim deposit PDA with 1 lamport → victim's `Deposit` call must revert.
- (After fix) Pre-fund victim deposit PDA with 1 lamport → victim's `Deposit` call must succeed.

---

## VULN-03 — AdminSetHwmConfig Disable Silently Resets Floor to Zero (LOW)

**Location:** `src/processor.rs:1246-1247`

### Root cause

`process_admin_set_hwm_config` unconditionally writes `hwm_floor_bps` regardless of whether HWM is being enabled or disabled:

```rust
// processor.rs:1246-1247
pool.set_hwm_enabled(enabled);
pool.set_hwm_floor_bps(hwm_floor_bps);   // ← always written
```

When an admin calls this to **disable** HWM (e.g. `enabled=false`), the caller conventionally passes `hwm_floor_bps=0` (since the field is irrelevant while disabled and the on-chain validation `hwm_floor_bps > 10_000` accepts 0). The stored floor is silently overwritten to 0. When the admin later re-enables HWM without explicitly re-specifying the floor, the floor remains 0 — meaning the HWM withdrawal check always passes (0% floor = no protection).

Percolator-stake fixed this as **#185** by only writing the floor when `enabled = true` (see `apply_hwm_config` at `percolator-stake/src/processor.rs:2142-2145`). Percolator-stake also validates `hwm_floor_bps != 0` when enabling (line 117).

### Impact

High-water mark protection can be permanently silently degraded without the admin noticing. After a disable/re-enable cycle without explicit floor reconfiguration, the HWM check (`post_tvl >= hwm * floor_bps / 10_000`) evaluates as `post_tvl >= 0` — always true — allowing unrestricted rapid TVL drain in a single epoch.

A malicious or mistaken admin key can exploit this by:
1. Calling `AdminSetHwmConfig(enabled=false, hwm_floor_bps=0)` — looks like a benign disable.
2. Calling `AdminSetHwmConfig(enabled=true, hwm_floor_bps=0)` — re-enables with floor=0.
3. Draining the pool in a single epoch, bypassing the HWM protection that operators believed was active.

### Fix

Only write the floor when enabling (mirroring percolator-stake #185):

```rust
pool.set_hwm_enabled(enabled);
if enabled {
    if hwm_floor_bps == 0 || hwm_floor_bps > 10_000 {
        return Err(ProgramError::InvalidInstructionData);
    }
    pool.set_hwm_floor_bps(hwm_floor_bps);
}
```

### PoC

`tests/poc_vuln03_hwm_floor_clobber.rs` — `cargo test poc_vuln03`

Anti-hollow differential:
- Configure HWM with `floor_bps=5000`. Disable. Re-enable (passing `hwm_floor_bps=0`). Verify floor is still 5000 (not 0). Without fix, floor is 0 and HWM check always passes.

---

## Leads investigated and ruled out

| Lead | Resolution |
|---|---|
| `calc_lp_for_deposit` uses `unwrap_or(0)` for `total_pool_value` (state.rs:357) | Benign: if `total_pool_value()=None` with `lp_supply>0`, math::calc_lp_for_deposit returns `None` (pool-value=0, supply>0 → block). Only `lp_supply==0` reaches first-depositor path, but that state is unreachable via normal operations (withdrawal rounds down). |
| `process_accrue_fees` reads vault balance before key check (lines 1149–1154) | Benign: key check fires at line 1154 **before** `total_fees_earned` is mutated at line 1171. No state change precedes the verification. |
| `total_returned > total_flushed` via `AdminWithdrawInsurance` | Not exploitable: `total_returned` is only incremented after a successful CPI to the wrapper's `WithdrawInsuranceLimited`, which physically transfers tokens into the stake vault. If more tokens enter than were flushed (shared insurance pool), pool value accounting remains correct. |
| `_reserved` bit collision (byte 9, bit 0 = resolved vs bit 1 = hwm_enabled) | Not a collision: different bits within the same byte. `is_resolved() = _reserved[9] & 0x01`; `hwm_enabled() = _reserved[9] & 0x02`. No interference. (Percolator-stake PERC-8422 used the whole byte; vault uses bit fields.) |
| Zeroed discriminator accepted (`validate_discriminator` accepts all-zero bytes, state.rs:148) | Defense-in-depth gap (ported FINDING-10 from stake would help), but the `is_initialized != 1` check at every handler entry provides a primary guard. Not independently exploitable to bypass auth. |
| Missing percolator program allowlist in `process_init_pool` | Admin-trust boundary: admin controls pool config including `percolator_program`. Stake's allowlist is defense-in-depth against key compromise. Not a standalone exploit path. |
