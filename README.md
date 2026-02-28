# Percolator LP Vault

Standalone Solana program for LP vaults powering [Percolator](https://github.com/dcccrypto/percolator-launch) perpetual markets.

## Overview

The vault program manages two types of LP pools per market (slab):

| Mode | Pool Type | How LPs Earn |
|------|-----------|-------------|
| 0 | **Insurance LP** | Back the insurance fund; earn from insurance withdrawals and market resolution |
| 1 | **Trading LP** | Earn trading fees via share-price appreciation (AccrueFees crank) |

### Architecture

```
┌──────────────────────────────────────────────────┐
│  Percolator Wrapper (thin perp engine)           │
│  • Pure math: funding, PnL, liquidation          │
│  • header.admin = vault pool PDA                 │
└──────────────┬───────────────────────────────────┘
               │ CPI (PDA-signed)
┌──────────────▼───────────────────────────────────┐
│  Percolator Vault (this program)                 │
│  • LP deposit / withdraw with cooldown           │
│  • Insurance flush (vault → wrapper insurance)   │
│  • Fee accrual (trading LP mode)                 │
│  • Admin forwarding (oracle, risk, fees)         │
│  • Epoch accounting                              │
└──────────────────────────────────────────────────┘
```

The vault PDA becomes the **admin** of the percolator wrapper slab. This means:
- The wrapper stays thin (pure perp math) — auditable in isolation
- Policy logic (caps, cooldowns, fee distribution) lives here
- Admin operations (set oracle, risk thresholds) are forwarded via CPI with PDA signature

### Instructions

| # | Instruction | Description |
|---|------------|-------------|
| 0 | `InitPool` | Create an insurance LP pool for a slab (market) |
| 1 | `Deposit` | Deposit collateral → vault, receive LP tokens pro-rata |
| 2 | `Withdraw` | Burn LP tokens → withdraw collateral (after cooldown) |
| 3 | `FlushToInsurance` | CPI TopUpInsurance — move vault funds → wrapper insurance |
| 4 | `UpdateConfig` | Admin updates cooldown period, deposit caps |
| 5 | `TransferAdmin` | One-time: transfer wrapper admin to pool PDA |
| 6 | `AdminSetOracleAuth` | CPI SetOracleAuthority on wrapper |
| 7 | `AdminSetRiskThreshold` | CPI SetRiskThreshold on wrapper |
| 8 | `AdminSetMaintenanceFee` | CPI SetMaintenanceFee on wrapper |
| 9 | `AdminResolveMarket` | CPI ResolveMarket (end-of-epoch) |
| 10 | `AdminWithdrawInsurance` | CPI WithdrawInsurance → distribute to LPs |
| 11 | `AdminSetInsurancePolicy` | CPI SetInsuranceWithdrawPolicy on wrapper |
| 12 | `AccrueFees` | Permissionless crank — accrues trading fees into vault |
| 13 | `InitTradingPool` | Create a trading LP pool (mode 1) |

### Key Data Structures

- **StakePool** — Per-slab pool state (PDA seeds: `[b"stake_pool", slab_pubkey]`)
  - Tracks deposits, withdrawals, LP supply, insurance flushes, fee accruals
  - `pool_mode`: 0 = insurance, 1 = trading LP
- **StakeDeposit** — Per-user deposit record (PDA seeds: `[b"deposit", pool_pubkey, user_pubkey]`)
  - Tracks deposit slot for cooldown enforcement

## Building

```bash
# Native (for testing)
cargo build --features no-entrypoint

# SBF (for deployment)
cargo build-sbf
```

## Testing

```bash
# Unit + integration tests
cargo test --features no-entrypoint

# With proptest math fuzzing
cargo test --features no-entrypoint -- --include-ignored

# Clippy lint
cargo clippy --features no-entrypoint -- -D warnings

# Format check
cargo fmt --all -- --check
```

## Formal Verification (Kani)

The `kani-proofs/` crate contains zero-dependency formal proofs for LP math:

```bash
cd kani-proofs
cargo kani --lib --output-format terse
```

Proofs verify:
- LP mint/burn calculations never overflow
- Share price monotonically increases with fee accrual
- Deposit → withdraw round-trip is lossless (no rounding exploits)
- Pool value accounting is consistent

## Integration with Percolator

This program is designed to work with:
- [`percolator-prog`](https://github.com/dcccrypto/percolator-prog) — the core perp engine (wrapper)
- [`percolator-launch`](https://github.com/dcccrypto/percolator-launch) — the frontend + SDK

The vault CPI-calls into the wrapper for insurance operations and admin forwarding.
The wrapper only knows that its `header.admin` signed the instruction — it doesn't know
(or care) that it's a vault PDA.

## License

Apache-2.0 — see [LICENSE](LICENSE).
