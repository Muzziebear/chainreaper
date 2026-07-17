# GMX Invariant Specification

A concrete, testable invariant suite for GMX **V1** (`gmx-contracts`) and **V2** (`gmx-synthetics`),
each written as a property + the exact code hook + the tool that checks it. This is the spec the
fuzzing/handler harness in `tools_poc/` implements, and the template the Chainreaper Recon stage
(`IMPLEMENTATION-SPEC.md` §S2) emits per target.

> Grounded in the actual accounting primitives: V1 `Vault` (`poolAmounts`, `reservedAmounts`,
> `feeReserves`, `guaranteedUsd`, `usdgAmounts`, `globalShortSizes`, `globalShortAveragePrices`),
> `ShortsTracker` (`globalShortAveragePrices`, `isGlobalShortDataReady`), `GlpManager.getAum`;
> V2 `MarketUtils` (`getMarketTokenPrice`, `getPoolValueInfo`, `getNetPnl`, `getPnl`,
> `getPnlToPoolFactor`, `validateReserve`, `getReservedUsd`, `getOpenInterest`).

**Legend** — Severity: 🔴 funds-critical · 🟡 high · 🟢 medium.
Tool: `FND` Foundry invariant · `MED` Medusa/Echidna stateful · `HAL` Halmos symbolic ·
`CER` Certora · `WAKE` Wake scenario · `SLI` Slither static · `PROP` crytic/properties.

---

## 0. Methodology

**Actor/handler model.** Invariants are checked by a `Handler` that exposes bounded actions driven by
a fuzzer, run by a small set of **actors** (ghost-tracked): `LP` (mint/redeem GLP/GM), `Trader`
(increase/decrease long & short, swap), `Keeper` (execute/cancel orders, set prices within bounds),
`Liquidator` (liquidate, ADL). The fuzzer composes random action sequences; after each call the
invariant assertions run.

**Ghost variables** (tracked in the handler, compared to contract state):
`g_depositedByActor[token]`, `g_withdrawnByActor[token]`, `g_feesPaid`, `g_realizedPnl`,
`g_glpMinted/Burned`, `g_lastAum`, `g_lastGlpPrice`. Conservation invariants compare ghosts to
on-chain balances.

**Tiers** (run all; escalate the hard ones):
1. `FND` Foundry invariant — smoke, every commit (`forge test --mt invariant_`).
2. `MED` Medusa — deep, parallel, coverage-guided, nightly; **also optimization mode** (maximize
   `glpPrice`/`aum`) for the 2025 manipulation class.
3. `MED` Echidna — targeted properties + shrinking + fork mode.
4. `HAL`/`CER` — symbolic/formal proof of the few arithmetic invariants fuzzing can't exhaust.
5. `WAKE` — scenario reproduction for path-specific bugs (cross-contract reentrancy).

**Reuse:** crytic/properties (`tools_poc/properties/`) supplies ready-made `ERC4626` (GM/GLP vault
share math), `ERC20` (token), and `ABDKMath64x64` (fixed-point) properties — wire these before
writing custom ones.

**ID scheme:** `SOLV` solvency · `PRICE` share price · `POS` position/PnL · `LIQ` liquidation/ADL ·
`ORAC` oracle · `FEE` fees/funding/rounding · `EXEC` execution/reentrancy · `AC` access/config ·
`XMOD` cross-module (V2). Each ID is a stable handle used by the harness and Chainreaper findings.

---

## 1. Solvency & value conservation 🔴

| ID | Invariant | V1 hook | V2 hook | Tool |
|---|---|---|---|---|
| SOLV-01 | Real balance covers obligations: `token.balanceOf(vault) ≥ poolAmounts[t] + feeReserves[t]` | `Vault.poolAmounts`,`feeReserves`,`tokenBalances` | market token balance ≥ pool+claimable | FND/MED |
| SOLV-02 | Reserves never exceed pool: `reservedAmounts[t] ≤ poolAmounts[t]` | `Vault.reservedAmounts` | `validateReserve`, `getReservedUsd ≤ poolUsd` | FND/MED |
| SOLV-03 | **Conservation:** Σ(actor deposits) − Σ(withdrawals) − Σ(fees) == net pool delta; no value minted from nothing | ghost vs `poolAmounts`/balances | ghost vs `getPoolValueInfo` | MED |
| SOLV-04 | Redemption backing: `getRedemptionCollateral(t) ≥` USDG owed against `t` | `Vault.getRedemptionCollateral`,`usdgAmounts` | poolValue ≥ GM supply × min price | FND/MED |
| SOLV-05 | Long backing: `guaranteedUsd[t]` consistent with open long size − collateral | `Vault.guaranteedUsd` | open-interest accounting | MED |
| SOLV-06 | Utilisation ≤ 100% | `Vault.getUtilisation` | reserved ≤ pool | FND |
| SOLV-07 | Drain-resistance (optimization): no action sequence increases an actor's net asset value at the pool's expense | balances delta | `getPoolValueInfo` delta | MED (opt) |

## 2. GM/GLP share-price integrity 🔴  *(2025-hack class)*

| ID | Invariant | V1 hook | V2 hook | Tool |
|---|---|---|---|---|
| PRICE-01 | **AUM/price is reentrancy-stable:** `getAum`/`getMarketTokenPrice` identical at start vs. any reentrant re-read within a tx | `GlpManager.getAum` | `MarketUtils.getMarketTokenPrice` | WAKE/MED |
| PRICE-02 | **`globalShortSize` ↔ `globalShortAveragePrice` never observed inconsistent** (the lag the attacker exploited) | `ShortsTracker.globalShortAveragePrices`, `Vault.globalShortSizes` | short-side pool accounting | WAKE/MED |
| PRICE-03 | Mint→redeem round-trip in one block ≤ identity (no inflation/bounce extraction) | `GlpManager.addLiquidity/removeLiquidity` | deposit/withdrawal handlers | MED + `PROP`(ERC4626) |
| PRICE-04 | Global short PnL added to AUM is bounded by real exposure; can't exceed pool | `Vault.getGlobalShortDelta` | `getNetPnl`, `getCappedPnl` | MED |
| PRICE-05 | `getAum` monotonic w.r.t. only price + real flows, not call ordering | `GlpManager.getAum(maximise)` | `getPoolValueInfo` | HAL/MED |

## 3. Position & PnL correctness 🟡

| ID | Invariant | V1 hook | V2 hook | Tool |
|---|---|---|---|---|
| POS-01 | Every open position respects `maxLeverage` (V1 50×) | `Vault.maxLeverage`,`_validatePosition` | leverage config | FND/MED |
| POS-02 | No size without collateral; collateral ≥ 0 after any op | `Vault.positions` | `Position.Props` | MED |
| POS-03 | `averagePrice` update math has no precision/rounding exploit | `Vault.getNextAveragePrice` | `getNextPositionAveragePrice` | HAL + `PROP`(ABDKMath) |
| POS-04 | PnL symmetry: trader profit == pool loss (no asymmetric creation) | `Vault.getDelta` | `getPnl`/`getNetPnl` | MED |
| POS-05 | Closing a position pays exactly entry±PnL−fees (no over/under-pay) | decrease path | decrease order path | MED |

## 4. Liquidation & ADL 🔴

| ID | Invariant | V1 hook | V2 hook | Tool |
|---|---|---|---|---|
| LIQ-01 | Liquidatable ⇒ always closeable (no revert-lock) | `Vault.validateLiquidation` | `liquidation/` | MED |
| LIQ-02 | No silent bad debt: shortfall is either covered by collateral or accounted | `Vault.liquidatePosition` | liquidation accounting | MED |
| LIQ-03 | Liquidation fee paid exactly once, ≤ `liquidationFeeUsd` | `Vault.liquidationFeeUsd` | liquidation fee | FND |
| LIQ-04 | ADL only when `getPnlToPoolFactor` > cap, and proportional | — (V1 n/a) | `adl/`, `getPnlToPoolFactor` | MED |
| LIQ-05 | A solvent position is never liquidatable | `validateLiquidation` | liquidation check | HAL/MED |

## 5. Oracle / pricing 🔴

| ID | Invariant | V1 hook | V2 hook | Tool |
|---|---|---|---|---|
| ORAC-01 | Execution price ∈ `[minPrice,maxPrice]` window | `VaultPriceFeed.getPrice` | `Oracle` min/max | FND/MED |
| ORAC-02 | Stale/expired prices rejected | `FastPriceFeed` age | signed-price freshness | FND |
| ORAC-03 | **No price signature replay** (V2 signed oracle) | — | `oracle/` sig verify | WAKE/SLI |
| ORAC-04 | Swap output respects price × (1−fee); swap can't drain pool | `Vault.swap`,`getMaxPrice` | `swap/`,`SwapPricingUtils` | MED |
| ORAC-05 | Single-block price manipulation can't move execution beyond spread | fast-price keeper | keeper price | MED (fork) |

## 6. Fees, funding & rounding 🟡

| ID | Invariant | V1 hook | V2 hook | Tool |
|---|---|---|---|---|
| FEE-01 | **Rounding always favors the pool** (mint/redeem/swap/PnL); no dust extraction | all math paths | all math paths | MED + HAL |
| FEE-02 | No division-before-multiplication in price/PnL/fee math | (structural) | (structural) | SLI + HAL |
| FEE-03 | `feeReserves` only increase except via `withdrawFees`; total == Σ per-action fees | `Vault.feeReserves`,`withdrawFees` | claimable fees | FND/MED |
| FEE-04 | Funding accrues monotonically; can't be dodged by intra-block open/close | `cumulativeFundingRates`,`lastFundingTimes` | funding module | MED |
| FEE-05 | Borrowing fee ≥ 0 and bounded by config | margin fee bps | borrowing module | FND |

## 7. Order lifecycle, execution & reentrancy 🔴

| ID | Invariant | V1 hook | V2 hook | Tool |
|---|---|---|---|---|
| EXEC-01 | **No cross-contract reentrancy mutation:** an execution/transfer callback cannot reenter and change pool/price/position state mid-execution (the 2025 vector) | `PositionManager.executeDecreaseOrder` → WETH unwrap → fallback | order/callback handlers | **WAKE** + MED |
| EXEC-02 | Keeper execution never worse than user `acceptablePrice` / min-out (slippage honored) | `PositionRouter`,`OrderBook` | `acceptablePrice` in order | MED |
| EXEC-03 | No stuck funds: every created order is executable or cancellable with full refund | `PositionRouter` queue | order store | MED |
| EXEC-04 | `_account` treated as untrusted (no EOA assumption); callbacks gas-bounded | decrease path | `callback/` | SLI/WAKE |

## 8. Access control & config 🟡

| ID | Invariant | V1 hook | V2 hook | Tool |
|---|---|---|---|---|
| AC-01 | Only keepers execute; only timelock/RoleStore-admin sets params | `Vault.gov`,`Timelock` | `role/RoleStore` | SLI + FND |
| AC-02 | Config bounds enforced (`fee ≤ MAX_FEE_BASIS_POINTS`, `leverage > MIN_LEVERAGE`) | `Vault.setFees`,`_validate` | `config/` bounds | FND/HAL |
| AC-03 | Param change can't instantly break SOLV-01..03 (e.g. raising maxLeverage past solvency) | setters | config setters | MED |
| AC-04 | Upgrade/init guards: no re-init, no unprotected upgrade | `isInitialized` | proxy/init | SLI(`check-upgradeability`) |

## 9. Cross-module (V2) 🟡

| ID | Invariant | V2 hook | Tool |
|---|---|---|---|
| XMOD-01 | GLV value == Σ underlying GM positions (no double-count) | `glv/` | MED |
| XMOD-02 | `shift` between markets conserves value | `shift/` | MED |
| XMOD-03 | Multichain message replay protection; bridged balances conserved | `multichain/` | WAKE/SLI |
| XMOD-04 | Subaccount actions bounded by granted permissions | `subaccount/` | FND |

---

## 10. The 2025-hack regression suite (must-pass)

The July-2025 $42M exploit is precisely **PRICE-01 + PRICE-02 + EXEC-01** failing together. Encode as
a dedicated **Wake scenario** that reproduces the path and asserts the invariants, plus a Medusa
optimization target:

- `WAKE`: drive `PositionManager.executeDecreaseOrder` with `_account` = attacker contract whose
  `fallback()` reenters to open a short while `ShortsTracker.globalShortAveragePrices` lags
  `globalShortSizes`; assert **PRICE-01** (`getAum` stable) and **PRICE-02** (coupling) — the test
  must fail on vulnerable code and pass after the fix.
- `MED` optimization mode: objective = maximize `GlpManager.getAum()` / GLP price across random
  sequences; any sequence that inflates price beyond real flows is a PRICE-04/SOLV-07 violation.

---

## 11. Tooling map & run commands

```bash
# Foundry invariant smoke (handlers under test/invariant/)
forge test --mt invariant_ -vvv
# Medusa deep + optimization
medusa fuzz --config medusa.json
# Echidna targeted (fork mode for live state)
echidna . --contract GmxInvariants --config echidna.yaml
# Halmos proofs on arithmetic invariants (POS-03, FEE-01/02, LIQ-05, PRICE-05)
halmos --function check_
# Wake scenario regression (EXEC-01, PRICE-01/02)
wake test tests/test_reentrancy_2025.py
# crytic/properties seeds (GM/GLP vault + fixed-point)
#   import tools_poc/properties/contracts/ERC4626 and ABDKMath64x64
```

## 12. Build plan (handler harness)

```
tools_poc/gmx-invariants/
  v1/
    handlers/VaultHandler.sol        # LP/Trader/Keeper/Liquidator actions + ghosts
    invariants/Solvency.t.sol        # SOLV-01..07 (FND)
    invariants/Pricing.t.sol         # PRICE-01..05
    invariants/Position.t.sol        # POS, LIQ, FEE
    medusa.json  echidna.yaml
    scenarios/test_reentrancy_2025.py  # WAKE regression (§10)
  v2/
    handlers/MarketHandler.sol       # deposit/withdraw/order/adl actors
    invariants/*.t.sol               # mirror, on MarketUtils hooks
    halmos/*.t.sol                   # POS-03, FEE-01/02 proofs
```
Order of implementation: **handler + ghosts → SOLV → PRICE (+§10 Wake) → POS/LIQ → FEE → ORAC/EXEC → AC/XMOD.**
Start on V1 (smaller, the hack target); replicate the structure for V2 on `MarketUtils` hooks.
