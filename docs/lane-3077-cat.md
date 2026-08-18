# Lane: dig_ecosystem#3077 slices C2+C3 — the CAT slice of the dig-app wallet

C2: widen `Asset` in `crates/dig-app-core/src/wallet/state.rs` from `{Xch, Dig}` to
`{Xch, Cat(AssetId)}` with `Asset::DIG` an associated const, matching the wire shape in
`dig-node-control-interface` 0.17.0. Multi-asset balance/coins/history + a multi-asset
`BalanceReading` list on the wallet overview.

C3: send scoped to a selected CAT, via `dig_account::MoneyWallet::build_cat_transfer`,
which is already generic over `asset_id`.

This file is removed before the PR is marked ready.
