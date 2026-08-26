# LANE-280 — adopt the hardware-capable keystore line

Ticket: https://github.com/DIG-Network/dig-app/issues/280
Epic: https://github.com/DIG-Network/dig_ecosystem/issues/1502

## Blocker (cleared, verified from index.crates.io 2026-08-26)

- `dig-session` **0.9.0** — declares `dig-keystore ^0.13`
- `dig-account` **0.26.0** — declares `dig-session ^0.9` + `dig-keystore ^0.13`
- `dig-keystore` latest **0.13.0**; `dig-keystore-hardware` latest **0.2.0** (on `dig-keystore ^0.13.0`)

Note: #280's body says "0.12"; the published line is now **0.13**.

## Plan

1. Move `dig-keystore` / `dig-session` / `dig-account` onto the 0.13 / 0.9 / 0.26 line TOGETHER.
2. Confirm from the resolved `Cargo.lock` that exactly ONE line of each survives.
3. Audit dig-app call sites against the two guards that changed direction across the range
   (three-valued existence read; `write_new` replacing an `exists`-then-`write` TOCTOU).
4. §2.4b sweep, bounded at the `chia-wallet-sdk` 0.36 ceiling.

## Status

- [ ] dep move
- [ ] lock single-line proof
- [ ] guard audit
