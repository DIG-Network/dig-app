# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.23.0] - 2026-08-28

### Features
- **collateral:** Declare the epoch collateral requirement + safety margin control methods (#33)

## [0.22.0] - 2026-08-27

### Features
- **spends:** Declare control.spends.list, the sanctioned reader for the spend audit record (#31)

## [0.21.0] - 2026-08-25

### Features
- **wallet:** Move the reservation codes off -32044, which dig-node already owns (#28)

## [0.20.0] - 2026-08-25

### Features
- **wallet:** Declare control.wallet.reservations.* for cross-process coin reservation (#25)

## [0.19.0] - 2026-08-23

### Features
- Declare control.capsule.fetch for operator-triggered P2P pulls (#23)

## [0.18.0] - 2026-08-19

### Features
- Declare control.chiaPeers.add/list/remove for trusted Chia peers (#18)

## [0.17.0] - 2026-08-17

### Features
- **params:** Widen wire Asset to name an arbitrary CAT by asset id (#17)

## [0.16.0] - 2026-08-16

### Features
- Declare control.profile.putBody/getBody + subscribe kind (#16)

## [0.15.0] - 2026-08-13

### Features
- Declare control.wallet.watch/unwatch/watched (wallet enrolment) (#15)

## [0.14.0] - 2026-08-12

### Features
- Add subscription_peer_count + chia_peer_peak_height to WalletSyncStatusResult (#14)

## [0.13.0] - 2026-08-11

### Features
- Carry the PEX-known DIG peer count, not just the connected one (#10)

## [0.12.0] - 2026-08-11

### Features
- **wallet:** Seal-regression doctest, bounded token rendering, and a compiler-checked settled rule (#13)

## [0.11.0] - 2026-08-11

### Features
- **wallet:** Forward-compatible WalletSyncPhase + enrolled/locked + watched_addresses (#12)

## [0.10.0] - 2026-08-10

### Features
- **wallet:** Declare control.wallet.coinSpend and control.wallet.coinsByParent (#11)

## [0.9.0] - 2026-08-10

### Features
- Publish the control.wallet.arrivals contract (#9)

## [0.8.0] - 2026-08-09

### Features
- **wallet:** Declare control.wallet.syncStatus, the wallet chain-sync view (#8)

## [0.7.0] - 2026-08-09

### Features
- **wallet:** Read one coin by coin id (control.wallet.coinById) (#7)

## [0.6.0] - 2026-08-08

### Features
- **control:** Wallet coin read, peak height and signed-bundle push (#6)

## [0.5.0] - 2026-08-06

### Features
- **results:** Disclose which tier answered a wallet balance read (#5)

## [0.4.0] - 2026-08-06

### Features
- **control:** PeerSoftware type and an always-present software field on peerStatus (#4)

## [0.3.0] - 2026-08-02

### Features
- **control:** Add control.wallet.balance read method to the contract (#3)

## [0.2.0] - 2026-07-19

### Features
- **control:** The canonical control-method catalog (#1147) (#1)

## [0.1.0] - 2026-07-19

### Chores
- Provision dig-node-control-interface contract crate skeleton


