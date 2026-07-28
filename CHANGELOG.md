# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [3.0.0] - 2026-07-28

### Features
- **agent:** Dig-app agent core + cross-platform tray shell (U3, epic #908) (#2)- **keystore:** DIG identity key mgmt — sign/unlock + DIGOP1 sealing + OS-store primary (#3)- **profiles:** Multi-DID profile management with per-profile sealed AppData (U5) (#4)- **dig-app:** Per-user autostart — macOS LaunchAgent + Linux systemd user unit (#908) (#8)- **dig-app:** U6 IPC session client — handshake, attach, sign-callback, re-attach (#908) (#6)- **dig-app:** U6 cross-session profile persistence + F-1/F-3 hardening (#908) (#10)- **dig-app:** U7 dign CLI + gateway routing (local vs engine-proxy) (#908) (#9)- **dig-app:** Integrate dig-logging — dual-sink + op-level log discipline (#934) (#12)- **dig-app:** Per-profile wallet host — chip35 spend build + local sign (#948) (#11)- **dig-app:** APP-SIGN ws:9779 transport + pairing + auth-HMAC (SIGN-1, #950) (#14)- **dig-app:** APP-SIGN connect-whitelist + sign policy + tx-decode (SIGN-2, #950) (#15)- **dig-app:** Per-OS NativeConfirmer — Win Hello / macOS Touch ID / Linux polkit (SIGN-3, #950) (#16)- **dig-app:** Wire APP-SIGN loopback server + native confirmer + sealed persistence (#958) (#18)- **dig-app:** Wire wallet receive-addresses + send-history into APP-SIGN connect (#961) (#20)- **dig-app:** Plain-language spend summary in the confirm dialog (WSEC-B, #964) (#19)- **dig-app:** Session-lock lifecycle — idle + OS-lock + lock-now + tiered re-auth (WSEC-D, #965) (#21)- **dig-app:** Wire session-lock into the tray + sign-path re-auth gate (#967) (#22)- **dig-app:** Onboarding gate (wallet→profile) + configurable default profile (#986 SG-0) (#24)- **session:** Consume dig-ipc-protocol client session half (#1081) (#25)- **events:** Event-driven wallet UI seam + native notifications (#1008, #970) (#26)- Migrate IPC session signing to BLS G1/G2 identity key (#1211) (#27)- **keystore:** Consume canonical dig-constants + dedup dig-identity (#1024 Phase 2, WS1+WS2) (#29)- **custody:** Adopt published dig-account 0.1.0 as the harness custody crate (#1509) (#31)- Custody SWITCHOVER — dig-account is the live custody path, retire old keystore (#1530) (#32)- **engine:** Connect to a real dig-node over loopback JSON-RPC, retiring NullConnector

### Bug Fixes
- **dig-app:** Domain-separate + confirm-gate dign sign (close identity-key oracle #959) (#17)

### Refactor
- **dig-app:** Extract one shared crash-safe durable-write helper (F-4, #908) (#7)- **dig-app:** Re-unlock only the signing profile on sign re-auth (#973) (#23)

### Documentation
- **spec:** Dig-app identity-hub architecture SPEC + gated apps-repo scaffold (U1, epic #908) (#1)- **dig-app:** Concrete dig-app↔engine IPC session contract (SPEC §5.3, epic #908) (#5)- **dig-app:** APP-SIGN paired-loopback signing + dapp-connect contract (SPEC §5.6, #950) (#13)

### Build
- **deps:** Bump dig-wallet-backend 0.6→0.12 + absorb client-seam breaking deltas (#1024) (#30)

### CI
- **nightly:** Install GTK/libxdo system deps in nightly test-gate (#28)

### Chores
- Initial commit — dig-app scaffold (the DIG user app / identity hub, epic #908)


