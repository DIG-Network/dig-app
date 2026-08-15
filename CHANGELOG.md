# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [12.2.0] - 2026-08-15

### Features
- **app:** Express funding-elsewhere so the profiles card can offer creation honestly (#173)

## [12.1.0] - 2026-08-15

### Features
- **wallet:** Redesign the Wallet tab — balance first, real actions, asset rows, activity (#174)

## [12.0.0] - 2026-08-15

### Features
- **session:** 24h idle lock policy, deposit re-raise cap, single XCH renderer (#172)

## [11.2.0] - 2026-08-15

### Features
- **app:** Raise the zero-profile fund-and-create prompt on a daily cadence (#171)

## [11.1.0] - 2026-08-14

### Features
- **app:** Wire the profile-mint transport in the binary (S1 of #2398) (#170)

### Bug Fixes
- **chain:** An ABSENCE may be believed only from a synced tier (#169)

## [11.0.0] - 2026-08-14

### Features
- **wallet:** Send XCH end to end — build, sign locally, push via the node, confirm on chain (#167)

## [10.10.0] - 2026-08-14

### Features
- **wallet:** Show the last-synced balance with its as-of provenance and a syncing indicator (#163)

## [10.9.0] - 2026-08-13

### Features
- **wallet:** Enrol account keys with the node and name the real balance reason (#164)

## [10.8.0] - 2026-08-13

### Features
- **network:** State how far the chain replica is behind its peers (#162)

## [10.7.0] - 2026-08-12

### Features
- **app:** Show the Chia light client — peers held and the peak they announced (#161)

## [10.6.0] - 2026-08-11

### Features
- **chain:** ChainSource and SpendPublisher over the dig-node control plane (#153)- **profile:** Profile-mint seams, journalled mint door and liveness (gate closed) (#155)- **profile:** Open the profile creation gate on a real lineage walk (#157)- **chain:** Poll node chain readiness off the painting thread (#159)- **profiles:** An unmeasured node is Unknown, and the readiness probe measures what it credits

### Bug Fixes
- **did:** Never offer a spend this build cannot make, nor a menu route that does not exist (#152)- **control:** Require a loopback address before sending the node control token (#154)- **chain:** Tighten the push refusal taxonomy and the coins read's asset check (#156)

### Documentation
- **spec:** SPEC 3.1d now matches the served lineage walk (#158)

## [10.1.1] - 2026-08-10

### Features
- **window:** Native controls, a sync badge, and selectable text (#150)

### Bug Fixes
- **did:** Stop the tray explainer promising a cost screen that does not exist (#149)

### Chores
- **deps:** Migrate to chia 0.36 line and dig-account 0.10 (#151)

## [10.0.0] - 2026-08-10

### Features
- Notify on wallet arrivals by consuming the node's arrival cursor (#148)

## [9.2.1] - 2026-08-10

### Bug Fixes
- **build:** Compile the headless dig-app shell and gate it in CI (#146)

## [9.2.0] - 2026-08-10

### Features
- **profiles:** The dig-profile system — list, hide, and a settable active slot (#145)

## [9.1.1] - 2026-08-09

### Bug Fixes
- **window:** Wire the content list and Sharing cards to the node readings #2330 delivered (#143)

### Testing
- **hosted-stores:** Enumerate the reasons from the compiler, not a second array (#144)

## [9.0.0] - 2026-08-09

### Features
- **wallet:** Read coins and push signed bundles through the node, and close the mint-gate findings (#142)

## [8.0.0] - 2026-08-08

### Features
- **window:** Carry the node's real facts into TrayView and the pane layer (#135)- **window:** The product register, a cache chooser, one pane header, one state vocabulary (#137)- **window:** Five semantic tabs, one account narrative, and a window-wide status strip (#138)- **custody:** Adopt dig-account 0.5.0 — a real gate replaces the always-approve authorizer (#139)- **account:** The DID wizard opens at startup when no DID is minted (#141)

### Bug Fixes
- **custody:** A lock revokes the money signer it already handed out (#140)

### Documentation
- **gallery:** The complete app gallery, and a capture that cannot lie (#136)

## [5.41.0] - 2026-08-08

### Features
- **confirm:** Watch the app window for a wedged frame loop, and restore three vacuous drag guards (#119)- **settings:** Add a Settings tab with an auto-update group (#120)- **window:** A content-pane design system, with Status as its reference implementation (#124)- **window:** The Apps and Settings content panes (#127)- **window:** Account and Security content panes (#129)- **window:** Wallet and Cache content panes (#2326 Phase 2) (#128)- **account:** First-run DID wizard — DID-existence gate, QR fund step, confirmation wait (#130)- **window:** The DIG mark, a gallery-openable tab, and an honest account note (#134)

### Bug Fixes
- **confirm:** Require an affirmative gesture begun after the surface could be read (#118)- **wallet:** Render $DIG at its real 3 CAT decimals, not XCH's 12 (#121)- **window:** Wrap the narrow tab strip instead of dropping the tabs that do not fit (#122)- **wallet:** A balance read that runs out of time is not a missing node (#123)

## [5.31.0] - 2026-08-07

### Features
- **window:** Model the tabbed app window from the shared menu rules (#113)- **window:** The tabbed app window, the tray row that opens it, and the four-row trim (#115)- **window:** Draw every prompt inside the app window (#2270) (#117)

### Refactor
- **tray:** Share the menu group builders and add a window-host capability field (#112)

### Documentation
- **window:** Resolve the four rustdoc links that broke the doc gate (#116)

## [5.27.0] - 2026-08-06

### Features
- **account:** Pin wallet operations to the sole active derivation index (#111)

## [5.26.0] - 2026-08-06

### Features
- **wallet:** Read the real balance from the node instead of asserting it is unknowable (#109)

### Documentation
- **tray:** Unlink seven references to items that are private on Windows (#110)

## [5.25.0] - 2026-08-05

### Bug Fixes
- **shell:** Declare DPI in a manifest, and make a stranded pump phase unrepresentable (#94)- **tray:** Give the tick its own thread, and delete the mitigation it needed (#97)- **confirm:** Hold the consent-surface guard across the biometric prompt (#103)- **tray:** Refuse to track a popup Windows will not let us dismiss (#107)

## [5.23.0] - 2026-08-05

### Features
- **tray:** Watch the tray event loop, so a stall names itself (#88)

### Bug Fixes
- **tray:** Claim the foreground on the edge that matters, and make the breaker actually reach the window (#89)

## [5.21.0] - 2026-08-04

### Bug Fixes
- **account:** The account survives a restart (#85)

## [5.20.0] - 2026-08-04

### Features
- **confirm:** Prompt windows are draggable by their header (#81)

### Bug Fixes
- **logging:** A per-user run no longer goes silently blind, and a rebuilt menu no longer eats clicks (#83)

## [5.18.0] - 2026-08-04

### Features
- **tray:** Add an Apps menu group with Chat launching dig-chat (#2101)

### Testing
- **account:** Guard refusal_is_default at the 3 custody-critical claim sites (#2098)

## [5.17.0] - 2026-08-04

### Features
- **identity:** Identity.* capability class (attest/seal/unseal) for dig-chat (#57)- **account:** First-run import choice + recovery-phrase backup ceremony (#1564)- **2fa:** Persistent, escalating bound on the challenge window (#1847)- **account:** Auto-clear the recovery phrase from the clipboard after a timeout (#1964)- **dig-app:** Configurable node cache cap in the tray (#2002)- **tray:** The Wallet submenu reports the balance, or why it cannot (#73)- **dig-app:** Branded egui prompt GUI replacing the native OS dialogs (#69)- **confirm:** Render identifiers in Space Mono in the branded prompt window (#2060)- **account:** Native save picker + owner-only ACL for the recovery phrase (#72)- **confirm:** Restore the frameless InputStyle::Bar launcher chrome (#2054)

### Bug Fixes
- **2fa:** Show the challenge throttle wait before prompting for a code (#1970)- **wallet:** An unlocked account with a failed address derivation no longer says "unlock" (#2059)- **confirm:** One prompt can no longer cost every later one (#78)

### Refactor
- **account:** Single-source the at-rest seal-write across the two vaults (#1982)

### Documentation
- **account:** Coherence sweep to the master-HD / separated-keystore model (#1571)- **dig-app-core:** Make cargo doc warning-clean (#2005)- **2fa:** Record the evaluated-and-rejected monotonic/trusted-time throttle decision (#1969)

### Testing
- **gateway:** Pin control.* two-transport conformance to the shared contract crate (#2019)- **recovery:** Make the bad-checksum recovery-phrase test deterministic (#2062)- **confirm:** Pin the many-output sign window against action-row overflow (#2063)

### CI
- **dig-app:** Gate cargo doc on -D warnings + fix the doc-link stragglers (#2012)- **dig-app:** Make the doc gate robust to rustc drift + fix the dign private-doc-link (#2056)

### Chores
- **dig-app:** Zeroize clipboard read-back, gate dead-code, fix doc links (#1978)- **dig-app:** Collapse hard-coded space runs in tray notice bodies (#1973)

## [5.5.0] - 2026-08-01

### Bug Fixes
- **tray:** Run menu actions off the event loop so custody actions stop deadlocking (#55)

## [5.4.0] - 2026-07-31

### Features
- **app:** Refuse a second instance so a duplicate launch is a no-op (#54)

## [5.3.0] - 2026-07-30

### Features
- **confirm:** Draw every Windows consent window ourselves, with labelled buttons (#42)- **tray:** The five named top-level options (#44)- **tray:** A Wallet submenu on the spine (#45)- **hotkey:** Alt+Space opens a floating URN bar from any application (#46)- **security:** Set up two-factor codes from the tray, with a real enrolment window (#48)- **account:** An account exists only when the user asks, and unlocking requires their password (#47)- **wallet:** A real receive address, and a balance that never lies about being unknown (#52)- **2fa:** Show a scannable QR code during two-factor enrolment (#51)- **pairing:** Third-party apps pair with a code, and the user can see and revoke them (#50)

### Bug Fixes
- **confirm:** One layout walk, and buttons sized to their labels (#43)- **confirm:** Show the WHOLE recovery phrase — 16 of 24 words were invisible (#49)- **confirm:** A body that does not fit now SCROLLS — the phrase still clipped on most displays (#53)

## [4.2.0] - 2026-07-29

### Features
- **confirm:** Scale the input window to the monitor's real DPI (#41)

## [4.1.0] - 2026-07-29

### Features
- **tray:** Add an Open action that asks for a DIG link and opens it via the node (#40)

## [4.0.0] - 2026-07-29

### Features
- **tray:** Make the tray a real tray application (#39)

## [3.5.0] - 2026-07-29

### Bug Fixes
- **tray:** Present notices as notices, not warnings with a meaningless Cancel (#38)

## [3.4.0] - 2026-07-29

### Features
- **tray:** Make every tray entry do what it names, add --version, survive a missing Linux indicator (#37)

## [3.3.0] - 2026-07-28

### Features
- **tray:** Show the DIG mark instead of a solid-colour placeholder

## [3.2.0] - 2026-07-28

### Features
- **tray:** Account, recovery phrase and DID surfaces in the tray menu

### Bug Fixes
- **linux:** Drop the unused libxdo dep and ship a headless binary

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


