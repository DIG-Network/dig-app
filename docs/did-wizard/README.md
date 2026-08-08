# The DID wizard

Every screen of the first-run DID wizard, in both themes. Light is the default; dark is the persisted
opt-in.

The wizard opens from the DIG menu's **Set up** row, and — since dig_ecosystem#2359 — **when the app
starts and this computer has an account with no minted DID, on a build that can actually mint one**.
This build cannot (it has no chain transport), so the start-up opening does not happen here; `SPEC.md`
§3.1b states the same condition. It is one journey read as a sequence: the
funding claim, the offer that spends, a wait, then exactly one of five endings.

| screen | light | dark |
|---|---|---|
| Fund the wallet (QR + address) | [did-fund-light.png](did-fund-light.png) | [did-fund-dark.png](did-fund-dark.png) |
| The mint offer — spends real XCH | [did-offer-light.png](did-offer-light.png) | [did-offer-dark.png](did-offer-dark.png) |
| Waiting for the chain | [did-waiting-light.png](did-waiting-light.png) | [did-waiting-dark.png](did-waiting-dark.png) |
| Waiting, connection lost | [did-waiting-offline-light.png](did-waiting-offline-light.png) | [did-waiting-offline-dark.png](did-waiting-offline-dark.png) |
| Confirmed — the DID exists | [did-confirmed-light.png](did-confirmed-light.png) | [did-confirmed-dark.png](did-confirmed-dark.png) |
| Rejected by the chain | [did-rejected-light.png](did-rejected-light.png) | [did-rejected-dark.png](did-rejected-dark.png) |
| Still pending when the watch ended | [did-pending-light.png](did-pending-light.png) | [did-pending-dark.png](did-pending-dark.png) |
| The chain could not be reached | [did-offline-light.png](did-offline-light.png) | [did-offline-dark.png](did-offline-dark.png) |

## The state with no picture

The second startup state — **an account that already holds a DID** — draws nothing at all, and a
photograph of nothing is not evidence of anything. What proves it is
`the_startup_wizard_opens_only_for_an_enrolled_account_that_can_still_mint`
(`crates/dig-app-core/src/account/journey.rs`), which drives the whole cross-product of account state
and mint availability and asserts `NotNeeded` for all four of the cases that must draw no window.

## Regenerating

```
DIG_WIZARD_SHOTS=docs/did-wizard cargo test -p dig-app-core --lib -- --ignored --nocapture did_wizard_gallery
```

Every screen is built by the journey's own builder (`funding_claim`, `mint_offer`, `waiting_screen`,
`mint_report`), so these are pictures of the product rather than of copy re-typed for a gallery.

**Do not photograph these with a screenshot tool.** A GDI screen capture cannot see a hardware GL
surface: it returns the desktop behind the window, and a perfectly-painted window photographs as blank
(dig_ecosystem#2038). The harness reads the real window's framebuffer back with
`egui::ViewportCommand::Screenshot`, at a pinned 2× scale, so the files are the same picture on every
machine.
