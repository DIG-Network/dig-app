//! The tray menu **model** — what the user can do, as data (dig_ecosystem#1800).
//!
//! # Why the menu is a model and not just code in the shell
//!
//! Rules about which items appear, which are enabled, and what each one says cannot be tested from
//! inside a platform event loop. So the shell ([`dig-app`'s `tray` module](../../dig_app/index.html))
//! asks [`build`] for a [`MenuModel`] and does nothing but render it and dispatch the [`TrayAction`]s
//! back. Every rule below is unit-tested here.
//!
//! # The three craft rules this module enforces (§6.1 `professional-ui`)
//!
//! **1. A menu item is an ACTION. State is not a menu item.**
//!
//! The tray used to open with five greyed rows — the running line, the node line, the account line, the
//! DIG ID and the on-chain DID — because they were convenient places to print text. A disabled item
//! means *"something you cannot do right now"*, so using five of them as labels taught every new user
//! that the app was broken before they read a word. It also forced absurdities: one status row had to be
//! truncated to 72 characters because a real node diagnosis ran to ~700, and a "Node details…" row was
//! itself greyed out whenever there was nothing to expand.
//!
//! State now lives in the three places a tray application has for it, and the menu holds actions only:
//!
//! | What the user needs to know | Where it lives now |
//! |---|---|
//! | Am I connected / locked / set up? | the tray ICON — [`status`] picks a [`TrayGlyph`] |
//! | The one-line summary | the tray TOOLTIP — [`TrayStatus::tooltip`] |
//! | Everything, in full, untruncated | the `Status and details…` window — [`details_text`] |
//!
//! **2. Never trap the user.** Every state offers a way forward AND a way out. `Quit DIG`, the log
//! folder and `Status and details…` are always clickable, and — the defect this module was rewritten
//! for — **account management is reachable at all times**: creating, replacing, restoring and removing
//! an account are offered whenever the host can hold one, never gated on the account being absent.
//!
//! **3. A row that IS legitimately disabled says why in its own label.** Five rows are disabled across
//! the account states — `Set up my DIG Account (not supported on this system yet)` on a host with no
//! per-application credential store, plus `Show my recovery phrase (…)` and `Copy my receive address (…)`
//! in each of the two states that withhold key material, every one naming what stands in the way (an
//! unlock, or a password that has never been set). Each sits beside an ENABLED remedy (the management
//! submenu; the `Unlock…` or `Set a password…` row), so none is a dead end. That set is
//! asserted by the `the_disabled_rows_are_exactly_the_ones_that_name_their_reason` test, because "rare" is the
//! kind of claim that drifts silently — an earlier revision of this comment said "exactly one" while the
//! model rendered two.
//!
//! # Destroying custody is deliberately awkward
//!
//! [`TrayAction::ReplaceWithNewAccount`], [`TrayAction::ReplaceFromPhrase`] and
//! [`TrayAction::RemoveAccount`] destroy master key material. They are always REACHABLE — a user who
//! wants a different account must not have to edit files — but they live in the
//! `Manage my DIG Account…` submenu rather than the top level, they say "Replace"/"Remove" in their own
//! labels, and the shell routes each through the biometric authorization seam
//! ([`confirm_destroy`](crate::confirm::NativeConfirmer::confirm_destroy)), never through a notice or a
//! claim. See [`crate::account::journey::replace_account`].

use std::fmt;

use crate::account::did::{Allowance, Capability};

/// The widest the tray TOOLTIP may be, in characters.
///
/// The Windows notification area truncates `NOTIFYICONDATA::szTip` at 128 UTF-16 units and simply drops
/// the rest, so a tooltip built from the engine's disconnected reason (~700 characters in the field)
/// would be cut at an arbitrary point with no indication anything was missing. Bounding it here makes
/// the cut deliberate and appends an ellipsis, and [`details_text`] holds the untruncated text one click
/// away.
///
/// 120 leaves room inside the 128-unit budget for the ellipsis and for a multi-byte character sitting on
/// the boundary.
pub const MAX_TOOLTIP_CHARS: usize = 120;

/// Where the account is, as far as the user is concerned. This is the four-state async surface for the
/// account: not-possible-here, none-yet, locked, and live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountState {
    /// This host cannot hold an account yet — no per-application credential store (today: Linux). The
    /// user is told why rather than shown a button that silently does nothing.
    Unsupported,
    /// No account exists yet. The first-run path is open.
    Absent,
    /// An account exists but is locked, so nothing can be signed or revealed until it unlocks.
    Locked,
    /// An account exists at rest but **cannot be opened at all** — its sealed seed will not unlock.
    ///
    /// # Why this is its own state and not "locked"
    ///
    /// A locked account has a way back in: `Unlock…`. An unopenable one does not, so reporting it as locked
    /// offers a button that will always fail and says nothing about why. The tray must name the situation and
    /// route the user to the only remedy there is — replacing the account (dig_ecosystem#1799 review).
    ///
    /// The live cause is a **legacy raw-seed blob**. dig-app USED to auto-enrol `account.default` at first
    /// boot on every Windows/macOS host, and those blobs carry the old `DIGVK1` shape. That auto-enrolment
    /// is long gone — an account now exists only because a user asked (dig_ecosystem#1820), and no boot
    /// path creates one — but the blobs it left behind are still in the field, which is why this state has
    /// work to do. Under `dig-account` 0.3 they neither unlock (`SessionError::LegacySeedFormat`) nor
    /// re-enrol at the same id (`AlreadyExists`) — they are WEDGED, not merely fail-closed. Before this
    /// state existed the boot swallowed that into a `tracing::warn!` and returned `None`, so the tray
    /// reported a locked account and the user silently lost signing with no in-app route out.
    ///
    /// **Reaching this state requires an unlock ATTEMPT that hit an unreadable seal** — never the mere
    /// absence of a session (`SPEC.md` §3.1c, dig_ecosystem#2128). The app boots locked and tries nothing,
    /// so "no session" is the ordinary state of every fresh process; reading it as a failure reported every
    /// launch as an unreadable account and pointed its owner at the destructive remedy.
    Unopenable,
    /// An account exists, but it is still sealed under a password the MACHINE generated and kept in the
    /// OS credential store — so opening it requires nothing its owner knows (dig_ecosystem#1817).
    ///
    /// # Why this is its own state
    ///
    /// It is not `Locked`: `Unlock…` here would ask for a password the user has never chosen and does not
    /// have. It is not `Unopenable` either — the account opens perfectly well, which is precisely the
    /// problem. The one honest offer is to SET a password, so the state that produces that offer has to
    /// exist. The account keeps its identity, address and data through the change
    /// ([`migration`](crate::account::migration)); only the lock on it changes.
    NeedsPassword,
    /// An account is live.
    Unlocked {
        /// Whether a recovery phrase is stored for it. `false` = enrolled before recovery phrases
        /// existed, so **it cannot be recovered from words** and the menu says so.
        recoverable: bool,
    },
}

impl AccountState {
    /// Whether an account exists on this host at all (locked or live).
    ///
    /// This is the fact the management verbs branch on: with an account present they REPLACE, and
    /// without one they CREATE. It deliberately does not care whether the account is unlocked — a locked
    /// account is still custody that a replace would destroy.
    fn exists(&self) -> bool {
        matches!(
            self,
            Self::Locked | Self::NeedsPassword | Self::Unopenable | Self::Unlocked { .. }
        )
    }

    /// Whether this host can hold an account at all.
    fn supported(&self) -> bool {
        !matches!(self, Self::Unsupported)
    }
}

/// Why an UNLOCKED account still reported no receive address.
///
/// Distinguished from "no address yet" because the remedy differs and, in both cases, "unlock your
/// account" is a remedy the user has already performed — advice that names a step already taken is
/// worse than none. Carried on [`TrayView::address_fault`] and mapped to the sentence a person reads
/// by [`crate::wallet::overview::WalletOverview::of_tray`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFault {
    /// The account was unlocked and the derivation itself failed — a genuine defect
    /// (dig_ecosystem#2059).
    DerivationFailed,
    /// The account was unlocked, but its wallet derives at a different profile than the one now
    /// active, so the only address available belongs to the profile the user just left
    /// (dig_ecosystem#2496). Nothing is broken; the wallet simply cannot move until the account is
    /// re-opened.
    WalletBehindActiveProfile,
}

/// Everything the tray is rendered from — one snapshot, read once per repaint.
#[derive(Debug, Clone, Default)]
pub struct TrayView {
    /// Whether a profile can be EDITED here, and when it cannot, which piece is missing.
    ///
    /// A reading rather than a boolean, for `profile_creation`'s reason: an unmeasured capability
    /// and a measured blocker are different facts, and drawing the first as the second names a
    /// cause nobody observed (dig_ecosystem#2993).
    pub profile_editing: crate::profile_edit::ProfileEditing,
    /// Whether the agent loop is running.
    pub running: bool,
    /// Whether the agent is talking to a node right now.
    ///
    /// Read from the engine's own state rather than sniffed out of [`node`](Self::node), so the icon and
    /// the tooltip cannot disagree with the engine because a summary's wording changed.
    pub node_connected: bool,
    /// The node connection line, already summarized by the engine (connected + detail, or the
    /// actionable reason it is not).
    pub node: String,
    /// The account's user-visible state.
    pub account: Option<AccountState>,
    /// The root profile's stable id (the hex identity public key until the on-chain DID mint lands).
    pub profile_id: Option<String>,
    /// The account's `xch1…` receive address, derived from its MONEY key, or `None` when there is no
    /// unlocked account to derive one from (dig_ecosystem#1850).
    ///
    /// Deliberately a separate field from [`profile_id`](Self::profile_id) rather than a reuse of it: the
    /// two are different keys, and the reason the Wallet menu carried no address row until now was that
    /// only the identity key was on hand. A `Copy my receive address` wired to that would hand out a
    /// string that receives nothing.
    pub receive_address: Option<String>,
    /// Why the SAME observation that produced [`receive_address`](Self::receive_address) found the
    /// residency unlocked and STILL reported no address, or `None` when that is not what happened
    /// (dig_ecosystem#2059, #2496).
    ///
    /// Only meaningful when `receive_address` is `None`: it is what tells
    /// `wallet::overview::WalletOverview::of_tray` apart the reasons a `None` can mean — an account
    /// that is simply not unlocked (say "unlock it"), versus one that WAS unlocked at the moment of
    /// observation and still produced nothing, where saying "unlock it" would name a remedy the user
    /// already performed. The shell fills both fields from a single call to
    /// `AccountResidency::observe_receiving_address` so the two facts describe the SAME instant —
    /// reading unlock-state and the address as two separate calls lets an idle relock or `Lock now` land
    /// between them and misreport an ordinary lock as a fault.
    ///
    /// An enum rather than a flag per cause: the faults are alternatives, and two booleans would make
    /// "derivation failed AND the wallet is behind" expressible when it is not a state the residency
    /// can report.
    pub address_fault: Option<AddressFault>,
    /// The account's balance as the node last reported it, or why it is not known
    /// (dig_ecosystem#2206).
    ///
    /// Polled on its own cadence by [`crate::wallet::node::NodeBalance`] rather than read while the
    /// menu is built: a snapshot is taken on every repaint, and a chain read is a rate-limited
    /// network round trip.
    ///
    /// The default — [`BalanceUnknown::NoNode`](crate::wallet::overview::BalanceUnknown::NoNode) —
    /// is the truth before the first poll: at that point nothing has answered. It is deliberately
    /// NOT a zero; see [`crate::wallet::overview`] for why those are different types.
    pub balance: crate::wallet::overview::BalanceReading,
    /// The profile's **minted on-chain** `did:chia:` DID, or `None` when it has none.
    ///
    /// This must be set from evidence that a DID was actually minted on chain — never from a local
    /// profile reference that merely has DID-shaped text in it. Since minting is unimplemented, the
    /// honest value is always `None` (see the
    /// `never_claims_an_on_chain_did_from_a_local_profile_reference` test).
    pub did: Option<String>,
    /// Whether a second factor (an authenticator code) is enrolled for this account
    /// (dig_ecosystem#1840).
    ///
    /// Decides which of the two Security rows is offered — "Set up…" or "Turn off…" — so the row always
    /// names what clicking it will actually do. Read fresh on each repaint from
    /// [`enrolment_present`](crate::account::second_factor::vault::enrolment_present), which needs no
    /// unlock — so the menu flips the moment an enrolment completes AND still tells the truth about a
    /// locked account.
    pub second_factor: bool,
    /// What became of the global shortcut that opens the URN bar (dig_ecosystem#1839).
    ///
    /// `None` before the shell has attempted registration, which is why it is not simply a
    /// [`HotkeyState`](crate::hotkey::HotkeyState): "not tried yet" and "tried and refused" are different
    /// facts, and only the second is worth telling the user about.
    pub hotkey: Option<crate::hotkey::HotkeyState>,
    /// Whether the last tray click had its menu refused because Windows would not bring DIG
    /// forward (dig-app#86).
    ///
    /// Carried in the view rather than read from its atomic at paint time so that a flip actually
    /// REPAINTS: the renderer only redraws when the view changes, so a fact the view does not carry
    /// is a fact the user never sees change.
    pub menu_suppressed: bool,
    /// The node's content-cache cap + usage, or `None` when no node is connected to report it
    /// (dig_ecosystem#2002).
    ///
    /// Filled from the node's `control.status` snapshot, so the tray shows the node's real numbers.
    /// `None` is the honest value when the node is unreachable — the cache submenu then says the cap
    /// cannot be changed until a node is connected rather than inventing a figure.
    pub cache: Option<crate::cache::CacheSnapshot>,
    /// Whether this host can open the app window at all (dig_ecosystem#2253).
    ///
    /// `Unavailable` is what keeps every verb on the tray once a window-hosted surface exists: while
    /// no window can be opened, the tray remains the ONLY route to the 25 actions a future trim would
    /// otherwise move off it. Filled by the shell from a RUNTIME capability check
    /// (`confirm::gui::available()` plus the macOS host restriction) rather than the target triple,
    /// because a headless Linux session with neither `$WAYLAND_DISPLAY` nor `$DISPLAY` set hits the
    /// exact same "no window host" condition macOS does.
    ///
    /// Nothing reads this field yet — it exists so its value is exercised by `cargo test` on every
    /// platform ahead of the trim that will consume it, rather than living behind a `cfg!` that only
    /// one CI runner could ever prove.
    pub window_host: WindowHost,
    /// What the update beacon reports about itself, or `None` when it could not be asked
    /// (dig_ecosystem#2293).
    ///
    /// Filled from `dig-updater status --json` — an UNPRIVILEGED read, so this is honest even for a
    /// user who never grants elevation. `None` is the truthful value on a machine with no beacon
    /// installed, or one whose status could not be parsed; the auto-update group then says the updater
    /// cannot be asked rather than drawing a switch position nobody reported.
    ///
    /// The user's remembered PREFERENCE lives elsewhere ([`crate::auto_update::AutoUpdate`], in
    /// `agent.json`). This field is the observed state, and the observed state is what the surface
    /// shows whenever it exists — see [`crate::auto_update`] for why those are different facts.
    pub update: Option<crate::auto_update::BeaconStatus>,
    /// What the connected node says about ITSELF — version, build, protocol, address, uptime, sync
    /// availability and its three content counts — or `None` when no node answered
    /// (dig_ecosystem#2330).
    ///
    /// The rich data has always existed one layer down, in `EngineState::Connected`'s
    /// [`StatusResult`](dig_node_control_interface::results::StatusResult); the view reduced all of
    /// it to [`node_connected`](Self::node_connected) plus the pre-summarised
    /// [`node`](Self::node) line, so the Status pane had nothing to draw but that sentence.
    ///
    /// It is a DISTILLATION ([`crate::node_facts::NodeFacts`]) rather than the contract type
    /// verbatim, and its uptime is bucketed to the minute before it gets here. Both are repaint
    /// decisions, argued in that module's docs.
    ///
    /// `None` is honest when there is no node: the REASON there is none is already
    /// [`node`](Self::node)'s, which carries the engine's actionable diagnosis.
    pub node_facts: Option<crate::node_facts::NodeFacts>,
    /// The stores this node holds, or why they are not known (dig_ecosystem#2330).
    ///
    /// Polled on its own cadence by [`crate::hosted_stores::NodeHostedStores`] rather than read
    /// while the window is drawn: a snapshot is taken twice a second and this is a node round trip
    /// — the same reason [`balance`](Self::balance) is polled.
    ///
    /// The default — [`HostedStoresReading::Pending`](crate::hosted_stores::HostedStoresReading::Pending)
    /// — is the truth before the first poll: nothing has answered, and nothing has failed either. It
    /// is deliberately NOT an empty list; see [`crate::hosted_stores`] for why an unread list and a
    /// node holding nothing are different types.
    pub hosted_stores: crate::hosted_stores::HostedStoresReading,
    /// Which sibling DIG apps this install can open, or that nobody has been able to look
    /// (dig_ecosystem#2330).
    ///
    /// Presence used to be discovered only inside the click handler
    /// ([`crate::apps::plan_launch`]), so a pane could not draw an accurate "Installed" chip at all
    /// — and a chip that guessed would be the placeholder-that-looks-real this surface must not
    /// have. Carrying it here is what makes the chip drawable from a fact.
    ///
    /// [`AppPresence::Unknown`](crate::apps::AppPresence::Unknown) is the default and means exactly
    /// that nobody looked; see that type for why it is not an empty list.
    pub installed_apps: crate::apps::AppPresence,
    /// This account's dig-profiles, or why they are not known (dig_ecosystem#2403).
    ///
    /// Filled from the app's live [`ProfileSession`](crate::account::profile_session::ProfileSession),
    /// which is the ONE place the active profile is stored — so the list a person picks from and the
    /// index the wallet derives at cannot disagree.
    ///
    /// The default — [`ProfilesReading::Pending`](crate::profiles::ProfilesReading::Pending) — is the
    /// truth before boot has reported, and is deliberately not an empty list. Every real user's
    /// answer today is `Known(vec![])`, because nothing can mint a profile; that is a reading, and
    /// the surface says so in its own words.
    pub profiles: crate::profiles::ProfilesReading,
    /// Whether a profile can be CREATED on this build, and which missing piece stops it.
    ///
    /// Derived by the shell from the same [`MintSeams`](crate::account::chain_mint::MintSeams) value
    /// it hands the start-up wizard, through [`ProfileCreation::of`](crate::profiles::ProfileCreation::of).
    /// That single seam is the point (dig_ecosystem#2377): a second, independent check here is how a
    /// surface comes to advertise a create control whose implementation refuses.
    pub profile_creation: crate::profiles::ProfileCreation,
    /// Whether a profile can be DELETED on this build, and which missing piece stops it
    /// (dig_ecosystem#3037).
    ///
    /// Its own reading rather than `profile_editing` reused: the facts coincide today and the
    /// sentences do not, and a person trying to delete a profile cannot be shown a blocker phrased
    /// about changing one. See [`ProfileDeletion`](crate::profiles::ProfileDeletion).
    pub profile_deletion: crate::profiles::ProfileDeletion,
    /// What the connected node last said about its ability to service a profile mint, or `None`
    /// when nobody has asked it yet (dig_ecosystem#2398).
    ///
    /// Polled on its own cadence by [`NodeChainReadiness`](crate::chain::NodeChainReadiness), for
    /// the reason the balance is: this snapshot is taken twice a second and the reading is two node
    /// round trips.
    ///
    /// It is a READING, not a capability. Nothing gates on it — the one surface that consumes it is
    /// the DID explainer, which needs it in order to stop naming a cause nobody measured. A mint's
    /// availability is read off `ProfileMintSeams`, which needs a door this field cannot hold.
    pub mint_chain: Option<crate::account::profile_mint::ChainReadiness>,
    /// Where this node stands on the DIG and Chia networks (dig_ecosystem#2569).
    ///
    /// Polled on its own cadence by [`NodeNetworkStanding`](crate::network::NodeNetworkStanding), for
    /// the reason the balance is: this snapshot is taken twice a second and the reading is two node
    /// round trips.
    ///
    /// The default — every reading `Pending` — is the truth before the first poll, and is
    /// deliberately not "synced with zero peers". See [`crate::network`].
    pub network: crate::network::NetworkStanding,
    /// Whether the node has this account's addresses enrolled (dig_ecosystem#2848).
    ///
    /// Carried because it is what tells apart the two reasons a caught-up node holds no figure: one
    /// where the addresses were never registered, and one where they were and the node picks them up
    /// at its next start (dig_ecosystem#2826). Without it both render as the third situation
    /// entirely — "still catching up" — which is what a live user saw beside a window reporting the
    /// chain synced.
    pub enrolment: crate::wallet::enrol::Enrolment,
    /// How the send this app is running is going, or that there is none (dig_ecosystem#2819).
    ///
    /// Carried in the view for the reason [`balance`](Self::balance) is: the Wallet pane RENDERS it,
    /// and the window only repaints when the view changes. A send whose progress lived anywhere else
    /// would move from signing to pending to confirmed while the screen kept showing the form.
    ///
    /// The default — [`SendProgress::Idle`](crate::wallet::sending::SendProgress::Idle) — is the truth
    /// on a fresh boot: this app sends nothing it was not asked to. It says nothing about transfers
    /// made in an earlier run, which are the chain's business and not this field's.
    pub send: crate::wallet::sending::SendProgress,
}

impl TrayView {
    /// Whether `other` would render the same tray menu as `self`.
    ///
    /// The shell's tick calls this to decide whether to rebuild and repaint. A field that changes what
    /// the menu shows, but which this says nothing about, freezes the tray on stale rows until some
    /// OTHER field happens to move — and if nothing else moves, forever.
    ///
    /// # Why it destructures instead of listing fields
    ///
    /// This began as a hand-spelled `a.x == b.x && …` chain in the shell binary, and it silently fell
    /// three fields behind [`TrayView`]: `window_host`, `hotkey` and the address fault. The
    /// `window_host` omission was the expensive one — when a window fails to open, `window_host`
    /// degrades to [`WindowHost::Unavailable`] so the tray can re-expand from four rows to the full
    /// menu, and that is the ONLY thing standing between a failed open and a user with no route to
    /// `RemoveAccount`, `FixMissingPhrase` or `OpenLogs`. The degrade fired correctly and the repaint
    /// gate discarded it (dig_ecosystem#2253).
    ///
    /// So the field list is not written down twice. Destructuring binds every field by name, and
    /// `..` is deliberately absent: **adding a field to [`TrayView`] fails to compile here**, which
    /// forces whoever adds it to decide whether it changes what the menu shows. A comparison that
    /// cannot fall behind the struct is worth more than one that is merely correct today.
    pub fn renders_same_as(&self, other: &Self) -> bool {
        // No `..` — see above. Each binding is compared exactly once, in declaration order.
        let Self {
            profile_editing,
            node_connected,
            node,
            account,
            profile_id,
            receive_address,
            address_fault,
            balance,
            did,
            second_factor,
            cache,
            hotkey,
            menu_suppressed,
            window_host,
            update,
            node_facts,
            hosted_stores,
            installed_apps,
            profiles,
            profile_creation,
            profile_deletion,
            mint_chain,
            network,
            enrolment,
            send,
            running,
        } = self;

        // The editor's card flips between its form and the sentence naming what is missing on this
        // reading alone, so a view that ignored it would leave a person looking at "your account is
        // locked" after they unlocked it.
        profile_editing == &other.profile_editing
            && running == &other.running
            && node_connected == &other.node_connected
            && node == &other.node
            && account == &other.account
            && profile_id == &other.profile_id
            // The Wallet row flips between "Copy my receive address" and "(unlock first)" on this
            // field alone, so a menu that ignored it could offer a copy the shell can no longer serve.
            && receive_address == &other.receive_address
            // A fault changes what the Wallet row SAYS, so it must repaint even though the address
            // itself is `None` in both snapshots.
            && address_fault == &other.address_fault
            // The Wallet row RENDERS the balance, so a reading that changed must repaint — without
            // this the first real figure would never replace "Balance not known" until something
            // else in the menu happened to move (dig_ecosystem#2206).
            && balance == &other.balance
            && did == &other.did
            // Without this the Security submenu would keep offering "Set up..." after an enrolment
            // completed, because nothing else in the view changed and the menu would not repaint.
            && second_factor == &other.second_factor
            // The Cache submenu shows live usage on its parent label and marks the current cap, so a
            // changed cap or a moved usage figure must repaint — otherwise a just-applied new cap would
            // not show as current until something else changed (dig_ecosystem#2002).
            && cache == &other.cache
            // The `Open URL…` row's label carries the registered chord, so a hotkey that was taken or
            // released changes the row's text.
            && hotkey == &other.hotkey
            // A menu refused for want of foreground rights explains a click that produced nothing,
            // so the tooltip must repaint the moment it flips -- in both directions, since the
            // recovery is what tells the user their next click will work (dig-app#86).
            && menu_suppressed == &other.menu_suppressed
            // The trim switch itself. See the module doc above: without this, a degraded host keeps a
            // four-row tray and the window that was supposed to hold the other 25 verbs never opens.
            && window_host == &other.window_host
            // The auto-update group's heading states whether updates are on and which channel is
            // followed, and one channel row is marked as current. A switch applied through an
            // elevation prompt changes nothing else in the view, so without this the group would keep
            // showing the OLD setting until something unrelated moved (dig_ecosystem#2293).
            && update == &other.update
            // The Status pane RENDERS these facts, so a node that restarted into a new version — or
            // whose capsule count moved — must repaint. Safe to compare because the one field that
            // moved every second is bucketed to the minute before it arrives here
            // (`crate::node_facts`); at minute granularity this contributes at most one extra
            // repaint a minute, which is a fact a person can actually see change.
            && node_facts == &other.node_facts
            // The Cache pane RENDERS this list, so a store that was just cached — or a read that
            // finished, failed, or timed out — must repaint. Without it the first real list would
            // never replace "checking" until something else in the view happened to move, which is
            // the freeze `balance` needed this same arm to avoid (dig_ecosystem#2206).
            //
            // It cannot change per tick: the poller returns a CACHED reading for a whole
            // `REFRESH_INTERVAL`, and the per-capsule detail that a busy node rewrites continuously
            // is deliberately not carried (`crate::hosted_stores::HostedStore`).
            && hosted_stores == &other.hosted_stores
            // The Apps pane draws an "Installed" chip from this, so an app that finished installing
            // while the window was open must repaint. It changes only when a sibling binary appears
            // or disappears — an event, not a tick.
            && installed_apps == &other.installed_apps
            // The Account pane RENDERS this list, and every one of its controls changes it: a
            // switch moves the active row, hiding moves a visibility. Without this arm a person
            // would press "Use this profile" and watch nothing move until some unrelated field
            // happened to tick — the freeze `balance` and `hosted_stores` both needed this same arm
            // to avoid (dig_ecosystem#2206).
            && profiles == &other.profiles
            // It changes only when the build does, which is never within a session — carried so a
            // field the pane draws from cannot escape this comparison, which destructures with no
            // `..` precisely so that it cannot.
            && profile_creation == &other.profile_creation
            // The delete control appears and disappears on this reading alone, and it is the one
            // control in the app a person must never find missing without a sentence saying why.
            && profile_deletion == &other.profile_deletion
            && mint_chain == &other.mint_chain
            // The header strip RENDERS all three of these, on every tab. Without this arm the first
            // real peer count would never replace nothing at all until some unrelated field moved —
            // the freeze `balance`, `hosted_stores` and `profiles` each needed this same arm to
            // avoid (dig_ecosystem#2206). It cannot change per tick: the poller returns a CACHED
            // reading for a whole `REFRESH_INTERVAL`.
            && network == &other.network
            // The Wallet window's explanation for a missing figure NAMES this, so an enrolment that
            // landed must repaint — otherwise the window keeps blaming the chain after the reason
            // stopped being the chain.
            && enrolment == &other.enrolment
            // The Wallet pane RENDERS this, and every state it passes through is one a person is
            // waiting on: signing, then pending with a block count that grows, then confirmed.
            // Without this arm a send would move through all of them behind a screen still showing
            // the form — the freeze `balance` needed this same arm to avoid (dig_ecosystem#2206).
            && send == &other.send
    }

    /// The account state, defaulting to [`AccountState::Absent`] before the first boot has reported.
    ///
    /// `pub(crate)`: the window model builds from the same snapshot and must read the same default
    /// (dig_ecosystem#2253). Re-deriving "no report yet means Absent" there would let the two surfaces
    /// disagree about a freshly started app.
    pub(crate) fn account(&self) -> AccountState {
        self.account.clone().unwrap_or(AccountState::Absent)
    }
}

/// Whether this host can open the tabbed app window, as opposed to the tray menu alone
/// (dig_ecosystem#2253).
///
/// A three-state capability rather than something inferred at each call site from the target triple:
/// the SAME two hosts — macOS, and a Linux session with no display server reachable — must answer this
/// identically, and a `cfg!(target_os = ...)` inside the model would let one of them go unexercised by
/// CI. The shell is the only thing that knows whether a window host is actually reachable right now, so
/// it fills this field once per snapshot and the model reads it as plain data like everything else in
/// [`TrayView`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WindowHost {
    /// A window can be opened on this host right now.
    #[default]
    Available,
    /// No window can be opened on this host — every verb must stay reachable from the tray alone.
    Unavailable,
}

/// What the host holds at rest, independent of any live session.
///
/// Three states rather than a `bool`, because "there is an account here that will not open" is a genuinely
/// different situation from both "no account" and "an account we simply have not unlocked yet" — and
/// collapsing it into either produces a tray that lies (see [`AccountState::Unopenable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtRest {
    /// No account is enrolled on this host.
    None,
    /// An account is enrolled. Whether it is currently unlocked is the session's business.
    Present,
    /// An account is enrolled and an attempt to open it FAILED.
    PresentButUnopenable,
    /// An account is enrolled, and it is still sealed under the machine-generated password — it has no
    /// user-known secret protecting it yet. See [`AccountState::NeedsPassword`].
    PresentUnderMachinePassword,
}

/// How far the shell has got trying to OPEN the account this run — the fact that separates an account
/// nobody has unlocked yet from one that will not open (dig_ecosystem#2128).
///
/// An enum rather than a `bool`, because the shell used to carry a single `boot_failed` flag it derived
/// from "there is no live session". Since #1817 the app boots LOCKED and attempts no unlock at start-up,
/// so that flag read `true` on every launch with an enrolled account and reported every one of them as
/// [`AccountState::Unopenable`] — an account in an unreadable format, whose only offered remedy is to
/// replace it. Nothing had failed; nothing had been tried. Only an ATTEMPT can fail, so only an attempt
/// can be reported as having failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAttempt {
    /// No unlock has been attempted this run. The normal state of a freshly started app: the account
    /// boots locked and waits for its owner (#1817).
    NotAttempted,
    /// An unlock was attempted and did not complete — the user cancelled, the password did not open the
    /// seal, or the host could not draw the window. All of these are RETRYABLE, so the account stays
    /// merely locked and `Unlock…` remains the way in.
    Refused,
    /// An unlock was attempted and the SEAL ITSELF could not be read: a legacy raw-seed blob or a seed
    /// envelope this build does not understand. No password opens such an account, which is what makes
    /// [`AccountState::Unopenable`]'s replace-it remedy the honest answer — and why nothing else may
    /// reach it.
    Wedged,
}

/// Derive what the host holds at rest from the three facts the shell can observe.
///
/// The order is deliberate: an absent account outranks everything (there is nothing to say about opening
/// one that does not exist), and an account still under the retired machine password outranks a wedge
/// verdict, because its remedy is to choose a password rather than to replace the account.
pub fn at_rest_of(enrolled: bool, needs_password: bool, attempt: OpenAttempt) -> AtRest {
    match () {
        _ if !enrolled => AtRest::None,
        _ if needs_password => AtRest::PresentUnderMachinePassword,
        _ if matches!(attempt, OpenAttempt::Wedged) => AtRest::PresentButUnopenable,
        _ => AtRest::Present,
    }
}

/// What a live tray session knows about its account — the two facts the state derivation needs.
///
/// `keys_unlocked` is read FRESH from the residency, never inferred from the session existing: a session
/// outlives its key material by design (lock-now and the idle auto-lock drop the keys and keep the
/// session, so the sign path can re-unlock into it). Confusing "we have a session" with "the account is
/// unlocked" is what made the menu report `unlocked` after Lock now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionFacts {
    /// Whether the residency still holds key material RIGHT NOW.
    pub keys_unlocked: bool,
    /// Whether a recovery phrase is stored for this account.
    pub recoverable: bool,
}

impl SessionFacts {
    /// Read the facts off a live residency.
    ///
    /// This lives here, beside the rules that consume it, so the `is_any_unlocked` call itself is covered
    /// by tests rather than sitting untested in a binary.
    pub fn of(residency: &crate::account::residency::AccountResidency, recoverable: bool) -> Self {
        use crate::session_lock::SessionKeys;

        Self {
            keys_unlocked: residency.is_any_unlocked(),
            recoverable,
        }
    }
}

/// Derive the account state the menu shows.
///
/// - `host_supports_accounts` — whether this OS can hold an account at all (a per-application-ACL
///   credential store exists).
/// - `enrolled` — whether an account exists at rest.
/// - `session` — the live session's facts, or `None` when the shell holds no session.
///
/// A session whose KEYS have been dropped reports [`AccountState::Locked`] — deliberately the same state
/// as a not-yet-unlocked account, because the way back in is the same (`Unlock…`). Anything else would
/// report a lock that is not there and offer no route out of it (`SPEC.md` §3.1c).
pub fn account_state(
    host_supports_accounts: bool,
    at_rest: AtRest,
    session: Option<SessionFacts>,
) -> AccountState {
    if !host_supports_accounts {
        return AccountState::Unsupported;
    }
    match session {
        Some(SessionFacts {
            keys_unlocked: true,
            recoverable,
        }) => AccountState::Unlocked { recoverable },
        // A session with no keys is LOCKED even if a previous open attempt failed: we provably opened this
        // account once, so `Unlock…` is the right offer and the way back in.
        Some(_) => AccountState::Locked,
        None => match at_rest {
            AtRest::None => AccountState::Absent,
            AtRest::Present => AccountState::Locked,
            AtRest::PresentButUnopenable => AccountState::Unopenable,
            AtRest::PresentUnderMachinePassword => AccountState::NeedsPassword,
        },
    }
}

/// The native menu-item id that stands for `action`, on every menu this shell will ever build.
///
/// **Why the id must not be generated (dig_ecosystem#2074).** `muda` assigns an unnamed `MenuItem` an id
/// from a process-global counter, so every menu rebuild renames every row. The shell rebuilds whenever the
/// rendered view changes — and the view carries the node's own description, which the five-second node poll
/// rewrites whenever a capsule or store count moves — so the ids under a menu the user is looking at are
/// replaced out from under them on a timer they cannot see. A click then arrives bearing an id the shell no
/// longer has a handler for, and the only honest thing left to do with it is drop it. That is what
/// "I click it and nothing happens" was.
///
/// Deriving the id from the action instead makes a rebuilt menu name its rows exactly as the previous one
/// did, so a click that crosses a rebuild still resolves to the verb the user actually chose. The `Debug`
/// spelling is used because the variant name is already the stable, unique, human-legible thing an id
/// wants to be.
///
/// # The property this actually has (dig_ecosystem#2257)
///
/// The id is **injective over ACTIONS**: two different [`TrayAction`] values — including two
/// [`SetCacheCap`](TrayAction::SetCacheCap) presets and two [`LaunchApp`](TrayAction::LaunchApp) apps —
/// never share one.
/// `window_model::tests::stable_ids_are_unique_across_every_variant_this_shell_can_build` holds that.
///
/// It is **not** injective over ROWS, and that is intended. Eight variants render two rows each in the
/// same menu (`Unlock`, `SetAccountPassword`, `ExplainUnopenable`, `SetUpAccount`, `AboutDid`,
/// `AboutWallet`, `AboutCache`, `ShowStatus`) — the top-level urgent row repeated inside a submenu, or
/// the wallet's balance line beside its explainer — and each pair deliberately shares one id, because
/// both rows do the same thing. The shell's `verbs` map collapses them onto one handler for exactly that
/// reason; that collapse is correct and must not be "fixed". A surface that must address one particular
/// ROW (a sidebar highlighting the active entry) needs a row key of its own, not a change here.
///
/// An earlier version of this comment cited a test named
/// `stable_ids_are_unique_across_every_menu_this_shell_can_build`, which had never been written and
/// claimed the per-row property that does not hold.
pub fn action_id(action: TrayAction) -> String {
    format!("dig-tray-action:{action:?}")
}

/// Every action row in `rows`, as the native id the shell will give it (see [`action_id`]).
///
/// Recursive over submenus for the same reason [`MenuModel::find`] is: a verb's id must not depend on how
/// deeply it happens to be nested.
pub fn action_ids(rows: &[MenuRow]) -> Vec<(String, TrayAction)> {
    let mut found = Vec::new();
    collect_action_ids(rows, &mut found);
    found
}

fn collect_action_ids(rows: &[MenuRow], found: &mut Vec<(String, TrayAction)>) {
    for row in rows {
        match row {
            MenuRow::Separator => {}
            MenuRow::Action { action, .. } => found.push((action_id(*action), *action)),
            MenuRow::Submenu { rows, .. } => collect_action_ids(rows, found),
        }
    }
}

/// One thing the user can click. The shell maps each to its handler; the model never performs an action.
///
/// Deliberately NOT `Hash`: [`Send`](Self::Send) carries a `TransferRequest`, which is not, and
/// nothing keys a map by an action — the shell's verb map is keyed by [`action_id`], a string, so that
/// two rows performing the same verb can share one handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    /// Show everything the tray knows, in full, in a window that can hold it.
    ///
    /// This is where the five former greyed status rows went. It is enabled in every state, because what
    /// it promises — telling the user what is going on — is something the app can always do, even (and
    /// especially) when everything else is broken.
    ShowStatus,
    /// Ask for a DIG link in a native input window, then open it through the local node.
    ///
    /// The tray equivalent of `diga open` (dig_ecosystem#1821). Enabled in EVERY state, deliberately:
    /// reading content is the product's core function and needs no account (§6.0 — consumption stays
    /// frictionless and must never be gated on custody), and when there is no node to resolve through,
    /// the handler says so precisely rather than the menu offering a greyed row that explains nothing
    /// (§1800). The link is validated before anything is opened — store content is attacker-controlled
    /// (#745), so the scheme allowlist is a security boundary, not a convenience.
    Open,
    /// Create the FIRST account on a host that has none: generate a recovery phrase, show it, confirm,
    /// enrol. Offered only while no account exists; replacing one that does is
    /// [`ReplaceWithNewAccount`](Self::ReplaceWithNewAccount), which destroys custody and must say so.
    SetUpAccount,
    /// Restore an account onto a host that has none, from its recovery phrase, typed into a native
    /// input window.
    RestoreFromPhrase,
    /// **Destructive.** Discard the account on this host and create a brand-new one in its place.
    ///
    /// The remedy for a phrase-less legacy account (there is no way to add words to an existing custody
    /// root) and for a user who simply wants a different identity. Routed through the biometric
    /// authorization seam, never a notice.
    ReplaceWithNewAccount,
    /// **Destructive.** Discard the account on this host and restore a different one from its recovery
    /// phrase. Same guard as [`ReplaceWithNewAccount`](Self::ReplaceWithNewAccount).
    ReplaceFromPhrase,
    /// **Destructive.** Remove the account from this computer, leaving none.
    ///
    /// The way out for someone uninstalling, handing the machine on, or moving their account elsewhere —
    /// and the reason "manage the current one" does not mean "replace it or live with it".
    RemoveAccount,
    /// Unlock the existing account.
    Unlock,
    /// Give an account that is still sealed under the machine-generated password one the USER chooses,
    /// re-sealing the SAME seed so the account, its identity and its data all survive.
    ///
    /// Offered ONLY in [`AccountState::NeedsPassword`], because in every other state there is either no
    /// account to re-seal or a user password already in place.
    SetAccountPassword,
    /// Re-seal the session now.
    LockNow,
    /// Re-display the account's recovery phrase, behind unlock + a native confirm.
    ShowRecoveryPhrase,
    /// Copy the account's recovery phrase to the clipboard, behind the SAME gate as a reveal plus a stark
    /// unencrypted-storage warning (dig_ecosystem#1564). Offered ONLY on an unlocked, recoverable account.
    CopyRecoveryPhrase,
    /// Save the account's recovery phrase to a plain `.txt` file, behind the same gate + warning as
    /// [`CopyRecoveryPhrase`](Self::CopyRecoveryPhrase). Offered ONLY on an unlocked, recoverable account.
    SaveRecoveryPhrase,
    /// Offered ONLY to an account that cannot be opened: explain WHY signing is unavailable and point at
    /// the only remedy, which is replacing the account.
    ///
    /// This is the in-app route out of the wedged legacy-seed state ([`AccountState::Unopenable`]) that the
    /// boot previously reduced to a log line.
    ExplainUnopenable,
    /// Offered ONLY to an account that has no recovery phrase: explain the situation and point at the
    /// remedy, which is [`ReplaceWithNewAccount`](Self::ReplaceWithNewAccount) in the management submenu.
    ///
    /// It informs and nothing more — it does NOT replace or delete anything. Before #1800 this was a
    /// dead end: it explained that the only remedy was a new account while the menu offered no way to
    /// create one. Now it names where that remedy is.
    FixMissingPhrase,
    /// Set up an authenticator-app code as a SECOND factor (dig_ecosystem#1840).
    ///
    /// Offered only while the account is unlocked, which is its real precondition: the enrolment is
    /// sealed under the account's own key, so a locked account cannot store one. The Security submenu in
    /// the locked state offers `Unlock…` and nothing else, so the row's absence is not a dead end — the
    /// remedy is the only row there.
    ///
    /// The handler ships with the row (see the `dig-app` shell's `dispatch`). A row whose handler does
    /// nothing is exactly the dead end dig_ecosystem#1800 removed from this menu.
    SetUpTwoFactor,
    /// Turn the enrolled second factor OFF, behind the biometric authorization seam.
    ///
    /// Weakening a protection is a security act, not a toggle, so this is authorized rather than
    /// switched — see [`journey::disable`](crate::account::second_factor::journey::disable).
    TurnOffTwoFactor,
    /// Show a pairing code so another program on this computer can use this DIG Account
    /// (dig_ecosystem#1848).
    ///
    /// Lives under **Security**, not Manage Account, because Security's question is *is my account
    /// safe right now* and "which other programs can act through it" is exactly that question. Manage
    /// Account answers *I want a different account*, which this is not.
    ///
    /// Offered only while the account is UNLOCKED, which is its real precondition: pairing seals a
    /// record under the account's own key, so a locked account cannot store one. In the locked state
    /// the row is absent rather than greyed, and the `Unlock…` row directly above is the remedy — the
    /// same shape [`SetUpTwoFactor`](Self::SetUpTwoFactor) uses, for the same reason (#1800).
    PairAnApp,
    /// See which programs are paired with this DIG Account, and remove any of their access.
    ///
    /// Enabled whenever the account is unlocked, INCLUDING when nothing is paired: the window then says
    /// so and names the way to pair something. A row that vanished when the list was empty would leave
    /// a user who wants to check unable to find out that the answer is "nothing".
    ManagePairedApps,
    /// Copy the profile's DIG ID to the clipboard.
    CopyDigId,
    /// EXPLAIN what an on-chain `did:chia:` DID is, what it costs, and that the account works without one.
    ///
    /// There is deliberately no `CreateDid` action: nothing in this build can mint (see
    /// [`crate::account::mint`]), so an action that mints does not exist and therefore is not offered —
    /// not even disabled. Because no
    /// [`TrayAction`] can mint, "the tray cannot spend XCH on a DID" is structural rather than a property
    /// of one `enabled: false`.
    AboutDid,
    /// Make one of this account's dig-profiles the active one (dig_ecosystem#2403).
    ///
    /// Carries the HD index rather than "the next one" for the reason
    /// [`SetCacheCap`](Self::SetCacheCap) carries its bytes: a click must resolve the same way
    /// however stale the list it was drawn from is. The shell DISCLOSES what the switch changes
    /// before applying it ([`SwitchPlan`](crate::profiles::SwitchPlan)), because the receive address,
    /// the per-profile DEK and the identity signing key all derive at this index — being told
    /// afterwards means the first a person knows of it is money arriving somewhere they were not
    /// shown.
    ///
    /// Offered only for a profile that is NOT already active: a row that reads "use this profile"
    /// beside the profile in use is a control whose only effect is to raise a warning about a change
    /// that is not happening.
    SetActiveProfile {
        /// The profile's HD index, as `ProfileIx`'s inner `u32`. A plain integer so the whole action
        /// stays `Copy` and comparable, exactly as the cache preset's byte count is.
        ix: u32,
    },
    /// Show a dig-profile in this host's lists, or stop showing it (dig_ecosystem#2403).
    ///
    /// Carries the visibility being MOVED TO, not "toggle", for the reason
    /// [`SetAutoUpdate`](Self::SetAutoUpdate) does: a list that moved between the repaint and the
    /// click then resolves to what the row said rather than to the opposite of a state that changed.
    ///
    /// **This is a local view preference and nothing more.** A minted profile is permanent on chain
    /// — hiding one does not delete it, does not stop it deriving, and does not stop it spending —
    /// so the row's label says *hide from this list*, never *remove* or *delete*. dig-account
    /// refuses to hide the ACTIVE profile, and `set_active` un-hides its target, so there is no
    /// state in which a person can hide their way out of their own account.
    SetProfileVisibility {
        /// The profile's HD index, as `ProfileIx`'s inner `u32`.
        ix: u32,
        /// `true` to hide it from this host's lists, `false` to show it again.
        hidden: bool,
    },
    /// DELETE a profile permanently, by melting both of its singletons (dig_ecosystem#3037).
    ///
    /// # This is the one verb in the app that cannot be undone at any layer
    ///
    /// [`SetProfileVisibility`](Self::SetProfileVisibility) directly above it is a preference about
    /// one computer's lists. This ends the profile on chain: both singletons are spent with
    /// `MELT_SINGLETON`, so neither lineage has a successor and the launcher ids can never be
    /// re-derived. Every `did:chia:` reference to that identity stops resolving, for everybody.
    ///
    /// So the row carries no state to move to and no toggle — pressing it opens a confirmation that
    /// NAMES the DID and the store it will end, and the ceremony begins only after that. The label
    /// says *permanently* for the same reason `PublishProfileEdits` says *publish*: a verb that
    /// sounds reversible in front of an act that is not is the surprise `professional-ui` forbids.
    ///
    /// Offered ONLY where [`ProfileDeletion::is_possible`](crate::profiles::ProfileDeletion) — the
    /// seams, an unlocked account, and a profile the registry actually holds. Never derived from
    /// `blocked().is_none()`, which reads an unmeasured build as a capable one.
    DeleteProfile {
        /// The profile's HD index, as `ProfileIx`'s inner `u32`.
        ix: u32,
    },
    /// EXPLAIN what a dig-profile is and what creating one costs (dig_ecosystem#2403).
    ///
    /// # It is an explainer, and the reason changed when the ceremony landed
    ///
    /// It used to be the honest surface because nothing in this shell COULD create a profile:
    /// dig-account's mint was `todo!()`, and then it was implemented but had no ceremony here to
    /// disclose the cost and take consent. Both of those expired — dig_ecosystem#2989 landed the
    /// ceremony, and the funded first-profile window now offers it.
    ///
    /// What did not change is that this row is not the way in. Creating costs real XCH from a wallet
    /// that has to be funded FIRST, so the path runs through [`CreateProfile`](Self::CreateProfile)'s
    /// funding check; a concept explainer that quietly spent money would be the worse dead end.
    ///
    /// Like the other explainers it is about the CONCEPT, so it is offered in every state.
    AboutProfiles,
    /// Publish the changes a person has made to their profile (dig_ecosystem#2993).
    ///
    /// # Why the verb says *publish* and not *save*
    ///
    /// Saving a document is free, private and reversible. This spends real XCH, writes to a public
    /// chain, and cannot be taken back — anybody who read the old profile may have kept it. A label
    /// promising the first while doing the second is the surprise `professional-ui` forbids.
    ///
    /// Offered ONLY where [`ProfileEditing::is_possible`](crate::profile_edit::ProfileEditing) — a
    /// build with the seams, an account that is unlocked, and a profile that exists. Never derived
    /// from `blocked().is_none()`, which reads an unmeasured build as a capable one.
    PublishProfileEdits,
    ///
    /// # The verb is deliberately NARROWER than "create a profile"
    ///
    /// Pressing this raises the same funding window the first-profile prompt raises on its daily
    /// cadence — it reads the balance and shows the address to send XCH to. Pressing THIS row still
    /// spends nothing: what it opens is the funding check.
    ///
    /// So the label says *funding*, not *create*, and it still should. The ceremony behind the
    /// funded window landed in dig_ecosystem#2989, but a row promising *create* would still be one
    /// screen short of the truth — the wallet has to be able to pay before anything can be created,
    /// and a row that led to *you need funds* would be the refuses-one-screen-later dead end
    /// `professional-ui` forbids and dig_ecosystem#1800 removed once already.
    ///
    /// Offered ONLY where `ProfileCreation::is_possible()` — a live node answered both probes AND
    /// the ceremony would not refuse on divergent indices (dig_ecosystem#2939). Never derived from
    /// `blocked().is_none()`, which reads an unmeasured node as a capable one.
    CreateProfile,
    /// Put the zero-profile funding prompt on screen (dig_ecosystem#2950).
    ///
    /// # The one action here that NO menu row offers
    ///
    /// Every other variant is a click. This one is raised by the state loop, which is the whole
    /// point of the feature: the user asked for *"an automatic popout"*, so nobody presses anything
    /// to reach it.
    ///
    /// It is a [`TrayAction`] rather than a dialog the tick opens directly for two reasons, and both
    /// are properties the worker already provides. The tick thread must never block — a prompt drawn
    /// there would freeze the tray for as long as somebody left the window open — and the worker's
    /// one-at-a-time reservation is what stops this window appearing on top of an unlock, a recovery
    /// phrase, or a send confirmation. A prompt that could stack over a custody dialog would be a
    /// window asking for money in front of one asking for a password.
    ///
    /// Whether it is raised at all is decided by
    /// [`first_profile_prompt`](crate::account::first_profile::first_profile_prompt), never here.
    CreateFirstProfile,
    /// Copy the account's `xch1…` receive address to the clipboard (dig_ecosystem#1850).
    ///
    /// The address comes from [`TrayView::receive_address`], which the shell fills from the account's own
    /// MONEY key — never from [`profile_id`](TrayView::profile_id), which is the identity public key and
    /// would be a confidently wrong string to hand someone who means to pay you. Offered only where an
    /// address can exist; see `wallet_actions`.
    CopyReceiveAddress,
    /// Show the wallet: the receive address, the balance (or precisely why it is not known), and where
    /// sending lives.
    ///
    /// There is deliberately no send ROW. That is a statement about menus, not about the app: a menu
    /// cannot hold a form, and an amount is not something a person picks from a list — the same reason
    /// [`Send`](Self::Send) is emitted by the Wallet PANE and never by a tray row.
    ///
    /// The stronger claim this comment used to make — that no [`TrayAction`] can move funds, so "the tray
    /// cannot spend" is STRUCTURAL — **expired** when [`Send`](Self::Send) landed
    /// (dig_ecosystem#2819). Do not rely on it as an invariant; a `TrayAction` CAN now carry a spend, and
    /// what keeps it off this menu is the row inventory, not the type. The window's body was corrected
    /// alongside this comment, because it was telling users the same expired thing (dig_ecosystem#2988).
    AboutWallet,
    /// Send money from this wallet — the payment a person filled in on the Wallet tab, ready to
    /// build (dig_ecosystem#2819, extended to $DIG by dig_ecosystem#2396).
    ///
    /// # Why it carries a validated [`SendIntent`](crate::wallet::sending::SendIntent), not the typed strings
    ///
    /// Both of its arms can only be built from a destination that has
    /// already been decoded and judged payable, because
    /// [`PayableDestination`](dig_account::PayableDestination) has no other public route from a string
    /// — its `from_address` refuses any prefix but `xch`, since paying the puzzle hash inside a `txch`
    /// address burns the funds permanently. Carrying the raw text instead would move that decode into
    /// the shell binary, which no test can execute (dig_ecosystem#2377); carrying a bare puzzle hash
    /// would mean reconstructing the request through `from_derived`, which is the documented way to
    /// bypass the very check that prevents the burn.
    ///
    /// So the validation happens where the string is — in
    /// [`SendDraft::assess`](crate::wallet::sending::SendDraft::assess), under test — and what reaches
    /// the shell is a request that is payable by construction. The fee is already applied.
    ///
    /// Carrying the ASSET as part of the validated intent, rather than beside it, is what makes it
    /// impossible for the shell to pair a $DIG amount with the XCH builder: there is no arm of this
    /// type in which the amount and the builder disagree.
    ///
    /// This action is offered by the Wallet PANE and never by a tray row: a menu cannot hold a form,
    /// and an amount is not something a person picks from a list.
    Send(crate::wallet::sending::SendIntent),
    /// Take the Chia offer the person pasted or scanned and is looking at (dig_ecosystem#3077).
    ///
    /// It carries NOTHING, and that is a design choice rather than a limitation of this `Copy` enum.
    /// The offer itself lives in [`crate::wallet::offer::staged`], as a
    /// [`ReviewedOffer`](crate::wallet::offer::ReviewedOffer) — a value that owns both the offer
    /// bytes and the summary those very bytes produced, whose only constructor is the parser. So the
    /// shell cannot take an offer other than the one the pane read and displayed: there is no raw
    /// string in flight for the two to disagree about.
    ///
    /// Offered by the Wallet PANE only, like [`Send`](Self::Send): it needs a field to paste
    /// an `offer1…` string into, and a native menu cannot hold one.
    TakeOffer,
    /// Make the offer the person has filled in on the Wallet pane (dig_ecosystem#3077).
    ///
    /// Carries nothing, for the same reason [`TakeOffer`](Self::TakeOffer) does: the draft lives in
    /// [`crate::wallet::making::staged`] as a checked
    /// [`MakeDraft`](crate::wallet::making::MakeDraft), so what the shell makes is the offer the form
    /// showed and no separate copy of the figures is in flight.
    ///
    /// Offered by the Wallet PANE only — it needs a form, and a native menu cannot hold one.
    MakeOffer,
    /// Cancel the offer the person pasted and is looking at, reclaiming its coins
    /// (dig_ecosystem#3077).
    ///
    /// Carries nothing: the offer lives in [`crate::wallet::offer::staged`], the same
    /// [`ReviewedOffer`](crate::wallet::offer::ReviewedOffer) the take path uses, so the bytes
    /// cancelled are the bytes displayed.
    ///
    /// Destructive (NC-14): it makes an outstanding offer unfillable and cannot be undone, which the
    /// confirm ceremony NAMES rather than expressing as a value delta.
    CancelOffer,
    /// Release a send whose fate this app never learned, on the person's own say-so
    /// (dig_ecosystem#2894).
    ///
    /// It carries nothing, for the same reason [`Send`](Self::Send) carries a validated
    /// request rather than the raw fields: the rule lives where a test can put a wrong answer in
    /// front of it. The typed acknowledgement is judged by
    /// [`ReleaseDraft::assess`](crate::wallet::sending::ReleaseDraft::assess), and this action is
    /// only ever emitted for a draft that passed — so what reaches the shell is an acknowledged
    /// release by construction.
    ///
    /// Like `Send` this is offered by the Wallet PANE only: it needs a field.
    ReleaseUnknownSend,
    /// Set the node's content-cache size cap to a specific preset (dig_ecosystem#2002).
    ///
    /// Carries the target cap in bytes so the shell forwards it straight to the node's
    /// `control.cache.setCap` — no free-text parsing for a preset, which is a known-good value. The
    /// shell still runs the eviction check ([`crate::cache::plan_cap_change`]) before applying, so a
    /// preset below current usage warns before it deletes anything, exactly like a custom value.
    SetCacheCap {
        /// The cap to apply, in bytes — one of [`crate::cache::CACHE_PRESETS`].
        bytes: u64,
    },
    /// Ask for a custom cache size in a native input window, validate it, then apply it
    /// (dig_ecosystem#2002). The typed path for a size no preset covers.
    SetCustomCacheCap,
    /// Explain what the cache is, what it costs in disk and buys in privacy, and the unit convention
    /// — the honest "About the cache…" notice (dig_ecosystem#2002, §6.0 honest copy). Carries no
    /// action beyond informing, and is always available because it is about the CONCEPT, not this
    /// node's live state.
    AboutCache,
    /// Turn auto-update on or off (dig_ecosystem#2293).
    ///
    /// Carries the state being MOVED TO rather than "toggle", so a click resolves the same way however
    /// stale the menu it was drawn from is: a beacon that was paused by an administrator between the
    /// repaint and the click gets `pause` again, which is a no-op, instead of being silently resumed.
    ///
    /// The shell performs this by running the beacon ([`crate::auto_update::plan_change`]), which needs
    /// elevation — the row's own label says so.
    SetAutoUpdate {
        /// `true` to resume auto-updates, `false` to pause them.
        enabled: bool,
    },
    /// Put back a daily update check that was deliberately removed (dig_ecosystem#2324).
    ///
    /// A SEPARATE action from `SetAutoUpdate { enabled: true }`, even though the row a person clicks
    /// says the same thing, because the two run different beacon commands and only one of them works
    /// here. `resume` clears a pause; on an opted-out host there is no pause to clear, so it succeeds
    /// while changing nothing and the app reports a saved setting for a machine that still never
    /// updates. `schedule install` is the command that actually re-arms the daily check.
    RearmUpdateSchedule,
    /// Follow a different update feed — stable or nightly (dig_ecosystem#2293).
    ///
    /// One variant per channel rather than one per direction: the channel in force is read from the
    /// beacon at click time, so the row only has to name the destination.
    SetUpdateChannel(crate::auto_update::UpdateChannel),
    /// Explain how auto-update works, what the two channels mean, and why changing either asks for
    /// administrator — the honest "About auto-update…" notice (dig_ecosystem#2293). Like
    /// [`AboutCache`](Self::AboutCache) it is about the CONCEPT, so it is offered in every state,
    /// including on a machine with no beacon installed at all.
    AboutAutoUpdate,
    /// Open another DIG app from the **Apps** group (dig_ecosystem#2101).
    ///
    /// Carries the [`AppId`](crate::apps::AppId) of the registry row clicked, so ONE action serves
    /// every app and adding one (dig-email, dig-video-chat — §5.4) is a [`crate::apps::APPS`] row, not
    /// a new variant here. The shell decides launch-vs-notice through the pure
    /// [`plan_launch`](crate::apps::plan_launch) seam and, when the app is present, spawns it DETACHED
    /// off the prompt thread (#78) with no argv identity — never a silent no-op when it is absent
    /// (§6.1), which today is the only reachable case.
    LaunchApp(crate::apps::AppId),
    /// Open the tabbed app window — the surface that holds every verb the tray no longer shows
    /// (dig_ecosystem#2253).
    ///
    /// Distinct from [`LaunchApp`](Self::LaunchApp), which starts a *separate sibling binary*, and from
    /// [`ShowStatus`](Self::ShowStatus), which opens a one-shot notice. This opens THIS app's own
    /// window, in this process, on the one prompt thread.
    ///
    /// The handler acks on OPEN, never on close: the window lives for as long as the person wants it,
    /// and a worker held for that whole time would refuse every later click — including `Quit`.
    OpenWindow,
    /// Open the log folder, the escape hatch when something is wrong and the menu cannot say why.
    OpenLogs,
    /// Stop the agent and exit.
    Quit,
}

/// A row of the rendered menu.
///
/// There is deliberately **no status/label variant**. A native menu offers only clickable items,
/// separators and submenus, so "read-only text" can only be rendered as a disabled item — which reads as
/// a broken control (see the module docs). Text belongs in the tooltip or the
/// `Status and details…` window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuRow {
    /// A visual divider grouping the rows around it.
    Separator,
    /// A clickable item.
    Action {
        /// What clicking it does.
        action: TrayAction,
        /// Its user-facing label.
        label: String,
        /// Whether it is clickable right now. A disabled item still SHOWS, so the menu's shape is
        /// stable — and its label must state WHY it cannot be used.
        enabled: bool,
    },
    /// A nested menu, so rare or destructive verbs stay reachable without lengthening the top level.
    Submenu {
        /// The parent row's label.
        label: String,
        /// Its contents, in render order.
        rows: Vec<MenuRow>,
    },
}

impl MenuRow {
    /// A convenience for building an enabled/disabled action row.
    fn action(action: TrayAction, label: impl Into<String>, enabled: bool) -> Self {
        MenuRow::Action {
            action,
            label: label.into(),
            enabled,
        }
    }

    /// A submenu row.
    fn submenu(label: impl Into<String>, rows: Vec<MenuRow>) -> Self {
        MenuRow::Submenu {
            label: label.into(),
            rows,
        }
    }
}

/// The complete menu, in render order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuModel {
    /// The rows, top to bottom.
    pub rows: Vec<MenuRow>,
}

impl MenuModel {
    /// The row for `action`, wherever it is — top level or inside a submenu.
    ///
    /// Searching recursively is what lets every query below stay indifferent to WHERE a verb was placed:
    /// moving `Remove this account…` into the management submenu must not change whether the model
    /// "offers" it.
    pub fn find(&self, wanted: TrayAction) -> Option<&MenuRow> {
        find_action(&self.rows, wanted)
    }

    /// Whether `action` is present AND clickable.
    pub fn is_enabled(&self, action: TrayAction) -> bool {
        matches!(
            self.find(action),
            Some(MenuRow::Action { enabled: true, .. })
        )
    }

    /// Whether `action` appears at all.
    pub fn offers(&self, action: TrayAction) -> bool {
        self.find(action).is_some()
    }

    /// The label `action` is rendered with, if present.
    pub fn label_of(&self, action: TrayAction) -> Option<&str> {
        match self.find(action) {
            Some(MenuRow::Action { label, .. }) => Some(label.as_str()),
            _ => None,
        }
    }

    /// Every action row in the whole menu, submenus included, as (label, enabled) pairs.
    ///
    /// Used by the tests that must hold for EVERY row rather than a named one — "no row mentions a
    /// terminal", "every disabled row says why".
    pub fn all_actions(&self) -> Vec<(&str, bool)> {
        let mut out = Vec::new();
        collect_actions(&self.rows, &mut out);
        out
    }
}

/// Depth-first search for the row carrying `wanted`.
fn find_action(rows: &[MenuRow], wanted: TrayAction) -> Option<&MenuRow> {
    for row in rows {
        match row {
            MenuRow::Action { action, .. } if *action == wanted => return Some(row),
            MenuRow::Submenu { rows, .. } => {
                if let Some(found) = find_action(rows, wanted) {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

/// Flatten every action row, submenus included.
fn collect_actions<'a>(rows: &'a [MenuRow], out: &mut Vec<(&'a str, bool)>) {
    for row in rows {
        match row {
            MenuRow::Action { label, enabled, .. } => out.push((label.as_str(), *enabled)),
            MenuRow::Submenu { rows, .. } => collect_actions(rows, out),
            MenuRow::Separator => {}
        }
    }
}

/// Which picture the tray icon shows — the app's state, at a glance, with no menu open.
///
/// A tray application's icon is the only thing a user sees without clicking, so it must carry the state
/// that used to be printed in greyed menu rows. The variants are ordered by how much they need the
/// user's attention, and [`status`] picks the FIRST one that applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayGlyph {
    /// The agent has not finished starting.
    Starting,
    /// This host cannot hold an account, or has none — nothing works until that is resolved, and it is
    /// the user's next action.
    NeedsAccount,
    /// An account exists but is locked: signing and revealing are unavailable until it unlocks.
    Locked,
    /// Unlocked, but not talking to a node — content cannot be read.
    NoNode,
    /// Everything is working.
    Ready,
}

/// The whole non-menu surface of the tray: its picture and its tooltip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayStatus {
    /// The icon to paint.
    pub glyph: TrayGlyph,
    /// The hover text, bounded to [`MAX_TOOLTIP_CHARS`].
    pub tooltip: String,
}

/// Pick the icon and tooltip for `view`.
///
/// The glyph reports the most actionable problem, not the prettiest fact: a locked account with a
/// healthy node is [`TrayGlyph::Locked`], because the lock is what stops the user doing anything.
pub fn status(view: &TrayView) -> TrayStatus {
    let account = view.account();
    let glyph = if !view.running {
        TrayGlyph::Starting
    } else if matches!(
        account,
        AccountState::Unopenable | AccountState::NeedsPassword
    ) || !account.exists()
    {
        TrayGlyph::NeedsAccount
    } else if !matches!(account, AccountState::Unlocked { .. }) {
        TrayGlyph::Locked
    } else if !view.node_connected {
        TrayGlyph::NoNode
    } else {
        TrayGlyph::Ready
    };
    TrayStatus {
        glyph,
        tooltip: bound_tooltip(&tooltip_text(view, glyph)),
    }
}

/// The unbounded tooltip text: the headline for `glyph`, then the node line.
///
/// Two lines rather than five, because a tooltip is glanced at, not read. Everything else is in
/// [`details_text`].
fn tooltip_text(view: &TrayView, glyph: TrayGlyph) -> String {
    let headline = match glyph {
        TrayGlyph::Starting => "DIG is starting…",
        TrayGlyph::NeedsAccount => match view.account() {
            AccountState::Unsupported => "DIG — accounts are not available on this system yet",
            AccountState::Unopenable => "DIG — your account cannot be opened",
            AccountState::NeedsPassword => "DIG — your account has no password yet",
            _ => "DIG — no account set up yet",
        },
        TrayGlyph::Locked => "DIG — your account is locked",
        TrayGlyph::NoNode => "DIG — no node connection",
        TrayGlyph::Ready => "DIG — ready",
    };
    // The node line is dropped from the tooltip when it would only repeat the headline; two lines saying
    // the same thing waste the whole budget.
    // A refused menu outranks the node line: it is the one thing here that explains something the
    // user just tried and did not get, and it names the remedy, which is simply to click again.
    if view.menu_suppressed {
        return format!(
            "{headline}
Menu blocked by Windows — click the DIG icon again"
        );
    }
    if matches!(glyph, TrayGlyph::NoNode) || view.node.is_empty() {
        headline.to_string()
    } else {
        format!("{headline}\n{}", first_line(&view.node))
    }
}

/// Fit `full` into the tooltip budget, appending an ellipsis when anything was left out.
///
/// Counts and cuts by CHARACTER, not by byte — the connected summary contains `·`, so a byte-indexed
/// slice would panic on a multi-byte boundary.
fn bound_tooltip(full: &str) -> String {
    if full.chars().count() <= MAX_TOOLTIP_CHARS {
        return full.to_string();
    }
    let kept: String = full.chars().take(MAX_TOOLTIP_CHARS).collect();
    format!("{}…", kept.trim_end())
}

/// The first line of a possibly-multi-line summary.
fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or("")
}

/// The full, untruncated text the `Status and details…` window shows.
///
/// This is the home of the five status rows the menu used to carry, and the reason nothing is lost by
/// removing them: a window has no width limit, so the engine's ~700-character diagnosis — the single most
/// actionable message the app can produce, naming the node to start or reinstall — arrives whole instead
/// of cut at 72 characters.
pub fn details_text(view: &TrayView) -> String {
    let account = view.account();
    let mut out = String::new();
    out.push_str(if view.running {
        "DIG agent: running\n"
    } else {
        "DIG agent: starting…\n"
    });
    out.push_str(&format!("Account: {account}\n"));
    out.push_str(&format!(
        "DIG ID: {}\n",
        view.profile_id.as_deref().unwrap_or("not set up yet")
    ));
    out.push_str(&format!(
        "On-chain DID: {}\n\nNode\n{}",
        did_label(view.did.as_deref()),
        if view.node.is_empty() {
            "The node connection has not been probed yet."
        } else {
            &view.node
        }
    ));
    // The full cache figures live here, in the window that has room, rather than the menu (SPEC
    // §3.1c). Only shown when a node reported them — an absent cache is already implied by the node
    // line above saying it is not connected.
    if let Some(cache) = &view.cache {
        use crate::cache::format_cap;
        out.push_str(&format!(
            "\nCache: {} of {} used",
            format_cap(cache.used_bytes),
            format_cap(cache.cap_bytes)
        ));
    }
    // The shortcut goes LAST and only once the shell has tried to claim it. This is the only place its
    // failure — or the fact that it displaced the Windows window menu — is ever stated, so a user who
    // presses the chord and gets nothing has somewhere to find out why (`crate::hotkey`).
    if let Some(hotkey) = &view.hotkey {
        out.push_str(&format!("\n\nKeyboard\n{}", hotkey.summary()));
    }
    out
}

/// Build the menu for `view`.
///
/// # The shape
///
/// Named rows, always the same ones, in this order (dig_ecosystem#1836, extended by #1841 and #2002):
///
/// ```text
/// Status
/// Open URL…
/// View Account    ▸
/// Manage Account  ▸
/// Wallet          ▸
/// Security        ▸
/// Cache           ▸
/// Apps            ▸
/// ──
/// Open the log folder
/// Quit DIG
/// ```
///
/// The **Apps** submenu (dig_ecosystem#2101) lists the other DIG apps this install can open — Chat
/// today, more as they ship (§5.4) — from the [`crate::apps`] registry. Like `Open URL…` and `Cache`
/// it is not gated on an account, because using another app is not a custody action.
///
/// The **Wallet** submenu (dig_ecosystem#1841) carries the receive address, the balance reading, and the
/// explainer — and nothing that moves money: sending lives in the window's Wallet tab, where a refusal
/// can be stated against the control it is about, not in a tray row. Its parent label is
/// deliberately the bare word: unlike the cache figure below, a balance is the user's own money, and a
/// tray spine is read by anyone standing behind them.
///
/// The **Cache** submenu (dig_ecosystem#2002) carries the node's content-cache size limit; its parent
/// label shows the live usage against the cap, so it is a spine row that also reports state without a
/// display-only disabled row (SPEC §3.1c). Like `Open URL…`, it is not gated on an account.
///
/// A FIXED spine is the point. The previous menu grew and shrank with account state — the identity block
/// appeared only when an account existed, and the primary row changed verb — so rows moved under the cursor
/// between repaints and no two machines showed the same menu. A stable spine means muscle memory works.
///
/// Two things sit outside the spine, deliberately:
///
/// - **The escapes.** `Open the log folder` and `Quit DIG` are always clickable, whatever else has gone
///   wrong (`professional-ui`'s never-trap-the-user HARD RULE). A tray app with no way out is a defect, so
///   these are not negotiable against menu length.
/// - **One contextual row, ONLY when the account needs action** — see `urgent_account_row`. Without it a
///   brand-new user would have to find "Set up my DIG Account" inside a submenu, which is exactly the
///   first-run dead end #1800 removed and #1826 exists to prevent.
///
/// # This shape is what a host with NO WINDOW gets
///
/// On a host that can open the app window ([`WindowHost::Available`]) the menu is
/// `trimmed` to four rows instead, and everything above lives in the window. The full menu
/// below is not legacy: it is what macOS and a display-less Linux session still render, and what any
/// host falls back to the moment an attempt to open the window is seen to fail
/// ([`crate::window_host`]).
pub fn build(view: &TrayView) -> MenuModel {
    match view.window_host {
        WindowHost::Available => trimmed(view),
        WindowHost::Unavailable => full(view),
    }
}

/// The four-row menu a host with a working app window gets (dig_ecosystem#2253).
///
/// ```text
/// <the one thing this account needs right now>
/// ──
/// Open URL…
/// Open App
/// Quit DIG
/// ```
///
/// # Why exactly these four, and not a shorter or longer list
///
/// Each is here because putting it behind the window would break something specific.
///
/// - **The account row** ([`urgent_account_row`]) is the whole first-run journey and every way back
///   into a wedged account. Its verb changes with the state — set up, unlock, set a password, explain,
///   lock now — so the ROW is fixed while the ACTION is not. Making a new user find "Set up my DIG
///   Account" inside a window they have no reason to open is the dead end #1800 removed.
/// - **`Open URL…`** is what the product is FOR, needs no account, and is bound to a global shortcut.
///   Reading content must never wait on a window (§6.0 — consumption stays frictionless).
/// - **`Open App`** is the route to the other twenty-five verbs. Without it the trim is a deletion.
/// - **`Quit DIG`** is the escape. A tray app you cannot leave from the tray is a defect.
///
/// `Open the log folder` moves into the window's Status tab, which is only safe because
/// [`crate::window_host`] degrades on an OBSERVED failure: if the window will not open, this menu is
/// not what renders, and the log folder is back on the tray where a broken window cannot hide it.
fn trimmed(view: &TrayView) -> MenuModel {
    let mut rows = Vec::new();
    if let Some(row) = urgent_account_row(&view.account()) {
        rows.push(row);
        rows.push(MenuRow::Separator);
    }
    rows.push(MenuRow::action(
        TrayAction::Open,
        open_url_label(view),
        true,
    ));
    rows.push(MenuRow::action(
        TrayAction::OpenWindow,
        OPEN_WINDOW_LABEL,
        true,
    ));
    rows.push(MenuRow::action(TrayAction::Quit, "Quit DIG", true));
    MenuModel { rows }
}

/// The `Open App` row's label.
///
/// "App", not "window": the person opened DIG, and this is DIG. It deliberately does not collide with
/// the Apps tab's `LaunchApp`, which starts a *different program*.
const OPEN_WINDOW_LABEL: &str = "Open App";

/// The whole menu, for a host with no app window to move it into.
fn full(view: &TrayView) -> MenuModel {
    let account = view.account();
    let mut rows = Vec::new();

    // Whatever the account needs RIGHT NOW, above everything, and only when there is something to need.
    if let Some(row) = urgent_account_row(&account) {
        rows.push(row);
        rows.push(MenuRow::Separator);
    }

    rows.push(MenuRow::action(TrayAction::ShowStatus, "Status", true));
    // Opening content is what the product is FOR, and it works with no account at all — so it sits high and
    // stays enabled in every state (§6.0: consumption is never gated on custody).
    rows.push(MenuRow::action(
        TrayAction::Open,
        open_url_label(view),
        true,
    ));
    rows.push(MenuRow::submenu(
        "View Account",
        view_account_actions(view, &account),
    ));
    rows.push(MenuRow::submenu(
        "Manage Account",
        management_actions(&account),
    ));
    rows.push(MenuRow::submenu("Wallet", wallet_actions(view, &account)));
    rows.push(MenuRow::submenu(
        "Security",
        security_actions(&account, view.second_factor, view.did.as_deref()),
    ));
    // The node's content-cache size limit (dig_ecosystem#2002). A submenu whose PARENT label carries
    // the live usage-against-cap, so the figure the user needs is shown by an actionable row rather
    // than a display-only disabled one (SPEC §3.1c: a menu item is an action). Reading is never gated
    // on an account, so this sits outside the account block.
    rows.push(MenuRow::submenu(
        cache_label(view.cache.as_ref()),
        cache_actions(view.cache.as_ref()),
    ));
    // The other DIG apps this install can open (dig_ecosystem#2101). A submenu built from the
    // `crate::apps` registry, so a second app is a data row. Like reading, using another app is not
    // gated on an account, so it sits outside the account block.
    rows.push(MenuRow::submenu("Apps", apps_actions()));
    // **Auto-update is deliberately NOT here** (dig_ecosystem#2293). It wanted a twelfth top-level row,
    // and `the_top_level_menu_stays_short_in_every_state` asks which of the eleven a new one replaces —
    // the answer is none of them, so it lives in the window's Settings tab instead. That costs nothing
    // real on the hosts this menu is the whole surface for: neither macOS nor a headless Linux session
    // can raise the elevation prompt the change needs (see `crate::auto_update::elevated_command`), so
    // the honest interface there is the beacon's own CLI, which those machines already have.
    rows.push(MenuRow::Separator);
    // The two escapes, always clickable: whatever else has gone wrong, a person can read the logs and
    // leave (§6.1 "never trap the user").
    rows.push(MenuRow::action(
        TrayAction::OpenLogs,
        "Open the log folder",
        true,
    ));
    rows.push(MenuRow::action(TrayAction::Quit, "Quit DIG", true));
    MenuModel { rows }
}

/// The ONE thing the account needs from the user right now, or `None` when it needs nothing.
///
/// `None` is the ordinary case — an unlocked, working account has no outstanding demand, and inventing a row
/// for it would be noise. The states that DO return a row are the ones where the app is otherwise unusable:
/// no account yet, a locked account, and an account that cannot be opened at all.
///
/// This is the row that keeps a first run from being a scavenger hunt. `Set up my DIG Account…` living only
/// inside **Manage Account** would put the single thing a new user must do behind a submenu they have no
/// reason to open.
///
/// # Why `Unlocked` is no longer `None` (dig_ecosystem#2253)
///
/// It used to be: an unlocked, working account owes the user nothing, and inventing a row for it was
/// noise on a menu that had `Lock now` under **Security** anyway. The trim removes Security from the
/// tray, so `None` here would leave the trimmed menu with an EMPTY first slot in the one state most
/// people are in — and no way to lock without opening a window first. `Lock now` fills it, which is
/// also what makes "unlock/lock" literally true of this row.
///
/// The row is therefore present in every state, and the trimmed menu is four rows in every state.
///
/// # `Lock now` must never be trimmed off the top level (dig_ecosystem#2953)
///
/// The idle window is 24 hours, so `Lock now` is the only *immediate* way to re-seal a session short
/// of quitting the app. A future tidy-up that demoted it into a submenu would leave the one escape
/// hatch a click deeper than the state it escapes from;
/// `lock_now_is_offered_at_the_top_level_whenever_the_account_is_unlocked` fails if that happens.
pub(crate) fn urgent_account_row(account: &AccountState) -> Option<MenuRow> {
    match account {
        // The one honestly-disabled row left on the top level, and it names its own reason (rule 3).
        AccountState::Unsupported => Some(MenuRow::action(
            TrayAction::SetUpAccount,
            "Set up my DIG Account (not supported on this system yet)",
            false,
        )),
        AccountState::Absent => Some(MenuRow::action(
            TrayAction::SetUpAccount,
            "Set up my DIG Account…",
            true,
        )),
        AccountState::Locked => Some(MenuRow::action(TrayAction::Unlock, "Unlock…", true)),
        // NOT `Unlock…`: this account opens with no password at all, so the honest offer is to give it
        // one — not to ask for a secret the user has never chosen.
        AccountState::NeedsPassword => Some(MenuRow::action(
            TrayAction::SetAccountPassword,
            "Set a password for my DIG Account…",
            true,
        )),
        // NOT an `Unlock…` row: unlocking is what already failed, so offering it again would be a button
        // guaranteed to fail. The one thing the app can do here is explain and point at the remedy.
        AccountState::Unopenable => Some(MenuRow::action(
            TrayAction::ExplainUnopenable,
            "This account cannot be opened — what to do…",
            true,
        )),
        // Unlocked and working: nothing is owed, so the row offers the one thing a person with a
        // working account routinely wants — see the note above on why this is no longer `None`.
        AccountState::Unlocked { .. } => {
            Some(MenuRow::action(TrayAction::LockNow, "Lock now", true))
        }
    }
}

/// **View Account** — the read-only views of the account. Nothing here changes anything.
///
/// That is the submenu's whole contract, and it is why the destructive verbs are NOT here: a person opening
/// "View" must not find "Remove this account from this computer" one mis-click away.
///
/// The recovery-phrase row is *either* "show it" or "you don't have one" — never both, because offering a
/// disabled "show my recovery phrase" to someone who has none tells them nothing about why (#1800).
///
/// `pub(crate)`: this is a shared rule, not tray-private. A window model built elsewhere in this crate
/// composes the same rows into a tab section rather than re-deriving which recovery-phrase row to show
/// (dig_ecosystem#2253) — the presence/enablement decision above is the contract both containers depend on.
pub(crate) fn view_account_actions(view: &TrayView, account: &AccountState) -> Vec<MenuRow> {
    if !account.exists() {
        // Nothing to view. The DID explainer still applies — it is about the CONCEPT, not this account —
        // and leaving the submenu empty would be a row that opens onto nothing.
        return vec![MenuRow::action(TrayAction::AboutDid, DID_LABEL, true)];
    }
    let mut rows = Vec::new();
    if view.profile_id.is_some() {
        rows.push(MenuRow::action(
            TrayAction::CopyDigId,
            "Copy my DIG ID",
            true,
        ));
    }
    match account {
        // An account that will not open cannot have its phrase read either — the vault is sealed under the
        // same seed. The urgent row already explains the situation, so nothing is added here.
        AccountState::Unopenable => {}
        AccountState::Unlocked { recoverable: false } => rows.push(MenuRow::action(
            TrayAction::FixMissingPhrase,
            "This account has NO recovery phrase — what to do…",
            true,
        )),
        // Locked: the row stays, so the capability is visibly there, and its label names the ONE thing
        // standing in the way — which the enabled `Unlock…` row does. This is one of the two
        // legitimately-disabled rows in the whole surface; see the module docs.
        AccountState::Locked => rows.push(MenuRow::action(
            TrayAction::ShowRecoveryPhrase,
            "Show my recovery phrase (unlock first)",
            false,
        )),
        AccountState::NeedsPassword => rows.push(MenuRow::action(
            TrayAction::ShowRecoveryPhrase,
            "Show my recovery phrase (set a password first)",
            false,
        )),
        // Unlocked WITH a phrase: the full backup surface — view it, copy it, or save it to a file. The
        // copy/save rows are gated identically to the reveal (unlock + a fresh confirm) and each carries
        // its own stark unencrypted-storage warning at the moment it runs (dig_ecosystem#1564).
        AccountState::Unlocked { recoverable: true } => {
            rows.push(MenuRow::action(
                TrayAction::ShowRecoveryPhrase,
                "Show my recovery phrase…",
                true,
            ));
            rows.push(MenuRow::action(
                TrayAction::CopyRecoveryPhrase,
                "Copy my recovery phrase…",
                true,
            ));
            rows.push(MenuRow::action(
                TrayAction::SaveRecoveryPhrase,
                "Save my recovery phrase to a file…",
                true,
            ));
        }
        // Any other state cannot read the phrase, so only the (disabled) view row is shown.
        _ => rows.push(MenuRow::action(
            TrayAction::ShowRecoveryPhrase,
            "Show my recovery phrase…",
            false,
        )),
    }
    rows.push(MenuRow::Separator);
    rows.push(MenuRow::action(TrayAction::AboutDid, DID_LABEL, true));
    rows
}

/// **Profiles** — the account's dig-profiles: which one is in use, and which are shown here
/// (dig_ecosystem#2403).
///
/// # What this builder decides, and what it deliberately does not
///
/// It decides which of the two per-profile verbs each row gets, and it never emits a THIRD verb for
/// creating one. Creating runs through the funding check instead — see
/// [`TrayAction::CreateProfile`], whose label says *funding* precisely because a row cannot promise
/// a creation the wallet may not be able to pay for.
///
/// It does NOT decide how the list is drawn, or which profile a row is ABOUT beyond the index it
/// carries. The pane reads the profiles themselves from
/// [`TrayView::profiles`] and matches each verb to its row by that index, exactly as the Content
/// tab matches a cache preset by its byte count.
///
/// # The two verbs, and the states each is withheld in
///
/// * **Use this profile** is emitted for every profile that is not already active. Withheld from the
///   active one because there is nothing for it to change; the list says which one that is.
/// * **Hide / show** is emitted for every profile EXCEPT the active one, because dig-account refuses
///   to hide the active profile (`AccountError::ActiveProfileCannotBeHidden`). A row offered there
///   would be a control that reports a refusal from the crate underneath, which is the dead end
///   #1800 removed — and the way to hide that profile, switching away from it first, is the row
///   directly beside it.
///
/// Nothing is emitted at all until the list has been READ. A verb built from
/// [`ProfilesReading::Pending`](crate::profiles::ProfilesReading::Pending) would be a control acting
/// on a profile nobody has confirmed exists.
/// **Profile editing** — the one verb that publishes what a person typed (dig_ecosystem#2993).
///
/// # What this builder decides
///
/// Whether the verb EXISTS, from one reading. It does not decide whether the control can be pressed
/// at this instant: that depends on whether anything has been typed, which is form state the window
/// owns and no menu can see. The pane draws the row it is given and disables it while the form has
/// nothing to publish — narrowing the model's answer, never widening it.
///
/// # Why the row is absent rather than greyed when editing is impossible
///
/// The card explains the missing piece in a sentence with room for it, which a menu row does not
/// have. A permanently-greyed *Publish my profile changes* row that cannot say when it will work is
/// the dead end dig_ecosystem#1800 removed.
pub(crate) fn profile_edit_actions(view: &TrayView) -> Vec<MenuRow> {
    if !view.profile_editing.is_possible() {
        return Vec::new();
    }
    // Publishing puts the user's identity on what they publish, so it is one of the verbs
    // `Allowance` governs (dig_ecosystem#2350). Until this wiring, the policy existed and no surface
    // asked it, which made "a DID is required to use dig-app" a rule the app stated and did not
    // apply.
    match Allowance::of_did(view.did.as_deref(), Capability::Publish) {
        Allowance::Allowed => vec![MenuRow::action(
            TrayAction::PublishProfileEdits,
            PUBLISH_PROFILE_LABEL,
            true,
        )],
        // Present and disabled rather than absent, because here the missing piece HAS a name and a
        // one-click remedy sitting in the same menu — which is precisely what the greyed rows #1800
        // removed could not offer.
        Allowance::NeedsDid => vec![MenuRow::action(
            TrayAction::PublishProfileEdits,
            PUBLISH_PROFILE_NEEDS_DID_LABEL,
            false,
        )],
    }
}

/// The publish control's label. Names what pressing it DOES — see [`TrayAction::PublishProfileEdits`]
/// for why it is not called *save*.
pub const PUBLISH_PROFILE_LABEL: &str = "Publish my profile changes…";

/// The publish control's label when no DID has been minted. Names the REMEDY, not the refusal.
pub const PUBLISH_PROFILE_NEEDS_DID_LABEL: &str =
    "Publish my profile changes (set up your DIG identity first)";

pub(crate) fn profile_actions(view: &TrayView) -> Vec<MenuRow> {
    let mut rows: Vec<MenuRow> = view
        .profiles
        .rows()
        .unwrap_or_default()
        .iter()
        .flat_map(|profile| match profile.active {
            true => Vec::new(),
            false => vec![
                MenuRow::action(
                    TrayAction::SetActiveProfile { ix: profile.ix.0 },
                    format!("Use {} for this account…", profile.display_name()),
                    true,
                ),
                MenuRow::action(
                    TrayAction::SetProfileVisibility {
                        ix: profile.ix.0,
                        hidden: !profile.hidden,
                    },
                    match profile.hidden {
                        true => format!("Show {} in this list", profile.display_name()),
                        false => format!("Hide {} from this list", profile.display_name()),
                    },
                    true,
                ),
            ],
        })
        .collect();
    // Delete is offered for EVERY profile, the active one included. Withholding it there would trap
    // the account that holds exactly one profile — nothing to switch to, so nothing could ever be
    // deleted — which is the dead end `professional-ui`'s never-trap rule forbids. What happens to
    // the active pointer afterwards is the shell's, and it is defined: it moves to the lowest
    // remaining profile, or the account is left with none, which the card already renders honestly.
    //
    // Keyed on the ARM, never on `blocked().is_none()`: an unmeasured build answers `None` there
    // too, and this row leads to a spend that cannot be undone.
    if view.profile_deletion.is_possible() {
        rows.extend(
            view.profiles
                .rows()
                .unwrap_or_default()
                .iter()
                .map(|profile| {
                    MenuRow::action(
                        TrayAction::DeleteProfile { ix: profile.ix.0 },
                        format!("Delete {} permanently…", profile.display_name()),
                        true,
                    )
                }),
        );
    }
    // Keyed on the ARM. `blocked().is_none()` answers `None` for `Unknown` too, and offering this
    // against a node nobody has spoken to is the fail-open direction on a path that leads to a
    // money window (dig_ecosystem#2690).
    if view.profile_creation.is_possible() {
        rows.push(MenuRow::action(
            TrayAction::CreateProfile,
            CREATE_PROFILE_LABEL,
            true,
        ));
    }
    if !rows.is_empty() {
        rows.push(MenuRow::Separator);
    }
    rows.push(MenuRow::action(
        TrayAction::AboutProfiles,
        PROFILES_LABEL,
        true,
    ));
    rows
}

/// The explainer row's label. Names the concept a person is about to read about, and — per rule 3 —
/// promises an explanation rather than an act.
pub const PROFILES_LABEL: &str = "About DIG profiles…";

/// The create control's label.
///
/// Names what pressing it DOES today — open the funding check — rather than the subject it belongs
/// to. See [`TrayAction::CreateProfile`] for why the verb is narrower than the card's heading, and
/// dig_ecosystem#2952 for the change that widens it.
pub const CREATE_PROFILE_LABEL: &str = "Set up funding for a profile…";

/// **Wallet** — what the account can do with money, which today is receive and understand.
///
/// # The address row
///
/// A receive address is PUBLIC, so a locked account is not a reason to drop the row — it is a reason to
/// say so, and the label names the ONE thing in the way (rule 3), with the enabled `Unlock…` row sitting
/// in Security as the remedy.
///
/// Two states have no row at all rather than a permanently-greyed one. With NO account there is no key
/// to derive from and nothing to wait for, so [`AboutWallet`](TrayAction::AboutWallet) explains it in a
/// window with room; with an UNOPENABLE account the key is unreachable and its urgent top-level row
/// already gives the remedy. In both, a greyed row that could not say when it would work is exactly the
/// dead end #1800 removed.
///
/// # Why there is no `Send`
///
/// A menu cannot hold a form, and an amount is not something a person picks from a list — so spending is
/// not offered *at all* from this menu. [`Send`](Self::Send) is emitted by the Wallet pane and
/// never by a tray row. [`AboutWallet`](TrayAction::AboutWallet) explains the situation in a window
/// that has room for it.
///
/// The same reasoning already governs DIDs ([`AboutDid`](TrayAction::AboutDid)): the tray does not offer
/// verbs the app cannot perform.
///
/// # The balance row
///
/// "What do I hold?" is half of what a wallet is for, so the answer belongs on the menu rather than one
/// click into a window. It is ALWAYS present and ALWAYS enabled: it renders the reading
/// [`crate::wallet::node::NodeBalance`] polled from the node — a figure when the node answered with
/// one, and otherwise the node's OWN reason (`Balance not known — your node has no chain connection
/// yet…`, `…DIG could not reach a node…`, `…this node cannot read balances yet…`). Whichever it is, the
/// sentence is honest content rather than a placeholder. Its label carries the short reason and
/// clicking it opens the window
/// with the full one, which is how the **Cache** submenu's disconnected row behaves for the same
/// reason: an enabled row that states the situation, never a greyed one the user must guess at (#1800).
///
/// It shares [`AboutWallet`](TrayAction::AboutWallet) with the explainer below it — as the Cache
/// submenu's two rows share [`AboutCache`](TrayAction::AboutCache) — because the window they open is
/// genuinely the same one, and inventing a second action that did the identical thing would put the
/// duplication in the shell instead of admitting it here.
///
/// The row is what makes the no-account case say something. With no account the address row is
/// (rightly) absent, and a submenu holding only `My wallet…` makes a person click to be told there is
/// nothing — so the balance row names that state on the menu itself.
///
/// `pub(crate)`: shared with the window model's Wallet tab (dig_ecosystem#2253) — which rows appear and
/// whether the address row is enabled is decided HERE, once, for both containers.
pub(crate) fn wallet_actions(view: &TrayView, account: &AccountState) -> Vec<MenuRow> {
    let mut rows = Vec::new();
    if account.exists() && !matches!(account, AccountState::Unopenable) {
        rows.push(match &view.receive_address {
            Some(_) => MenuRow::action(
                TrayAction::CopyReceiveAddress,
                "Copy my receive address",
                true,
            ),
            // The reason differs by state, and naming the wrong remedy is as much a dead end as naming
            // none: an account that has never had a password cannot be "unlocked", it must be given one.
            None => MenuRow::action(
                TrayAction::CopyReceiveAddress,
                match account {
                    AccountState::NeedsPassword => "Copy my receive address (set a password first)",
                    _ => "Copy my receive address (unlock first)",
                },
                false,
            ),
        });
    }
    rows.push(MenuRow::action(
        TrayAction::AboutWallet,
        {
            // ONE overview, so the figure and the peak it is judged against come from the same
            // snapshot. Reading them separately could mark a figure current on the strength of a
            // peak observed after it.
            let overview = crate::wallet::overview::WalletOverview::of_tray(view);
            crate::wallet::overview::menu_balance_label(&overview.balance, overview.peers_peak)
        },
        true,
    ));
    rows.push(MenuRow::Separator);
    rows.push(MenuRow::action(TrayAction::AboutWallet, "My wallet…", true));
    rows
}

/// **Security** — locking, and the custody-state explainers.
///
/// Separate from **Manage Account** because the two answer different questions. Security is *is my account
/// safe right now*; Manage is *I want a different account*. Putting `Lock now` beside `Remove this account
/// from this computer` would be a menu where the routine and the irreversible sit together, which is how a
/// mis-click becomes a loss.
///
/// `pub(crate)`: shared with the window model's Security tab (dig_ecosystem#2253) — the lock/unlock row
/// and the two-factor offer are decided by account state alone, so both containers read the same verdict.
pub(crate) fn security_actions(
    account: &AccountState,
    second_factor: bool,
    did: Option<&str>,
) -> Vec<MenuRow> {
    match account {
        AccountState::Unlocked { .. } => {
            let mut rows = vec![MenuRow::action(TrayAction::LockNow, "Lock now", true)];
            rows.extend(two_factor_row(true, second_factor));
            rows.push(MenuRow::Separator);
            rows.extend(paired_app_rows(did));
            rows
        }
        AccountState::Locked => {
            let mut rows = vec![MenuRow::action(TrayAction::Unlock, "Unlock…", true)];
            rows.extend(two_factor_row(false, second_factor));
            rows
        }
        AccountState::Unopenable => {
            let mut rows = vec![MenuRow::action(
                TrayAction::ExplainUnopenable,
                "This account cannot be opened — what to do…",
                true,
            )];
            rows.extend(two_factor_row(false, second_factor));
            rows
        }
        // Not `Unlock…`: this account opens with no password at all, so the honest offer is to give it
        // one. It passes `unlocked: false` to the two-factor row for the same reason `Locked` does —
        // enrolling a second factor seals a record under the account's DEK, which needs the account
        // open, and the row directly above is what opens it.
        AccountState::NeedsPassword => {
            let mut rows = vec![MenuRow::action(
                TrayAction::SetAccountPassword,
                "Set a password for my DIG Account…",
                true,
            )];
            rows.extend(two_factor_row(false, second_factor));
            rows
        }
        // No account to lock or unlock. Saying so beats an empty submenu or a greyed verb with no reason.
        AccountState::Absent | AccountState::Unsupported => vec![MenuRow::action(
            TrayAction::ShowStatus,
            "No account on this computer yet — see Status",
            true,
        )],
    }
}

/// The ONE two-factor row for the Security submenu, or `None` when there is nothing honest to offer.
///
/// The row is EITHER "set up" or "turn off" — never both, and never a greyed one of each. A row that
/// names the thing it will do needs no explanation, and offering the verb the account is not in a state
/// for is the greyed-row failure dig_ecosystem#1800 removed.
///
/// # Why "turn off" is offered even while the account is LOCKED
///
/// Setting a factor up seals a record under the account's key, so it genuinely needs an unlocked
/// account. Turning one off only deletes that record, and it is authorized by the platform biometric
/// rather than by the account — so it can run in any state.
///
/// That asymmetry is load-bearing rather than incidental. A second factor blocks the destructive verbs,
/// and an account that CANNOT BE OPENED AT ALL ([`AccountState::Unopenable`]) can never answer a
/// challenge. If "turn off" needed an unlock, such an account would be permanently unreplaceable and
/// unremovable — the trap §6.1 forbids, created by the very feature meant to protect it. Offering the
/// row here is the way out.
fn two_factor_row(unlocked: bool, second_factor: bool) -> Option<MenuRow> {
    match (second_factor, unlocked) {
        (true, _) => Some(MenuRow::action(
            TrayAction::TurnOffTwoFactor,
            "Turn off two-factor codes…",
            true,
        )),
        (false, true) => Some(MenuRow::action(
            TrayAction::SetUpTwoFactor,
            "Set up two-factor codes…",
            true,
        )),
        // Nothing enrolled and no unlocked account to enrol under. The `Unlock…` row directly above is
        // the remedy, so its absence is not a dead end.
        (false, false) => None,
    }
}

/// The two paired-app rows for the Security submenu (dig_ecosystem#1848).
///
/// Both are offered ONLY while the account is unlocked, so this returns them as a pair rather than
/// leaving each caller to remember the condition. A locked account sees no row at all, and the
/// `Unlock…` row above it is the way forward (#1800).
///
/// # Pairing is the SIGN surface, so it is gated on a DID (dig_ecosystem#2350)
///
/// Every capability a pairing can grant is identity-bearing — `identity.attest`, `identity.seal`,
/// `identity.unseal` ([`crate::pairing::Capability`]) — which is [`Capability::SignForAnApp`] and
/// [`Capability::Message`] in the app's own vocabulary. Pairing an app before an identity exists
/// hands out permissions over an identity that does not, so the door itself is what the policy gates
/// rather than each method behind it.
///
/// **`Paired apps…` is NEVER gated.** It is where a pairing is REVOKED, and a person who somehow
/// holds one must always be able to take it back; gating the way out is the trap `professional-ui`
/// forbids.
fn paired_app_rows(did: Option<&str>) -> Vec<MenuRow> {
    let pairing = match Allowance::of_did(did, Capability::SignForAnApp) {
        Allowance::Allowed => MenuRow::action(TrayAction::PairAnApp, "Pair an app…", true),
        Allowance::NeedsDid => {
            MenuRow::action(TrayAction::PairAnApp, PAIR_AN_APP_NEEDS_DID_LABEL, false)
        }
    };
    vec![
        pairing,
        MenuRow::action(TrayAction::ManagePairedApps, "Paired apps…", true),
    ]
}

/// The pairing control's label when no DID has been minted. Names the REMEDY, not the refusal.
pub const PAIR_AN_APP_NEEDS_DID_LABEL: &str = "Pair an app (set up your DIG identity first)";

/// The `Manage my DIG Account` submenu — **reachable in every state**, which is the whole point.
///
/// Before #1800, `Set up` and `Restore` were enabled only while `account == Absent`, so the machine this
/// was measured on — which had an account with no recovery phrase — offered setup greyed, restore greyed,
/// show-phrase greyed, and a single explainer whose advice ("create a new account") named a control that
/// was greyed out. Four dead rows and no way forward.
///
/// The verbs here are therefore gated on their REAL precondition — whether an account exists, which
/// decides whether the verb CREATES or REPLACES — never on it being absent.
///
/// `pub(crate)`: shared with the window model's Account tab (dig_ecosystem#2253) — the create-vs-replace
/// choice lives here so both containers offer the same verbs for the same account.
pub(crate) fn management_actions(account: &AccountState) -> Vec<MenuRow> {
    // A host with no credential store can neither create nor destroy an account, so the submenu holds
    // only what it can actually deliver: the explanation.
    if !account.supported() {
        return vec![MenuRow::action(TrayAction::AboutDid, DID_LABEL, true)];
    }
    let mut rows = if account.exists() {
        vec![
            MenuRow::action(
                TrayAction::ReplaceWithNewAccount,
                "Replace this account with a NEW one…",
                true,
            ),
            MenuRow::action(
                TrayAction::ReplaceFromPhrase,
                "Replace it with an account from a recovery phrase…",
                true,
            ),
            MenuRow::action(
                TrayAction::RemoveAccount,
                "Remove this account from this computer…",
                true,
            ),
        ]
    } else {
        // With no account there is nothing to REPLACE, so the verbs read plainly as create and restore.
        //
        // `Set up` is repeated here even though `urgent_account_row` also offers it on the top level, and
        // that repetition is deliberate: the top-level row is the first-run signpost, while this submenu is
        // where a person goes when they have decided to *manage* their account and expect to find both ways
        // of getting one. `Restore` has NO other home — it used to sit on the top level beside `Set up`, and
        // dropping it here silently would strand every user with an existing recovery phrase.
        vec![
            MenuRow::action(TrayAction::SetUpAccount, "Set up a new DIG Account…", true),
            MenuRow::action(
                TrayAction::RestoreFromPhrase,
                "Restore from a recovery phrase…",
                true,
            ),
        ]
    };
    if !rows.is_empty() {
        rows.push(MenuRow::Separator);
    }
    rows.push(MenuRow::action(TrayAction::AboutDid, DID_LABEL, true));
    rows
}

/// The **Apps** submenu — other DIG apps this install can open (dig_ecosystem#2101).
///
/// Data-driven from [`crate::apps::APPS`]: a second app (dig-email, dig-video-chat — §5.4) is a
/// registry row, not new code here. Every row is ENABLED, because clicking it always DOES something
/// visible — it either launches the app or shows the honest "not available yet" notice — never a
/// greyed dead end or a silent no-op (#1800, §6.1). The launch-vs-notice choice is the shell's, made
/// through the pure [`crate::apps::plan_launch`] seam; the menu only says the app exists to be opened.
///
/// `pub(crate)`: shared with the window model's Apps tab (dig_ecosystem#2253) — one registry read,
/// composed into whichever container is rendering.
pub(crate) fn apps_actions() -> Vec<MenuRow> {
    crate::apps::APPS
        .iter()
        .map(|app| MenuRow::action(TrayAction::LaunchApp(app.id), app.display_name, true))
        .collect()
}

/// The `Open URL…` row, carrying the global shortcut when there IS one.
///
/// A shortcut nobody can discover is a shortcut nobody uses, and a tray menu is the one place every user
/// of this app already looks. The chord is appended ONLY when it is live — advertising a chord that failed
/// to register would teach the user to press a key that does nothing (see
/// [`HotkeyState::shortcut`](crate::hotkey::HotkeyState::shortcut)).
fn open_url_label(view: &TrayView) -> String {
    match view.hotkey.as_ref().and_then(|state| state.shortcut()) {
        Some(hotkey) => format!("Open URL…\t{hotkey}"),
        None => "Open URL…".to_string(),
    }
}

/// The **Cache** submenu's parent label, carrying the live usage against the cap.
///
/// Putting the figure in the parent label is what lets the tray SHOW usage-against-cap without a
/// display-only disabled row (SPEC §3.1c forbids one): a submenu parent is an action — it opens — so
/// the number rides on something clickable. When no node is connected there are no live figures, so
/// the label says exactly that rather than showing a stale or invented number.
pub(crate) fn cache_label(cache: Option<&crate::cache::CacheSnapshot>) -> String {
    use crate::cache::format_cap;
    match cache {
        Some(snapshot) => format!(
            "Cache — {} of {} used",
            format_cap(snapshot.used_bytes),
            format_cap(snapshot.cap_bytes)
        ),
        None => "Cache — node not connected".to_string(),
    }
}

/// The **Cache** submenu — the size-limit presets, a custom option, and the honest explainer.
///
/// # The four async states (§6.4)
///
/// The node's cache figures come from a live connection, so this surface has the same loading /
/// error / empty / success shape every async view does. All of them collapse to two honest cases
/// here: with a snapshot (`Some`), the presets and the custom option are offered and the current cap
/// is marked; without one (`None` — no node reached yet, or a node that stopped), the change rows are
/// omitted and a single enabled row explains that a connected node is needed. That row is NOT a
/// disabled dead end — clicking it opens the same explainer, so the user always learns why (#1800).
/// The explainer itself is offered in every state because it is about the concept, not the live node.
///
/// `pub(crate)`: shared with the window model's Cache tab (dig_ecosystem#2253) — the same async-state
/// collapse applies whichever container is asking.
pub(crate) fn cache_actions(cache: Option<&crate::cache::CacheSnapshot>) -> Vec<MenuRow> {
    let mut rows = Vec::new();
    match cache {
        Some(snapshot) => {
            for &bytes in &crate::cache::CACHE_PRESETS {
                rows.push(MenuRow::action(
                    TrayAction::SetCacheCap { bytes },
                    cache_preset_label(bytes, snapshot.cap_bytes),
                    true,
                ));
            }
            rows.push(MenuRow::action(
                TrayAction::SetCustomCacheCap,
                "Custom size…",
                true,
            ));
        }
        // No node to read from or change: never a silent no-op. One enabled row states the
        // precondition and routes to the explainer, so the surface still does something visible.
        None => rows.push(MenuRow::action(
            TrayAction::AboutCache,
            "Change the size limit (connect a node first)…",
            true,
        )),
    }
    rows.push(MenuRow::Separator);
    rows.push(MenuRow::action(
        TrayAction::AboutCache,
        "About the cache and your privacy…",
        true,
    ));
    rows
}

/// The **Auto-update** group's heading — whether DIG updates itself, and which feed it follows
/// (dig_ecosystem#2293).
///
/// The heading carries the fact, exactly as [`cache_label`] does, so the group answers the question a
/// person opened it to ask before they read a single row. It reports the beacon's OBSERVED state, never
/// the remembered preference: an administrator can pause updates without dig-app being involved, and a
/// heading that echoed dig-app's own wish would then be confidently wrong.
pub(crate) fn auto_update_label(update: Option<&crate::auto_update::BeaconStatus>) -> String {
    match update {
        Some(status) if status.updates_are_live() => format!(
            "Auto-update — on, following the {} channel",
            status.channel.display_name()
        ),
        // Named apart from an ordinary pause, because the remedy is different and the user is entitled
        // to know WHICH thing is off. "Off" alone would have them looking for a pause to lift on a
        // machine whose daily check is simply not there (dig_ecosystem#2324).
        Some(status) if status.schedule_opted_out => {
            "Auto-update — off, the daily check was removed from this computer".to_string()
        }
        Some(status) => format!(
            "Auto-update — off, {} channel selected",
            status.channel.display_name()
        ),
        // Just the group's name. The pane note directly above already says the updater could not be
        // asked and what to do about it, and a heading repeating it made the screenshot state the
        // same fact three times in four lines — the panel, the heading, and the row's own "(install
        // the DIG updater first)".
        None => "Auto-update".to_string(),
    }
}

/// The **Auto-update** group — turn updates on or off, and choose which feed to follow
/// (dig_ecosystem#2293).
///
/// # The four async states (§6.4)
///
/// The beacon's state is read from a separate program, so this surface has the same shape every async
/// view does, and it collapses to the same two honest cases [`cache_actions`] uses. With a status
/// (`Some`), the on/off row and both channel rows are offered and the channel in force is marked.
/// Without one (`None` — no beacon installed, or one that would not answer), the change rows are
/// omitted and a single ENABLED row explains what is missing. That row is not a disabled dead end:
/// clicking it opens the explainer, so the user always learns why (#1800). The explainer is offered in
/// every state because it is about the concept, not this machine's beacon.
///
/// # Why the on/off control is one row and not two
///
/// The cache presets are six mutually-exclusive values, so they render as six rows with the active one
/// marked. On and off are not six values — they are a state and its opposite — and a pair of rows
/// where one is always a no-op reads as a control that half-works. One row that names the state it
/// moves TO says what the click does, which is what a menu row is for.
///
/// `pub(crate)`: shared with the window model's Settings tab, so the tray and the window cannot
/// disagree about what auto-update is doing.
pub(crate) fn auto_update_actions(
    update: Option<&crate::auto_update::BeaconStatus>,
) -> Vec<MenuRow> {
    use crate::auto_update::{Change, UpdateChannel};

    let mut rows = Vec::new();
    match update {
        Some(status) => {
            // What the click must DO is derived from the beacon's own account of what is stopping
            // updates, not from a single flag: `resume` is the right command for a pause and the wrong
            // one for a removed schedule (dig_ecosystem#2324).
            let action = match status.blocking_updates() {
                None => TrayAction::SetAutoUpdate { enabled: false },
                Some(Change::Enable(_)) => TrayAction::SetAutoUpdate { enabled: true },
                Some(Change::RearmSchedule) => TrayAction::RearmUpdateSchedule,
                // Unreachable: `blocking_updates` answers with a way to turn updates ON, and a channel
                // switch is not one. Mapped rather than matched exhaustively away so a future variant
                // is a compile error here instead of a silently wrong row.
                Some(Change::Channel { .. }) => TrayAction::AboutAutoUpdate,
            };
            rows.push(MenuRow::action(
                action,
                auto_update_toggle_label(status.updates_are_live()),
                true,
            ));
            rows.push(MenuRow::Separator);
            for channel in UpdateChannel::ALL {
                rows.push(MenuRow::action(
                    TrayAction::SetUpdateChannel(channel),
                    channel_row_label(channel, status.channel),
                    true,
                ));
            }
        }
        // No beacon to read from or change — never a silent no-op. One enabled row states the
        // precondition and routes to the explainer, so the surface still does something visible.
        None => rows.push(MenuRow::action(
            TrayAction::AboutAutoUpdate,
            "Change auto-update (install the DIG updater first)…",
            true,
        )),
    }
    rows.push(MenuRow::Separator);
    rows.push(MenuRow::action(
        TrayAction::AboutAutoUpdate,
        "About auto-update and channels…",
        true,
    ));
    rows
}

/// The on/off row's label, naming the state the click moves TO and the cost of getting there.
///
/// The elevation is in the label rather than discovered at the prompt for the same reason a disabled
/// row must name its remedy: a control whose real cost is only revealed after it is clicked is a
/// surprise, and a user who would have declined has already been interrupted. Changing machine-wide
/// update policy needs an administrator on every OS DIG ships on — see [`crate::auto_update`].
fn auto_update_toggle_label(enabled_now: bool) -> String {
    match enabled_now {
        true => "Turn auto-update off (asks for administrator)…".to_string(),
        false => "Turn auto-update on (asks for administrator)…".to_string(),
    }
}

/// One channel row's label: the name, what it means, and — for the one in force — that it is current.
///
/// The mark is the WORD "current" rather than a tick, for the reason [`cache_preset_label`] records:
/// the window draws these labels in a font with no U+2713, so a glyph would photograph as a tofu box
/// beside the very row a person is looking for.
fn channel_row_label(
    channel: crate::auto_update::UpdateChannel,
    current: crate::auto_update::UpdateChannel,
) -> String {
    let mark = match channel == current {
        true => " — current",
        false => "",
    };
    format!(
        "{} — {}{mark}",
        channel.display_name(),
        channel.description()
    )
}

/// One preset row's label, marking the preset that is the node's CURRENT cap so the active choice is
/// visible at a glance, and tagging the default so a person can find it deliberately.
///
/// # Why the mark is a word and not a tick
///
/// It was `✓ current`. The tray got that glyph from the operating system's own menu font; the app
/// window (dig_ecosystem#2253) draws the SAME label in the Space Grotesk stack, which has no U+2713 —
/// so the gallery photographed a tofu box beside the active cap, and the one row a person is looking
/// for was the one marked with a rendering error. A word needs no glyph coverage anywhere, and it is
/// what a screen reader would have had to say regardless: this file's own chrome already prefers "a
/// word, not a glyph" for exactly that reason.
fn cache_preset_label(bytes: u64, current_cap: u64) -> String {
    use crate::cache::{format_cap, DEFAULT_CACHE_CAP_BYTES};
    let mut label = format_cap(bytes);
    if bytes == DEFAULT_CACHE_CAP_BYTES {
        label.push_str(" (default)");
    }
    if bytes == current_cap {
        label.push_str(" — current");
    }
    label
}

/// The DID explainer's label.
///
/// It names the cost rather than hiding it in the dialog, so a person knows before they open it that a
/// DID is a real spend (§3.7 — mainnet is real money). It deliberately no longer says "optional": a DID
/// is the bedrock of a DIG Account (dig_ecosystem#1820), and calling it optional was the copy that made a
/// required step look like a nicety. It must not promise to CREATE one from here: this build has no
/// chain transport to mint over (`SPEC.md` §3.1b), so the row explains rather than offers.
const DID_LABEL: &str = "About on-chain DIDs (required, costs XCH)…";

/// The DID line. Absent is the state of every account on this build — the mint is implemented and
/// proven, but nothing here can reach a chain to run it (`SPEC.md` §3.1b) — so it names the remaining
/// step AND why it cannot be taken, rather than reading as something the user has neglected
/// (dig_ecosystem#1820).
fn did_label(did: Option<&str>) -> String {
    did.unwrap_or("not created yet — on-chain minting is not available in this version")
        .to_string()
}

/// A DIG ID abbreviated for display beside a full copy. The full value goes to the clipboard and into
/// the details window; this is for anywhere a 96-character hex key would not fit.
pub fn short_dig_id(profile_id: &str) -> String {
    if profile_id.len() > 16 {
        format!(
            "{}…{}",
            &profile_id[..8],
            &profile_id[profile_id.len() - 8..]
        )
    } else {
        profile_id.to_string()
    }
}

/// What to tell a user whose tray icon never appeared, for `os`, given the shell's `reason`.
///
/// # Why this exists (an invisible failure is the worst kind)
///
/// On Linux the AppIndicator library is **dlopened, not linked**, so on a desktop without
/// `libayatana-appindicator3-1` the process starts, reports itself healthy, and the icon simply never
/// appears. The user is left with an app that is running and unreachable — and every account surface
/// (setup, the recovery phrase, unlock) lives behind that icon.
///
/// So a tray that fails to mount MUST say so somewhere a person will find, name the likely cause, and
/// point at the way in that still works. This function is that message; it is pure so the wording is
/// tested rather than trusted.
pub fn tray_unavailable_advice(reason: &str, os: crate::Os) -> String {
    let cause = match os {
        // The overwhelmingly common cause, and one the user can act on in one command.
        crate::Os::Linux => {
            "\n\nOn Linux this is almost always a missing system tray library. Install \
             `libayatana-appindicator3-1` (Debian/Ubuntu) or `libappindicator-gtk3` (Fedora), then \
             start DIG again. Some desktops (GNOME) also need a tray extension such as \
             AppIndicator Support."
        }
        crate::Os::Windows | crate::Os::MacOs => "",
    };
    format!(
        "DIG is running, but its menu-bar icon could not be shown ({reason}), so the DIG menu is \
         not reachable on this desktop.{cause}\n\nRestart DIG once that is fixed — every account \
         action lives in the DIG menu."
    )
}

impl fmt::Display for AccountState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            AccountState::Unsupported => "not available on this system yet",
            AccountState::Absent => "not set up yet",
            AccountState::Locked => "locked",
            AccountState::Unopenable => "cannot be opened on this computer",
            AccountState::NeedsPassword => {
                "needs a password — anyone using this computer can open it"
            }
            AccountState::Unlocked { recoverable: true } => "unlocked",
            AccountState::Unlocked { recoverable: false } => "unlocked — NO recovery phrase",
        };
        f.write_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Every field of [`TrayView`] forces a repaint when it changes.**
    ///
    /// [`TrayView::renders_same_as`] is the shell's entire repaint gate: a `true` skips the rebuild
    /// and the tray keeps drawing the previous menu. A field it fails to compare freezes whatever that
    /// field controls until something ELSE happens to move — and if nothing else moves, permanently.
    ///
    /// This is a table over every field rather than a case for the interesting ones, because the
    /// failure has now happened three times on three different fields (#2206 balance, #2002 cache,
    /// dig-app#86 menu_suppressed) and a fourth time on `window_host`, where it made the tray trim
    /// irreversible: the window failed to open, the host degraded to `Unavailable` so the tray could
    /// re-expand, and the gate discarded the change — leaving four rows and no way back to
    /// `RemoveAccount`, `FixMissingPhrase` or `OpenLogs` (dig_ecosystem#2253).
    ///
    /// Each case moves ONE field off its default and asserts the two snapshots do not compare equal.
    /// The exhaustive destructure in `renders_same_as` stops a NEW field being forgotten; this stops a
    /// listed one being compared wrongly.
    #[test]
    fn every_field_of_the_view_forces_a_repaint_when_it_changes() {
        let base = TrayView::default();
        /// One field's name and a change to it that the tray must notice.
        type FieldChange = (&'static str, fn(&mut TrayView));

        let cases: Vec<FieldChange> = vec![
            ("running", |v| v.running = true),
            ("node_connected", |v| v.node_connected = true),
            ("node", |v| v.node = "dig.local".to_string()),
            ("account", |v| v.account = Some(AccountState::Locked)),
            ("profile_id", |v| v.profile_id = Some("dig1x".to_string())),
            ("receive_address", |v| {
                v.receive_address = Some("xch1x".to_string())
            }),
            ("address_fault", |v| {
                v.address_fault = Some(AddressFault::DerivationFailed)
            }),
            ("balance", |v| {
                v.balance = crate::wallet::overview::BalanceReading::Known {
                    balances: crate::wallet::overview::Balances::of_xch_and_dig(1, 0),
                    as_of: crate::wallet::engine::BalanceAsOf::Replica {
                        height: 7_000_000,
                        caught_up: true,
                    },
                }
            }),
            ("did", |v| v.did = Some("did:chia:x".to_string())),
            ("second_factor", |v| v.second_factor = true),
            ("cache", |v| {
                v.cache = Some(crate::cache::CacheSnapshot {
                    cap_bytes: 1,
                    used_bytes: 0,
                })
            }),
            ("hotkey", |v| {
                v.hotkey = Some(crate::hotkey::HotkeyState::Unavailable {
                    hotkey: Default::default(),
                    reason: "taken".to_string(),
                })
            }),
            ("menu_suppressed", |v| v.menu_suppressed = true),
            ("window_host", |v| v.window_host = WindowHost::Unavailable),
            // Absent from this table until dig_ecosystem#2330 despite `renders_same_as` comparing
            // it: the destructure guarantees a new field is DECIDED about, not that a case is added
            // here, and this one was decided and then never pinned. The count assertion below could
            // not catch it, because it was written from the table rather than from the struct.
            ("update", |v| {
                v.update = Some(crate::auto_update::BeaconStatus {
                    paused: true,
                    schedule_opted_out: false,
                    channel: crate::auto_update::UpdateChannel::Stable,
                })
            }),
            ("node_facts", |v| v.node_facts = Some(fixture_node_facts())),
            ("hosted_stores", |v| {
                v.hosted_stores = crate::hosted_stores::HostedStoresReading::Known(Vec::new())
            }),
            ("installed_apps", |v| {
                v.installed_apps = crate::apps::AppPresence::Known(Vec::new())
            }),
            ("enrolment", |v| {
                v.enrolment = crate::wallet::enrol::Enrolment::Registered
            }),
            ("network", |v| {
                v.network.dig_peers = crate::network::PeerCount::Known(6)
            }),
            // A reading that moved from unmeasured to measured changes what the DID explainer says,
            // so a view that did not repaint would keep showing "DIG has not yet been able to ask
            // your node" after the node had answered (dig_ecosystem#2398).
            ("mint_chain", |v| {
                v.mint_chain = Some(crate::account::profile_mint::ChainReadiness::WalksLineages)
            }),
        ];

        for (field, mutate) in &cases {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert!(
                !base.renders_same_as(&changed),
                "`{field}` changed and the tray would NOT repaint — whatever it controls is frozen \
                 until some other field happens to move"
            );
            // Symmetric, so a comparison that only reads one side is caught too.
            assert!(
                !changed.renders_same_as(&base),
                "`{field}` is compared in one direction only"
            );
        }

        // The table is only a guard if it is complete. `renders_same_as` destructures exhaustively, so
        // the field count is fixed at compile time; this pins the table to it.
        assert_eq!(
            21,
            cases.len(),
            "TrayView gained or lost a field — add or remove its case above"
        );
        assert!(
            base.renders_same_as(&base.clone()),
            "an unchanged view must not force a repaint, or the tray rebuilds on every tick"
        );
    }

    /// **The other half of the repaint contract: no field may move on every tick**
    /// (dig_ecosystem#2330).
    ///
    /// The table above pins that a changed field repaints. This pins the converse for the one field
    /// whose SOURCE changes every second — the node's `uptime_secs`. If the bucketing lived in the
    /// renderer instead of at the seam, the view would differ on every tick and the window would
    /// rebuild twice a second forever, showing a figure that had not visibly changed.
    ///
    /// The assertion is made through `renders_same_as` rather than on `NodeFacts` alone, because the
    /// property under test is a PLACEMENT — bucket before the view, not after it — and only the
    /// comparison the shell actually performs can see where the bucketing happened.
    #[test]
    fn a_second_of_node_uptime_does_not_repaint_the_window() {
        use dig_node_control_interface::results::StatusResult;
        let facts_at = |uptime_secs: u64| {
            Some(crate::node_facts::NodeFacts::of_status(&StatusResult {
                uptime_secs,
                ..crate::test_support::node::fake_status_result()
            }))
        };
        let view_at = |uptime_secs: u64| TrayView {
            node_facts: facts_at(uptime_secs),
            ..view(AccountState::Unlocked { recoverable: true })
        };

        assert!(
            view_at(4_200).renders_same_as(&view_at(4_259)),
            "59 further seconds of uptime rebuilt the whole window for a figure nobody can read"
        );
        // The control. Without it a `node_facts` dropped from the comparison entirely — or pinned to
        // `None` — would satisfy the assertion above while freezing the pane.
        assert!(
            !view_at(4_200).renders_same_as(&view_at(4_260)),
            "a whole minute later is a different phrase, and the pane must repaint to show it"
        );
    }

    /// **Regression, dig_ecosystem#2128 — the account survived every restart; the tray did not.**
    ///
    /// A fresh process holds no session, because since #1817 the app boots LOCKED and never attempts an
    /// unlock at start-up. The shell nevertheless derived "an open was attempted and failed" from
    /// `session.is_none() && enrolled`, which after #1817 is simply "an account exists" — so every launch
    /// with an enrolled account reported [`AccountState::Unopenable`], whose only window tells the user
    /// their account was made by an older DIG and steers them at a destructive replace. The account on
    /// disk was fine the whole time.
    ///
    /// The `Unopenable` arm is asserted alongside deliberately: a fix that simply stopped producing that
    /// state would pass a boot-only assertion while destroying the one signal a genuinely wedged
    /// legacy-format account has.
    #[test]
    fn a_boot_that_never_tried_to_unlock_is_locked_not_unopenable() {
        assert_eq!(
            at_rest_of(true, false, OpenAttempt::NotAttempted),
            AtRest::Present,
            "booting with an enrolled account is LOCKED — no unlock was attempted, so nothing failed"
        );
        assert_eq!(
            account_state(
                true,
                at_rest_of(true, false, OpenAttempt::NotAttempted),
                None
            ),
            AccountState::Locked,
            "the user must be offered Unlock…, never the destructive replace path"
        );
        assert_eq!(
            at_rest_of(true, false, OpenAttempt::Wedged),
            AtRest::PresentButUnopenable,
            "a genuinely wedged account must still be reported as such"
        );
    }

    /// An unlock the user cancelled, or one their password did not open, leaves the account exactly as
    /// LOCKED as it was — it is retryable, and saying otherwise sends someone who mistyped a password to
    /// a window offering to replace their account (dig_ecosystem#2128).
    #[test]
    fn a_refused_unlock_stays_locked_and_retryable() {
        assert_eq!(
            at_rest_of(true, false, OpenAttempt::Refused),
            AtRest::Present
        );
        assert_eq!(
            account_state(true, at_rest_of(true, false, OpenAttempt::Refused), None),
            AccountState::Locked
        );
    }

    /// The at-rest facts are read in a fixed order, and the earlier ones win: no account at all outranks
    /// any attempt outcome, and an account with no user-chosen password outranks a wedge verdict —
    /// otherwise a host in the middle of the machine-password migration would be offered the destructive
    /// remedy instead of `Set a password…`.
    #[test]
    fn absence_and_the_machine_password_outrank_any_attempt_outcome() {
        for attempt in [
            OpenAttempt::NotAttempted,
            OpenAttempt::Refused,
            OpenAttempt::Wedged,
        ] {
            assert_eq!(at_rest_of(false, false, attempt), AtRest::None);
            assert_eq!(
                at_rest_of(true, true, attempt),
                AtRest::PresentUnderMachinePassword
            );
        }
    }

    /// Every account state, so a rule can be asserted across all of them rather than on one fixture.
    ///
    /// Iterating is what makes the rules below load-bearing: the trap this module was rewritten for
    /// (`can_create = account == Absent`) looked correct from an `Absent` fixture and was wrong in every
    /// other state, which is where real users live.
    const EVERY_STATE: [AccountState; 7] = [
        AccountState::Unsupported,
        AccountState::Absent,
        AccountState::Locked,
        AccountState::NeedsPassword,
        AccountState::Unopenable,
        AccountState::Unlocked { recoverable: true },
        AccountState::Unlocked { recoverable: false },
    ];

    /// The states in which an account EXISTS — the ones the old gate locked out of management.
    const STATES_WITH_AN_ACCOUNT: [AccountState; 5] = [
        AccountState::Locked,
        AccountState::NeedsPassword,
        // The wedged legacy-seed state is deliberately IN this list: an account that cannot be opened is
        // exactly the one a user most needs to be able to replace.
        AccountState::Unopenable,
        AccountState::Unlocked { recoverable: true },
        AccountState::Unlocked { recoverable: false },
    ];

    /// A derived-looking receive address for the fixture views. Its exact value does not matter here —
    /// the derivation is proven in `account::residency`; what the menu cares about is present vs absent.
    const FIXTURE_ADDRESS: &str = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";

    /// The facts a node matching the fixture's `node` line would report — built by DISTILLING a real
    /// status snapshot rather than hand-writing the struct, so the fixture cannot drift from the
    /// conversion the shell performs.
    fn fixture_node_facts() -> crate::node_facts::NodeFacts {
        crate::node_facts::NodeFacts::of_status(&crate::test_support::node::fake_status_result())
    }

    fn view(account: AccountState) -> TrayView {
        // Only an UNLOCKED account can derive an address, so the fixture mirrors that rather than handing
        // every state an address the shell could never have produced for it.
        let receive_address =
            matches!(account, AccountState::Unlocked { .. }).then(|| FIXTURE_ADDRESS.to_string());
        TrayView {
            // These suites are about the account states, and editing is measured elsewhere; the
            // default has measured nothing, which is what every one of these fixtures has done.
            profile_editing: Default::default(),
            // Deletion is measured elsewhere too, and an unmeasured reading offers nothing — which
            // is exactly what every fixture in this suite has done.
            profile_deletion: Default::default(),
            running: true,
            node_connected: true,
            node: "Node v0.65.0 · 3 capsule(s) cached · 1 store(s) hosted".to_string(),
            // The strip's readings are the window's, not the tray's, so this suite pins them to the
            // pre-first-poll default rather than varying them. `network::tests` and the header's own
            // suite exercise the states.
            network: crate::network::NetworkStanding::default(),
            // Pinned to "nobody has asked" for the same reason: the tray draws no mint surface, and
            // the explainer's own suite exercises every reading.
            mint_chain: None,
            // Nothing has been asked of a node in this fixture, which is what the default states.
            enrolment: crate::wallet::enrol::Enrolment::default(),
            // This suite is about the MENU, which offers no send at all — a form is a window's job.
            send: crate::wallet::sending::SendProgress::Idle,
            account: Some(account),
            receive_address,
            address_fault: None,
            // Not yet polled — the honest pre-first-read state, and NOT a zero. Tests that care
            // about a figure set it explicitly.
            balance: crate::wallet::overview::BalanceReading::default(),
            profile_id: Some("a".repeat(96)),
            did: None,
            second_factor: false,
            hotkey: None,
            // The fixture's default: the suppressed case is exercised by the test that flips it.
            menu_suppressed: false,
            // A connected node reporting a default 1 GiB cap with 350 MiB in use — the ordinary
            // success case. Tests that need the disconnected surface null this out explicitly.
            cache: Some(crate::cache::CacheSnapshot {
                cap_bytes: crate::cache::GIB,
                used_bytes: 350 * crate::cache::MIB,
            }),
            // **`Unavailable` on purpose.** This suite describes the FULL menu — every submenu, every
            // verb — and that is exactly what a host with no app window renders (macOS, and any Linux
            // session with no display server). It is not a legacy shape: it is what those hosts get,
            // and what ANY host falls back to when opening the window is seen to fail
            // (`crate::window_host`). The four-row trim a windowed host gets has its own tests, which
            // set this to `Available` explicitly.
            window_host: WindowHost::Unavailable,
            // The three #2330 fields are pinned to the same connected node the `node` line above
            // describes, so nothing in this suite turns on them. Each is exercised by its own
            // module's tests and by `window_model`'s pane notes.
            node_facts: Some(fixture_node_facts()),
            hosted_stores: crate::hosted_stores::HostedStoresReading::Known(Vec::new()),
            installed_apps: crate::apps::AppPresence::Known(Vec::new()),
            // The registry ANSWERED and this account holds no profile — which is every real
            // account's state, because nothing in this build can mint one. Tests that need a list
            // build one from a registry fixture explicitly.
            profiles: crate::profiles::ProfilesReading::Known(Vec::new()),
            // What `mint_seams()` returns in the shipped binary — STATED, because
            // `ProfileCreation::default()` stopped meaning that: it is now `Unknown`, *nobody has
            // asked the node yet* (dig_ecosystem#2690), which no shipped build ever answers.
            profile_creation: crate::profiles::ProfileCreation::of(
                crate::account::chain_mint::MintAvailability::NoChainTransport,
            ),
            // A beacon that answered: auto-update on, following stable — the ordinary success case.
            // The tests that describe the absent beacon and the nightly channel null this out or
            // replace it explicitly.
            update: Some(crate::auto_update::BeaconStatus {
                paused: false,
                schedule_opted_out: false,
                channel: crate::auto_update::UpdateChannel::Stable,
            }),
        }
    }

    /// The regression test for dig_ecosystem#2074's second half: "I click it and nothing happens".
    ///
    /// The shell resolves a click by looking the native id up in the map it built with the CURRENT menu.
    /// If a rebuild renames the rows — which `muda` does for every unnamed item, from a process-global
    /// counter — then a click that crosses a rebuild carries an id the map no longer contains and is
    /// dropped. The node poll rewrites the view every five seconds, so rebuilds are continuous.
    ///
    /// The property that makes the drop impossible is that the same verb has the same id in two
    /// separately-built menus, so this asserts exactly that and nothing weaker.
    #[test]
    fn a_verb_keeps_its_id_across_a_rebuild() {
        let before = build(&view(AccountState::Unlocked { recoverable: true }));

        // The rebuild a user cannot see: the node's own description changed, nothing else.
        let mut changed = view(AccountState::Unlocked { recoverable: true });
        changed.node = "Node v0.84.0 · 9 capsule(s) cached · 4 store(s) hosted".to_string();
        let after = build(&changed);

        // Pairs rather than a map: `TrayAction` is deliberately not `Hash` (it carries a
        // `TransferRequest`), and a menu holds few enough rows that a scan is free.
        let ids_before: Vec<(TrayAction, String)> = action_ids(&before.rows)
            .into_iter()
            .map(|(id, a)| (a, id))
            .collect();
        let ids_after: Vec<(TrayAction, String)> = action_ids(&after.rows)
            .into_iter()
            .map(|(id, a)| (a, id))
            .collect();

        assert!(!ids_before.is_empty(), "the fixture menu must offer verbs");
        for (action, id) in &ids_before {
            assert_eq!(
                ids_after
                    .iter()
                    .find(|(candidate, _)| candidate == action)
                    .map(|(_, id)| id),
                Some(id),
                "{action:?} was renamed by a rebuild, so a click on it would be dropped"
            );
        }
    }

    /// A derived id could introduce an ambiguity in exchange for the one it removes: two rows answering
    /// to one id. That is only a defect when the rows mean DIFFERENT things — the same verb offered in
    /// two places (`AboutDid` is, in every state) resolves identically either way, which is the whole
    /// point of naming an id after the verb. So this pins the property that matters: within any one menu,
    /// an id never stands for two different actions, and every action row gets one.
    #[test]
    fn an_id_never_stands_for_two_different_verbs_in_one_menu() {
        for state in EVERY_STATE {
            let model = build(&view(state.clone()));
            let ids = action_ids(&model.rows);
            let mut seen = std::collections::HashMap::new();
            for (id, action) in &ids {
                if let Some(other) = seen.insert(id.clone(), *action) {
                    assert_eq!(
                        other, *action,
                        "in {state:?}, {other:?} and {action:?} share the id {id}"
                    );
                }
            }
            assert_eq!(
                ids.len(),
                every_action(&model).len(),
                "in {state:?} every action row must get exactly one id"
            );
        }
    }

    /// An id is only useful to the shell if it names the verb unambiguously in BOTH directions — two
    /// different verbs must never collide, in any menu, ever.
    #[test]
    fn different_verbs_never_share_an_id() {
        let mut seen = std::collections::HashMap::new();
        for state in EVERY_STATE {
            for (action, _, _) in every_action(&build(&view(state.clone()))) {
                let id = action_id(action);
                if let Some(other) = seen.insert(id.clone(), action) {
                    assert_eq!(
                        other, action,
                        "{other:?} and {action:?} both answer to {id}"
                    );
                }
            }
        }
        assert!(seen.len() > 1, "the sweep must have seen real verbs");
    }

    /// Every action row anywhere in `model`, submenus included, as `(action, label, enabled)`.
    ///
    /// A helper rather than a per-test walk because the rows under test live inside a submenu, and a
    /// test that reached in by index would pass for a row that had drifted into the wrong menu.
    fn every_action(model: &MenuModel) -> Vec<(TrayAction, String, bool)> {
        fn walk(rows: &[MenuRow], out: &mut Vec<(TrayAction, String, bool)>) {
            for row in rows {
                match row {
                    MenuRow::Action {
                        action,
                        label,
                        enabled,
                    } => out.push((*action, label.clone(), *enabled)),
                    MenuRow::Submenu { rows, .. } => walk(rows, out),
                    MenuRow::Separator => {}
                }
            }
        }
        let mut out = Vec::new();
        walk(&model.rows, &mut out);
        out
    }

    /// The rows inside the submenu labelled `label`.
    fn submenu(model: &MenuModel, label: &str) -> Vec<MenuRow> {
        model
            .rows
            .iter()
            .find_map(|row| match row {
                MenuRow::Submenu { label: l, rows } if l == label => Some(rows.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no {label} submenu"))
    }

    // ---- Apps group (dig_ecosystem#2101). ----

    /// The **Apps** submenu lists Chat, wired to launch dig-chat, in EVERY account state.
    ///
    /// Asserted across all states because using another app is not gated on custody — the group must
    /// not appear and vanish with the account (the drift #1836 fixed for the rest of the spine). It
    /// checks the row lives INSIDE the Apps submenu (via the recursive `submenu` helper, not a
    /// top-level index) so a Chat row that drifted elsewhere would fail rather than pass.
    #[test]
    fn the_apps_submenu_lists_chat_and_launches_dig_chat_in_every_state() {
        use crate::apps::AppId;
        for account in EVERY_STATE {
            let menu = build(&view(account.clone()));
            let rows = submenu(&menu, "Apps");
            let chat = rows
                .iter()
                .find_map(|row| match row {
                    MenuRow::Action {
                        action,
                        label,
                        enabled,
                    } => Some((*action, label.clone(), *enabled)),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{account:?}: the Apps submenu has no action row"));
            assert_eq!(
                chat,
                (TrayAction::LaunchApp(AppId::Chat), "Chat".to_string(), true),
                "{account:?}: Apps must offer an enabled Chat row launching dig-chat"
            );
        }
    }

    /// The Apps group is data-driven: the submenu offers exactly one launch row per registry entry, in
    /// registry order. This is what makes "a second app is a data row" true rather than aspirational —
    /// adding to `apps::APPS` adds a row here with no menu-code change.
    #[test]
    fn the_apps_submenu_mirrors_the_registry() {
        let menu = build(&view(AccountState::Unlocked { recoverable: true }));
        let launched: Vec<TrayAction> = submenu(&menu, "Apps")
            .iter()
            .filter_map(|row| match row {
                MenuRow::Action { action, .. } => Some(*action),
                _ => None,
            })
            .collect();
        let expected: Vec<TrayAction> = crate::apps::APPS
            .iter()
            .map(|app| TrayAction::LaunchApp(app.id))
            .collect();
        assert_eq!(launched, expected);
    }

    // ---- Paired apps (dig_ecosystem#1848). ----

    /// Both paired-app rows live under **Security**, and nowhere else.
    ///
    /// The placement is the decision worth pinning: "which other programs can act through my account"
    /// is a question about whether the account is safe right now, not about wanting a different
    /// account — and a row that drifted into Manage Account would sit one mis-click from
    /// "Remove this account from this computer".
    #[test]
    fn the_paired_app_rows_live_under_security() {
        let model = build(&view(AccountState::Unlocked { recoverable: true }));
        let security: Vec<TrayAction> = every_action(&MenuModel {
            rows: submenu(&model, "Security"),
        })
        .into_iter()
        .map(|(action, _, _)| action)
        .collect();
        assert!(security.contains(&TrayAction::PairAnApp));
        assert!(security.contains(&TrayAction::ManagePairedApps));

        for elsewhere in ["Manage Account", "View Account", "Wallet"] {
            let rows: Vec<TrayAction> = every_action(&MenuModel {
                rows: submenu(&model, elsewhere),
            })
            .into_iter()
            .map(|(action, _, _)| action)
            .collect();
            assert!(
                !rows.contains(&TrayAction::PairAnApp)
                    && !rows.contains(&TrayAction::ManagePairedApps),
                "the paired-app rows must not appear under {elsewhere}"
            );
        }
    }

    /// The rows appear ONLY while the account is unlocked, and `Paired apps…` is never greyed.
    ///
    /// Both halves matter and neither implies the other: an implementation that always offered them
    /// would pass a greyness check while putting a row in front of a locked user that could only fail,
    /// and one that always hid them would pass the "never greyed" check by offering nothing at all.
    ///
    /// # Why `Pair an app…` no longer carries the never-greyed half (dig_ecosystem#2350)
    ///
    /// It did, and only because no reason to grey it existed yet. Every capability a pairing grants is
    /// identity-bearing, so pairing without a DID hands out permissions over an identity that does not
    /// exist — which the DID policy now refuses. The refusal is a greyed row NAMING the remedy, which
    /// is the same shape as `Show my recovery phrase (unlock first)` and is what #1800 asks for; the
    /// dead end #1800 removed was a greyed row that could not say what would fix it. The DID-present
    /// case is covered by [`the_pairing_door_opens_once_a_did_exists`].
    ///
    /// `Paired apps…` keeps the never-greyed guarantee unconditionally, because it is where a pairing
    /// is REVOKED and the way out is never gated.
    #[test]
    fn the_paired_app_rows_appear_only_when_the_account_is_unlocked() {
        for account in EVERY_STATE {
            let model = build(&view(account.clone()));
            let unlocked = matches!(account, AccountState::Unlocked { .. });
            for action in [TrayAction::PairAnApp, TrayAction::ManagePairedApps] {
                assert_eq!(
                    model.offers(action),
                    unlocked,
                    "{action:?} in {account:?}: pairing seals under the account key, so an unlocked account is its real precondition"
                );
            }
            if model.offers(TrayAction::ManagePairedApps) {
                assert!(
                    model.is_enabled(TrayAction::ManagePairedApps),
                    "{account:?}: revoking a pairing is the way out and must never be greyed"
                );
            }
        }
    }

    /// Whether the publish row is offered, and enabled, for `view`. `None` when no row exists at all.
    fn publish_row_is_enabled(view: &TrayView) -> Option<bool> {
        profile_edit_actions(view).iter().find_map(|row| match row {
            MenuRow::Action {
                action: TrayAction::PublishProfileEdits,
                enabled,
                ..
            } => Some(*enabled),
            _ => None,
        })
    }

    /// **The DID gate, driven in BOTH states over the surfaces that consult it**
    /// (dig_ecosystem#2350).
    ///
    /// One fixture, varying ONLY whether a DID exists. Asserting the policy function in isolation is
    /// what already existed and is exactly what could not catch this: `Allowance::of` has always been
    /// right, and no surface asked it.
    ///
    /// Publishing is checked through the same builder in the same two states, and reading — the verb
    /// dig-app promises never needs an identity — is checked to be untouched by either.
    #[test]
    fn the_identity_bearing_verbs_are_gated_on_a_did_and_reading_is_not() {
        let mut without = view(AccountState::Unlocked { recoverable: true });
        without.did = None;
        without.profile_editing = crate::profile_edit::ProfileEditing::Possible;
        let mut with = without.clone();
        with.did =
            Some("did:chia:1gatefixture0000000000000000000000000000000000000000000000".into());

        let closed = build(&without);
        let open = build(&with);

        assert!(
            !closed.is_enabled(TrayAction::PairAnApp),
            "pairing grants identity capabilities, so it cannot be offered before an identity exists"
        );
        assert!(
            open.is_enabled(TrayAction::PairAnApp),
            "with a DID minted the same door must open, or the gate is just a permanent refusal"
        );
        // Publishing lives in the WINDOW, not the tray menu, so it is driven through the group
        // builder both containers compose (pinned verbatim by `each_tab_is_the_shared_group_builder_verbatim`).
        assert_eq!(
            publish_row_is_enabled(&without),
            Some(false),
            "publishing puts the user's identity on what they publish, so it is offered and refused"
        );
        assert_eq!(
            publish_row_is_enabled(&with),
            Some(true),
            "with a DID minted publishing must be available, or the gate is a permanent refusal"
        );

        for model in [&closed, &open] {
            assert!(
                model.is_enabled(TrayAction::Open),
                "reading DIG content never needs an account, a wallet or a DID"
            );
        }
    }

    // ---- The second factor (dig_ecosystem#1840). ----

    /// The row is EITHER "set up" or "turn off" — the one that names what clicking it will do — and the
    /// other is absent rather than greyed.
    ///
    /// Both states are exercised from the same unlocked fixture, varying ONLY `second_factor`: a test
    /// that checked one state could not tell a state-dependent row from a hardcoded one.
    #[test]
    fn the_two_factor_row_names_the_verb_the_account_is_actually_in_a_state_for() {
        for (enrolled, offered, absent) in [
            (
                false,
                TrayAction::SetUpTwoFactor,
                TrayAction::TurnOffTwoFactor,
            ),
            (
                true,
                TrayAction::TurnOffTwoFactor,
                TrayAction::SetUpTwoFactor,
            ),
        ] {
            let mut v = view(AccountState::Unlocked { recoverable: true });
            v.second_factor = enrolled;
            let rows = submenu(&build(&v), "Security");
            let actions: Vec<TrayAction> = every_action(&MenuModel { rows })
                .into_iter()
                .map(|(action, _, _)| action)
                .collect();

            assert!(actions.contains(&offered), "with second_factor={enrolled}");
            assert!(!actions.contains(&absent), "with second_factor={enrolled}");
        }
    }

    /// Both two-factor rows are ENABLED wherever they appear. A greyed security verb with no stated
    /// reason is the #1800 defect; the row's precondition is expressed by it appearing at all.
    #[test]
    fn no_two_factor_row_is_ever_offered_greyed_out() {
        for enrolled in [false, true] {
            for account in EVERY_STATE {
                let mut v = view(account.clone());
                v.second_factor = enrolled;
                for (action, label, enabled) in every_action(&build(&v)) {
                    if matches!(
                        action,
                        TrayAction::SetUpTwoFactor | TrayAction::TurnOffTwoFactor
                    ) {
                        assert!(enabled, "{label:?} is offered greyed in {account:?}");
                    }
                }
            }
        }
    }

    /// SETTING UP is offered only where it can run — an unlocked account, since the enrolment is sealed
    /// under the account's own key.
    ///
    /// The unlocked case is the control in the same loop: without it this would also pass for a menu
    /// that never offered the row at all.
    #[test]
    fn setting_up_is_offered_only_where_it_can_actually_run() {
        for account in EVERY_STATE {
            let expected = matches!(account, AccountState::Unlocked { .. });
            let offered = every_action(&build(&view(account.clone())))
                .iter()
                .any(|(a, _, _)| matches!(a, TrayAction::SetUpTwoFactor));
            assert_eq!(offered, expected, "in {account:?}");
        }
    }

    /// **The way out of the trap this feature could otherwise create.** An enrolled factor blocks the
    /// destructive verbs, and an account that cannot be opened can never answer a challenge — so
    /// `Turn off two-factor codes…` must be reachable in EVERY state an account exists in, including
    /// `Locked` and `Unopenable`. If it were not, such an account could never be replaced or removed.
    #[test]
    fn turning_off_stays_reachable_even_when_the_account_will_not_open() {
        for account in STATES_WITH_AN_ACCOUNT {
            let mut v = view(account.clone());
            v.second_factor = true;
            assert!(
                every_action(&build(&v))
                    .iter()
                    .any(|(a, _, enabled)| *a == TrayAction::TurnOffTwoFactor && *enabled),
                "an enrolled factor must be removable in {account:?}"
            );
        }
    }

    // ---- The global shortcut's two surfaces (dig_ecosystem#1839). ----

    /// A live shortcut is DISCOVERABLE from the menu; a failed or unattempted one is not advertised.
    ///
    /// All three states asserted against the same view, because "shows the chord" and "shows the chord
    /// only when it works" are different properties and only a fixture that varies the state can tell them
    /// apart.
    #[test]
    fn the_open_row_advertises_the_shortcut_only_while_it_is_live() {
        let base = view(AccountState::Absent);
        let label_with = |hotkey| {
            let view = TrayView {
                hotkey,
                ..base.clone()
            };
            build(&view).label_of(TrayAction::Open).unwrap().to_string()
        };

        let live = label_with(Some(crate::hotkey::HotkeyState::Registered(
            crate::hotkey::Hotkey::default(),
        )));
        assert!(live.starts_with("Open URL…"), "{live}");
        assert!(live.contains("Alt+Space"), "{live}");

        // Not attempted, and attempted-but-refused, must both read exactly as the row always did — a
        // menu that promised a chord the OS refused would be a lie the user acts on.
        for absent in [
            None,
            Some(crate::hotkey::HotkeyState::Unavailable {
                hotkey: crate::hotkey::Hotkey::default(),
                reason: "another application already uses it".to_string(),
            }),
            Some(crate::hotkey::HotkeyState::Unsupported {
                reason: "no global shortcuts on this desktop".to_string(),
            }),
        ] {
            assert_eq!(label_with(absent), "Open URL…");
        }
    }

    /// `Status` is where a shortcut that did NOT work gets explained — the only place it can be, since a
    /// chord that does nothing produces no other signal at all.
    #[test]
    fn status_explains_a_shortcut_that_failed_and_stays_quiet_before_one_is_tried() {
        let base = view(AccountState::Absent);
        assert!(
            !details_text(&base).contains("Keyboard"),
            "nothing to report before the shell has tried"
        );

        let failed = TrayView {
            hotkey: Some(crate::hotkey::HotkeyState::Unavailable {
                hotkey: crate::hotkey::Hotkey::default(),
                reason: "another application already uses it".to_string(),
            }),
            ..base.clone()
        };
        let text = details_text(&failed);
        assert!(text.contains("Keyboard"));
        assert!(
            text.contains("another application already uses it"),
            "{text}"
        );
        assert!(text.contains("Open URL…"), "{text}");

        // The account and node lines must survive the addition — a new section appended over the top of
        // an existing one is exactly the kind of thing a `contains` on the new text alone cannot see.
        assert!(text.contains("Node"));
        assert!(text.contains("DIG ID:"));
    }

    // ---- Rule 1: a menu item is an ACTION. ----

    /// **The headline regression (#1800).** No row may exist purely to display text.
    ///
    /// Asserted structurally — `MenuRow` has no status variant, so this is a compile-time guarantee that
    /// this test restates as an executable one: every row is a separator, an action, or a submenu.
    /// A future lane reaching for "just one greyed label" has to change the type to do it.
    #[test]
    fn the_menu_contains_only_actions_separators_and_submenus() {
        for account in EVERY_STATE {
            for row in &build(&view(account.clone())).rows {
                match row {
                    MenuRow::Separator | MenuRow::Action { .. } | MenuRow::Submenu { .. } => {}
                }
            }
        }
    }

    /// The five facts that used to be greyed menu rows must all still be reachable — in the details
    /// window. Removing them from the menu is only correct because nothing was lost.
    #[test]
    fn every_fact_the_status_rows_carried_is_in_the_details_window() {
        let mut v = view(AccountState::Unlocked { recoverable: false });
        v.did = Some("did:chia:1abc".to_string());
        let details = details_text(&v);

        assert!(details.contains("running"), "{details}");
        assert!(
            details.contains("unlocked — NO recovery phrase"),
            "{details}"
        );
        assert!(
            details.contains(&"a".repeat(96)),
            "the DIG ID must be here IN FULL, not abbreviated: {details}"
        );
        assert!(details.contains("did:chia:1abc"), "{details}");
        assert!(details.contains("Node v0.65.0"), "{details}");
    }

    /// The details window is the one surface with no width limit, so it must carry the engine's real
    /// diagnosis WHOLE. The fixture is the ~700-character control-token reason observed from a live run —
    /// the text the old 72-character menu row had to throw away.
    #[test]
    fn the_details_window_carries_the_full_untruncated_node_diagnosis() {
        let observed = "No node: the node at http://dig.local refused this app (the node refused the \
             request: control.* requires the local control token (X-Dig-Control-Token header or \
             params._control_token, from C:\\ProgramData\\DigNode\\control-token), or a paired \
             controller token (see `dig-node pair`). no control token found at \
             C:\\ProgramData\\DigNode\\control-token. Start the node so it mints one (`dig-node run`, \
             or `dig-node start` for the installed service), then retry.)";
        assert!(
            observed.chars().count() > MAX_TOOLTIP_CHARS * 3,
            "fixture guard: the point is that real reasons are FAR over any row/tooltip bound, got {}",
            observed.chars().count()
        );

        let mut v = view(AccountState::Locked);
        v.node = observed.to_string();
        let details = details_text(&v);

        assert!(
            details.contains(observed),
            "the diagnosis must arrive whole: {details}"
        );
        // And the tooltip — the bounded surface — must NOT, which is what makes the window load-bearing.
        assert!(status(&v).tooltip.chars().count() <= MAX_TOOLTIP_CHARS + 1);
    }

    /// `Status and details…` is clickable in every state, because explaining what is wrong is the one
    /// thing that must work when everything else is wrong.
    #[test]
    fn the_details_window_is_reachable_in_every_state() {
        for account in EVERY_STATE {
            assert!(
                build(&view(account.clone())).is_enabled(TrayAction::ShowStatus),
                "{account:?}"
            );
        }
    }

    // ---- Rule 2: never trap the user. Account management is ALWAYS available. ----

    /// **The trap this rewrite exists to fix (#1800/#1799).** On the machine this was measured on, an
    /// account existed with no recovery phrase, so `Set up`, `Restore` and `Show phrase` were ALL greyed
    /// and the one live row explained that the remedy was a new account — which nothing could create.
    ///
    /// So: in every state where an account EXISTS, a way to replace it and a way to remove it must be
    /// clickable. Iterating the three account-present states is what makes this load-bearing — the old
    /// rule was satisfied by `Absent` alone, which is the one state a real user is not in.
    #[test]
    fn an_existing_account_can_always_be_replaced_or_removed() {
        for account in STATES_WITH_AN_ACCOUNT {
            let menu = build(&view(account.clone()));
            for action in [
                TrayAction::ReplaceWithNewAccount,
                TrayAction::ReplaceFromPhrase,
                TrayAction::RemoveAccount,
            ] {
                assert!(
                    menu.is_enabled(action),
                    "{account:?}: {action:?} must be reachable — an account the user cannot change is a trap"
                );
            }
        }
    }

    /// The control that proves the test above is reading `exists` rather than always enabling the
    /// destructive verbs: with NO account there is nothing to replace or remove, so those rows are absent
    /// entirely (not greyed — a greyed "Remove this account" on a machine with no account is a mystery,
    /// and rule 3 would demand a reason there is none to give).
    #[test]
    fn a_host_with_no_account_offers_creation_and_no_destruction() {
        let menu = build(&view(AccountState::Absent));

        assert!(menu.is_enabled(TrayAction::SetUpAccount));
        assert!(menu.is_enabled(TrayAction::RestoreFromPhrase));
        for action in [
            TrayAction::ReplaceWithNewAccount,
            TrayAction::ReplaceFromPhrase,
            TrayAction::RemoveAccount,
        ] {
            assert!(
                !menu.offers(action),
                "{action:?} has nothing to act on when no account exists"
            );
        }
    }

    /// A phrase-less account is told so AND pointed at the remedy — and the remedy must be a row that is
    /// actually clickable, which is precisely what the measured install lacked.
    #[test]
    fn a_phrase_less_account_is_pointed_at_a_remedy_that_is_clickable() {
        let menu = build(&view(AccountState::Unlocked { recoverable: false }));

        assert!(menu.is_enabled(TrayAction::FixMissingPhrase));
        assert!(
            !menu.offers(TrayAction::ShowRecoveryPhrase),
            "a dead reveal row explains nothing; the remedy row replaces it"
        );
        assert!(
            menu.is_enabled(TrayAction::ReplaceWithNewAccount),
            "the explainer says the remedy is a new account, so a new account must be creatable"
        );
    }

    /// A recoverable account must NOT be nagged with the remedy row — the control that proves the test
    /// above reads `recoverable` rather than always warning.
    #[test]
    fn a_recoverable_account_is_not_shown_the_remedy_row() {
        let menu = build(&view(AccountState::Unlocked { recoverable: true }));
        assert!(!menu.offers(TrayAction::FixMissingPhrase));
        assert!(menu.is_enabled(TrayAction::ShowRecoveryPhrase));
    }

    /// Never trap the user: from EVERY account state, the escapes stay clickable.
    #[test]
    fn the_escapes_are_enabled_in_every_account_state() {
        for account in EVERY_STATE {
            let menu = build(&view(account.clone()));
            assert!(
                menu.is_enabled(TrayAction::Quit),
                "quit must work in {account:?}"
            );
            // Reading content is not a custody action: it must be reachable with no account, with a
            // locked one, and with one that cannot be opened at all (§6.0 — a $DIG-movement
            // opportunity must never gate consuming data).
            assert!(
                menu.is_enabled(TrayAction::Open),
                "opening a DIG link must work in {account:?} — it needs no account"
            );
            assert!(
                menu.is_enabled(TrayAction::OpenLogs),
                "the logs escape must work in {account:?}"
            );
        }
    }

    // ---- Rule 3: no row defers to a terminal, and a disabled row says why. ----

    /// **Regression (#1798).** No row may hand the user off to a command line. The tray IS the app.
    ///
    /// Sweeping EVERY label in EVERY state is the point: the defect was one row
    /// ("Restore from a recovery phrase (in a terminal)…"), and a test naming that row could not stop the
    /// next one appearing elsewhere.
    #[test]
    fn no_row_anywhere_defers_to_a_terminal_or_a_command() {
        for account in EVERY_STATE {
            for (label, _) in build(&view(account.clone())).all_actions() {
                let lowered = label.to_lowercase();
                for banned in [
                    "terminal",
                    "command line",
                    "console",
                    "diga ",
                    "dign ",
                    "cmd",
                ] {
                    assert!(
                        !lowered.contains(banned),
                        "{account:?}: a tray row must not defer to {banned:?}: {label}"
                    );
                }
            }
        }
    }

    /// A disabled row must state its own reason, so a greyed control is never an unexplained mystery.
    ///
    /// Asserted over every row in every state, which also enforces the design goal that disabled rows are
    /// now RARE — the only one left is the unsupported-host row.
    #[test]
    fn every_disabled_row_names_the_reason_it_cannot_be_used() {
        for account in EVERY_STATE {
            for (label, enabled) in build(&view(account.clone())).all_actions() {
                if enabled {
                    continue;
                }
                assert!(
                    label.contains('(') && label.contains(')'),
                    "{account:?}: a greyed row must carry its reason in parentheses: {label}"
                );
            }
        }
    }

    /// A host with no per-application credential store genuinely cannot hold an account — the one
    /// legitimately-disabled row — and must not be offered destruction verbs either.
    #[test]
    fn an_unsupported_host_explains_itself_and_offers_no_account_action() {
        let menu = build(&view(AccountState::Unsupported));

        let label = menu.label_of(TrayAction::SetUpAccount).unwrap();
        assert!(!menu.is_enabled(TrayAction::SetUpAccount));
        assert!(
            label.contains("not supported on this system yet"),
            "the one greyed row must say why: {label}"
        );
        for action in [
            TrayAction::ReplaceWithNewAccount,
            TrayAction::ReplaceFromPhrase,
            TrayAction::RemoveAccount,
            TrayAction::ShowRecoveryPhrase,
        ] {
            assert!(!menu.is_enabled(action), "{action:?} must be inert here");
        }
        // Still not a dead end: the details window and the escapes work.
        assert!(menu.is_enabled(TrayAction::ShowStatus));
        assert!(menu.is_enabled(TrayAction::Quit));
    }

    // ---- The custody gates, unchanged in strictness. ----

    /// The reveal gate: the phrase is offered ONLY to an unlocked, recoverable account.
    #[test]
    fn showing_the_phrase_requires_both_unlocked_and_recoverable() {
        assert!(build(&view(AccountState::Unlocked { recoverable: true }))
            .is_enabled(TrayAction::ShowRecoveryPhrase));

        for account in [
            AccountState::Absent,
            AccountState::Locked,
            AccountState::Unsupported,
            AccountState::Unlocked { recoverable: false },
        ] {
            assert!(
                !build(&view(account.clone())).is_enabled(TrayAction::ShowRecoveryPhrase),
                "{account:?} must not reveal a recovery phrase"
            );
        }
    }

    #[test]
    fn unlock_is_offered_only_while_locked_and_lock_only_while_unlocked() {
        let locked = build(&view(AccountState::Locked));
        assert!(locked.is_enabled(TrayAction::Unlock));
        assert!(!locked.is_enabled(TrayAction::LockNow));

        let unlocked = build(&view(AccountState::Unlocked { recoverable: true }));
        assert!(!unlocked.is_enabled(TrayAction::Unlock));
        assert!(unlocked.is_enabled(TrayAction::LockNow));
    }

    /// **Policy (dig_ecosystem#2953).** With a 24-hour idle window, `Lock now` is the only immediate
    /// lock a person has, so it must sit on the TOP level — not merely somewhere in the model.
    ///
    /// `is_enabled` searches recursively and would stay green if a future menu tidy-up demoted the row
    /// into a submenu, which is exactly the regression this guards: it walks `rows` directly, without
    /// descending, so a demotion is observable.
    #[test]
    fn lock_now_is_offered_at_the_top_level_whenever_the_account_is_unlocked() {
        for recoverable in [true, false] {
            for host in [WindowHost::Available, WindowHost::Unavailable] {
                let mut v = view(AccountState::Unlocked { recoverable });
                v.window_host = host;
                let top_level_lock_now = build(&v).rows.iter().any(|row| {
                    matches!(
                        row,
                        MenuRow::Action {
                            action: TrayAction::LockNow,
                            enabled: true,
                            ..
                        }
                    )
                });
                assert!(
                    top_level_lock_now,
                    "an unlocked account ({host:?}, recoverable={recoverable}) must offer `Lock now` \
                     on the top level: with a 24-hour idle window it is the only immediate lock"
                );
            }
        }
    }

    #[test]
    fn copying_the_dig_id_needs_a_profile() {
        let mut v = view(AccountState::Unlocked { recoverable: true });
        assert!(build(&v).is_enabled(TrayAction::CopyDigId));
        v.profile_id = None;
        assert!(
            !build(&v).is_enabled(TrayAction::CopyDigId),
            "there is nothing to copy"
        );
    }

    /// **Regression (#1773).** No tray row may offer to MINT a DID, in any account state — no code path
    /// in this build can mint (see `crate::account::mint`). The guarantee is STRUCTURAL (no `TrayAction`
    /// mints), so this also guards a future lane reintroducing one before minting is reachable.
    #[test]
    fn no_row_offers_to_mint_a_did_because_minting_does_not_exist_yet() {
        for account in EVERY_STATE {
            for (label, _) in build(&view(account.clone())).all_actions() {
                let lowered = label.to_lowercase();
                assert!(
                    !(lowered.starts_with("create") && lowered.contains("did")),
                    "{account:?}: no row may offer to mint a DID: {label}"
                );
            }
        }
    }

    /// The DID explainer is reachable in every state — an explanation needs no account to be readable —
    /// and its label carries both facts a person needs before opening it.
    #[test]
    fn the_did_explainer_is_reachable_everywhere_and_names_its_cost() {
        for account in EVERY_STATE {
            let menu = build(&view(account.clone()));
            assert!(menu.is_enabled(TrayAction::AboutDid), "{account:?}");
            let label = menu.label_of(TrayAction::AboutDid).unwrap();
            assert!(label.contains("XCH"), "{account:?}: {label}");
            // "required", never "optional": a DID is the bedrock of the account (dig_ecosystem#1820),
            // and the retired label described the one mandatory remaining step as a nicety.
            assert!(label.contains("required"), "{account:?}: {label}");
            assert!(!label.contains("optional"), "{account:?}: {label}");
        }
    }

    /// A destructive verb must SAY it is destructive in its own label, so the menu itself is a warning.
    #[test]
    fn the_destructive_verbs_name_what_they_destroy() {
        let menu = build(&view(AccountState::Unlocked { recoverable: true }));
        for (action, expected) in [
            (TrayAction::ReplaceWithNewAccount, "Replace"),
            (TrayAction::ReplaceFromPhrase, "Replace"),
            (TrayAction::RemoveAccount, "Remove"),
        ] {
            let label = menu.label_of(action).unwrap();
            assert!(
                label.starts_with(expected),
                "{action:?} must lead with its verb: {label}"
            );
        }
    }

    /// The destructive verbs live in the submenu, not the top level — reachable, but not somewhere a
    /// mis-click lands. Asserted on PLACEMENT (the top-level rows), which is the property; a test that
    /// only checked `is_enabled` would be satisfied by them sitting at the top of the menu.
    #[test]
    fn the_destructive_verbs_are_one_level_down_not_on_the_top_level() {
        let menu = build(&view(AccountState::Unlocked { recoverable: true }));
        let mut top_level = Vec::new();
        for row in &menu.rows {
            if let MenuRow::Action { action, .. } = row {
                top_level.push(*action);
            }
        }

        for action in [
            TrayAction::ReplaceWithNewAccount,
            TrayAction::ReplaceFromPhrase,
            TrayAction::RemoveAccount,
        ] {
            assert!(
                !top_level.contains(&action),
                "{action:?} destroys custody and must not sit next to Lock now: {top_level:?}"
            );
            assert!(
                menu.is_enabled(action),
                "{action:?} must still be reachable in the submenu"
            );
        }
        // **The control.** Without this, an EMPTY top level would satisfy every assertion above. `LockNow`
        // used to serve as that control; it now lives under Security (dig_ecosystem#1836), so the spine
        // itself does the job — and it is a stronger control, because it pins the two rows that must always
        // be one click away rather than whichever verb happened to be primary.
        for action in [TrayAction::ShowStatus, TrayAction::Open] {
            assert!(
                top_level.contains(&action),
                "{action:?} is part of the fixed spine and must stay on the top level: {top_level:?}"
            );
        }
        // `LockNow` IS on the top level now, and that is the deliberate change dig_ecosystem#2253
        // made: the trimmed menu's first slot must never be empty, and an unlocked account's one
        // routine want is to lock. It sits beside the escapes; the DESTRUCTIVE verbs asserted above
        // still do not, which is the property this test is actually about.
        assert!(
            top_level.contains(&TrayAction::LockNow),
            "the unlocked state's row must be Lock now: {top_level:?}"
        );
        assert!(
            menu.is_enabled(TrayAction::LockNow),
            "…and it must be usable"
        );
    }

    /// The top-level menu must stay SHORT — a native menu the length of the old one is a wall of text.
    ///
    /// The bound is 11, and since dig_ecosystem#1836 it is a bound on a FIXED spine rather than on a menu
    /// that grew with state: Status · Open URL · View Account · Manage Account · Wallet · Security · Cache ·
    /// Apps · logs · quit is ten, plus at most ONE contextual row when the account needs something (no
    /// account, locked, or unopenable).
    ///
    /// The number has moved five times, each for a recorded reason rather than as a bumped constant:
    /// 7 → 8 when `Open` arrived (#1821), because opening content is what the product is FOR and burying it
    /// under the custody menu would hide the one verb a content consumer wants; 8 → 9 when `Wallet` arrived
    /// (#1841), because money is a top-level concern of this product (§6.0) and it is a SUBMENU, so it costs
    /// one row and hides its own contents; 9 → 10 when `Cache` arrived (#2002), a SUBMENU carrying the
    /// node's size-limit control with its usage on the parent label; 10 → 11 when `Apps` arrived (#2101), a
    /// SUBMENU grouping the other DIG apps so they never each claim a spine row.
    ///
    /// The rule the number enforces is unchanged and is the thing to defend: every *further* verb goes in a
    /// submenu or the details window, never onto the top level. Seven named rows still fit on one screen
    /// without scrolling, which is what "not a wall" actually means. If an eighth ever wants the spine, the
    /// question to ask is which of the seven it replaces.
    #[test]
    fn the_top_level_menu_stays_short_in_every_state() {
        for account in EVERY_STATE {
            let menu = build(&view(account.clone()));
            let clickable = menu
                .rows
                .iter()
                .filter(|row| matches!(row, MenuRow::Action { .. } | MenuRow::Submenu { .. }))
                .count();
            assert!(
                clickable <= 11,
                "{account:?}: {clickable} top-level rows is a wall, not a menu"
            );
        }
    }

    /// **The named options are always present, in order** (dig_ecosystem#1836, plus Wallet from #1841).
    ///
    /// The user asked for a specific menu; this is what holds the loop to it. Asserted in EVERY state,
    /// because the defect it prevents is the old behaviour — a menu whose rows appeared and vanished with
    /// account state, so no two machines showed the same thing and nothing could be found twice in the
    /// same place.
    #[test]
    fn the_named_options_are_present_and_ordered_in_every_state() {
        for account in EVERY_STATE {
            let menu = build(&view(account.clone()));
            let spine: Vec<&str> = menu
                .rows
                .iter()
                .filter_map(|row| match row {
                    MenuRow::Action { label, .. } => Some(label.as_str()),
                    MenuRow::Submenu { label, .. } => Some(label.as_str()),
                    MenuRow::Separator => None,
                })
                .collect();

            let wanted = [
                "Status",
                "Open URL…",
                "View Account",
                "Manage Account",
                "Wallet",
                "Security",
            ];
            let found: Vec<&str> = spine
                .iter()
                .copied()
                .filter(|l| wanted.contains(l))
                .collect();
            assert_eq!(
                found, wanted,
                "{account:?}: every named option must be present, in order — got {spine:?}"
            );

            // The escapes are not part of the five, and are not negotiable against them: a tray app that
            // cannot be quit traps the user (`professional-ui` HARD RULE).
            assert!(menu.is_enabled(TrayAction::Quit), "{account:?}");
            assert!(menu.is_enabled(TrayAction::OpenLogs), "{account:?}");
        }
    }

    /// **Restore must not be lost.** It used to sit on the top level beside `Set up`; the five-option
    /// restructure moved it into **Manage Account**, and a user with an existing recovery phrase who cannot
    /// find it has no way onto this machine at all.
    ///
    /// Paired with the first-run property below, which pins the other half: `Set up` stays one click away.
    #[test]
    fn restoring_from_a_phrase_is_reachable_with_no_account() {
        let menu = build(&view(AccountState::Absent));
        assert!(
            menu.is_enabled(TrayAction::RestoreFromPhrase),
            "an existing phrase must have somewhere to go"
        );
    }

    /// **First run stays one click.** Someone who has just installed must see what to do WITHOUT opening a
    /// submenu — the dead end #1800 removed and #1826 is built to prevent.
    #[test]
    fn setting_up_an_account_is_on_the_top_level_when_there_is_none() {
        let menu = build(&view(AccountState::Absent));
        let top_level: Vec<TrayAction> = menu
            .rows
            .iter()
            .filter_map(|row| match row {
                MenuRow::Action { action, .. } => Some(*action),
                _ => None,
            })
            .collect();
        assert!(
            top_level.contains(&TrayAction::SetUpAccount),
            "a brand-new user must not have to hunt for setup: {top_level:?}"
        );

        // The control: once an account EXISTS there is nothing urgent, so the top level carries no account
        // verb at all and the menu is exactly the five plus the escapes.
        let unlocked = build(&view(AccountState::Unlocked { recoverable: true }));
        let unlocked_actions: Vec<TrayAction> = unlocked
            .rows
            .iter()
            .filter_map(|row| match row {
                MenuRow::Action { action, .. } => Some(*action),
                _ => None,
            })
            .collect();
        assert!(
            !unlocked_actions.contains(&TrayAction::SetUpAccount),
            "a working account has nothing urgent to offer: {unlocked_actions:?}"
        );
    }

    // ---- The tray icon + tooltip: state's new home. ----

    /// The glyph must distinguish all five situations, so the icon genuinely carries the state the menu
    /// rows used to print. A table over every input combination that matters, because a glyph rule tested
    /// on one state could collapse every case to `Ready` and still pass.
    #[test]
    fn the_glyph_reports_the_most_actionable_problem() {
        let starting = TrayView {
            running: false,
            ..view(AccountState::Unlocked { recoverable: true })
        };
        assert_eq!(status(&starting).glyph, TrayGlyph::Starting);

        for account in [AccountState::Absent, AccountState::Unsupported] {
            assert_eq!(
                status(&view(account.clone())).glyph,
                TrayGlyph::NeedsAccount,
                "{account:?}"
            );
        }
        assert_eq!(status(&view(AccountState::Locked)).glyph, TrayGlyph::Locked);

        let no_node = TrayView {
            node_connected: false,
            node: "No node: nothing is listening on this machine".to_string(),
            ..view(AccountState::Unlocked { recoverable: true })
        };
        assert_eq!(status(&no_node).glyph, TrayGlyph::NoNode);

        assert_eq!(
            status(&view(AccountState::Unlocked { recoverable: true })).glyph,
            TrayGlyph::Ready
        );
    }

    /// A locked account with a perfectly healthy node still shows LOCKED, because the lock is what stops
    /// the user. The fixture varies ONLY the account state against an otherwise-ideal world, which is what
    /// distinguishes this priority rule from an implementation that just reports the node.
    #[test]
    fn a_lock_outranks_a_healthy_node_in_the_icon() {
        let mut v = view(AccountState::Locked);
        v.node_connected = true;
        assert_eq!(status(&v).glyph, TrayGlyph::Locked);
    }

    /// The tooltip must be bounded, because Windows silently truncates `szTip` at 128 units — an
    /// unbounded tooltip is cut with no ellipsis and no clue anything is missing.
    ///
    /// Pinned from BOTH sides: at the bound nothing is touched, one character over is cut. A bound tested
    /// only from above would pass for an implementation that truncated at 40.
    #[test]
    fn the_tooltip_bound_holds_at_the_limit_and_cuts_one_character_over() {
        let at_bound = "a".repeat(MAX_TOOLTIP_CHARS);
        assert_eq!(bound_tooltip(&at_bound), at_bound);

        let one_over = "a".repeat(MAX_TOOLTIP_CHARS + 1);
        let cut = bound_tooltip(&one_over);
        assert_ne!(cut, one_over);
        assert!(cut.ends_with('…'), "the reader must be told there is more");
        assert!(cut.chars().count() <= MAX_TOOLTIP_CHARS + 1);
    }

    /// Bounding must count CHARACTERS, not bytes: the connected summary contains `·`, so a byte-indexed
    /// slice would panic on a multi-byte boundary. The fixture puts multi-byte characters exactly ACROSS
    /// the cut point, which an all-ASCII fixture could never exercise.
    #[test]
    fn bounding_never_splits_a_multi_byte_character() {
        let line = "·".repeat(MAX_TOOLTIP_CHARS * 2);
        assert!(
            line.len() > line.chars().count(),
            "fixture guard: multi-byte"
        );

        let bounded = bound_tooltip(&line);
        assert!(bounded.chars().count() <= MAX_TOOLTIP_CHARS + 1);
        assert!(bounded.starts_with('·'), "{bounded}");
    }

    /// The tooltip must name the state in words too — the icon alone cannot be read by someone using a
    /// screen reader or a high-contrast theme that flattens the badge colours (§6.6 a11y).
    #[test]
    fn the_tooltip_names_the_state_in_words_not_only_in_colour() {
        for (account, expected) in [
            (AccountState::Absent, "no account"),
            (AccountState::Locked, "locked"),
            (AccountState::Unlocked { recoverable: true }, "ready"),
        ] {
            let tooltip = status(&view(account.clone())).tooltip;
            assert!(
                tooltip.to_lowercase().contains(expected),
                "{account:?}: {tooltip}"
            );
        }
    }

    /// A tooltip must never say the same thing twice — the node line is dropped when the headline already
    /// reports the node, so the 120-character budget is not spent repeating itself.
    #[test]
    fn a_no_node_tooltip_does_not_repeat_itself() {
        let v = TrayView {
            node_connected: false,
            node: "No node: nothing is listening on this machine".to_string(),
            ..view(AccountState::Unlocked { recoverable: true })
        };
        let tooltip = status(&v).tooltip;
        assert!(!tooltip.contains('\n'), "one fact, one line: {tooltip:?}");
        assert!(tooltip.to_lowercase().contains("no node"));
    }

    /// A healthy tray still shows the node summary on the second line — the control that proves the rule
    /// above suppresses the line only for the redundant case rather than always.
    #[test]
    fn a_healthy_tooltip_carries_the_node_summary() {
        let tooltip = status(&view(AccountState::Unlocked { recoverable: true })).tooltip;
        assert!(tooltip.contains("Node v0.65.0"), "{tooltip}");
    }

    // ---- Presentation helpers. ----

    /// A 96-character hex key must be abbreviated — but must keep BOTH ends, so a user can eyeball that
    /// the id matches the one they pasted. A prefix-only rendering would fail this.
    #[test]
    fn a_long_dig_id_is_abbreviated_at_both_ends() {
        let id = format!("{}{}{}", "1".repeat(8), "0".repeat(80), "9".repeat(8));
        assert_eq!(short_dig_id(&id), "11111111…99999999");
        assert_eq!(short_dig_id("abcd"), "abcd", "a short id is shown verbatim");
    }

    /// With no minted DID the details window must say so rather than showing something DID-shaped.
    #[test]
    fn an_absent_did_is_never_dressed_up_as_a_minted_one() {
        let details = details_text(&view(AccountState::Unlocked { recoverable: true }));
        assert!(
            details.contains(
                "On-chain DID: not created yet — on-chain minting is not available in this version"
            ),
            "{details}"
        );
    }

    /// **Regression.** The advice must name the fix, not merely the symptom — and must NOT send the user
    /// to a command line at all. Both CLI names are banned, for two different reasons: `dign` is
    /// dig-node's binary (dig_ecosystem#1788), so naming it hands the person the wrong tool outright;
    /// `diga` is dig-app's own CLI (#243) and is the right tool, but a tray row that defers to it still
    /// sends someone to a console to fix a tray that will not draw.
    #[test]
    fn linux_tray_advice_names_the_missing_library_and_not_a_wrong_cli() {
        let advice = tray_unavailable_advice("no display", crate::Os::Linux);
        assert!(advice.contains("libayatana-appindicator3-1"), "{advice}");
        assert!(
            advice.contains("no display"),
            "the real reason must survive: {advice}"
        );
        assert!(
            !advice.contains("diga"),
            "tray advice must not defer to dig-app's own CLI (#243): {advice}"
        );
        assert!(
            !advice.contains("dign"),
            "`dign` is dig-node's binary (#1788), not dig-app's CLI: {advice}"
        );
    }

    /// The Linux-specific package advice must NOT be shown on Windows/macOS, where it is wrong. Two
    /// platforms are needed to see this at all — a Linux-only fixture would pass for a function that
    /// always appended it.
    #[test]
    fn desktop_platforms_get_no_linux_package_advice() {
        for os in [crate::Os::Windows, crate::Os::MacOs] {
            let advice = tray_unavailable_advice("tray build failed", os);
            assert!(!advice.contains("appindicator"), "{os:?}: {advice}");
            assert!(advice.contains("DIG menu"), "{os:?}: {advice}");
        }
    }

    // ---- account_state: the lock-state derivation, unchanged. ----

    /// **Regression (#1799 review).** An account that cannot be OPENED must not be reported as merely
    /// LOCKED, must explain itself, and must be replaceable — the three things the old silent
    /// `tracing::warn!` denied a user whose legacy raw-seed blob will not unlock.
    ///
    /// The fixture is the state itself rather than a boot failure, because the boot is impure; what this
    /// pins is that the state, once derived, produces a menu with a way OUT. `an_unopenable_account_is_never_
    /// reported_as_locked` pins the derivation.
    #[test]
    fn an_unopenable_account_explains_itself_and_can_be_replaced() {
        let menu = build(&view(AccountState::Unopenable));

        assert!(
            menu.is_enabled(TrayAction::ExplainUnopenable),
            "the user must be told why signing is unavailable"
        );
        assert!(
            !menu.offers(TrayAction::Unlock),
            "unlocking is what already failed; offering it again is a button guaranteed to fail"
        );
        assert!(
            !menu.offers(TrayAction::ShowRecoveryPhrase),
            "the phrase vault is sealed under the seed that will not open"
        );
        // The remedy, and the escape hatches.
        assert!(menu.is_enabled(TrayAction::ReplaceWithNewAccount));
        assert!(menu.is_enabled(TrayAction::ReplaceFromPhrase));
        assert!(menu.is_enabled(TrayAction::RemoveAccount));
        assert!(menu.is_enabled(TrayAction::ShowStatus));
        assert!(menu.is_enabled(TrayAction::Quit));
    }

    /// The tray must SAY the account cannot be opened, on the surfaces a user actually looks at — not only
    /// in a log file, which is what the boot did before this state existed.
    #[test]
    fn an_unopenable_account_says_so_in_the_tooltip_and_the_details_window() {
        let view = view(AccountState::Unopenable);
        let status = status(&view);

        assert_eq!(
            status.glyph,
            TrayGlyph::NeedsAccount,
            "this needs the user, so the icon must say so"
        );
        assert!(
            status.tooltip.to_lowercase().contains("cannot be opened"),
            "{}",
            status.tooltip
        );
        assert!(
            details_text(&view).contains("cannot be opened on this computer"),
            "{}",
            details_text(&view)
        );
    }

    /// **Regression (#1752 security gate).** After `Lock now` — or an idle auto-lock — the session is
    /// still held but its KEYS are gone. The menu previously keyed on the session's existence, so it
    /// reported unlocked, kept the reveal enabled, and left `Unlock…` disabled: a false state report AND
    /// a dead end (`SPEC.md` §3.1c).
    ///
    /// The fixture varies ONLY `keys_unlocked` across two otherwise identical sessions, because that is
    /// the single input the bug ignored.
    #[test]
    fn a_session_whose_keys_were_dropped_reports_locked() {
        let unlocked = SessionFacts {
            keys_unlocked: true,
            recoverable: true,
        };
        let after_lock = SessionFacts {
            keys_unlocked: false,
            ..unlocked
        };

        assert_eq!(
            account_state(true, AtRest::Present, Some(unlocked)),
            AccountState::Unlocked { recoverable: true }
        );
        assert_eq!(
            account_state(true, AtRest::Present, Some(after_lock)),
            AccountState::Locked,
            "a session that has dropped its keys is LOCKED, not unlocked"
        );
    }

    /// The user-visible consequence, asserted on the MENU: after Lock now the reveal must be gone and
    /// `Unlock…` must be the way back in.
    #[test]
    fn the_menu_after_lock_now_offers_unlock_and_no_reveal() {
        let after_lock = account_state(
            true,
            AtRest::Present,
            Some(SessionFacts {
                keys_unlocked: false,
                recoverable: true,
            }),
        );
        let menu = build(&view(after_lock));

        assert!(menu.is_enabled(TrayAction::Unlock));
        assert!(!menu.is_enabled(TrayAction::ShowRecoveryPhrase));
        assert!(!menu.is_enabled(TrayAction::LockNow));
    }

    /// A locked session must NOT be mistaken for an absent account — that would offer first-run
    /// enrolment over an account that already exists.
    #[test]
    fn a_locked_session_is_never_reported_as_absent() {
        let state = account_state(
            true,
            AtRest::Present,
            Some(SessionFacts {
                keys_unlocked: false,
                recoverable: false,
            }),
        );
        assert_eq!(state, AccountState::Locked);
        let menu = build(&view(state));
        assert!(
            !menu.is_enabled(TrayAction::SetUpAccount),
            "first-run enrolment refuses on an existing custody root; REPLACE is the honest verb"
        );
        assert!(menu.is_enabled(TrayAction::ReplaceWithNewAccount));
    }

    /// With no session, `enrolled` is what separates "locked" from "not set up yet".
    #[test]
    fn with_no_session_enrolment_separates_locked_from_absent() {
        assert_eq!(
            account_state(true, AtRest::Present, None),
            AccountState::Locked
        );
        assert_eq!(
            account_state(true, AtRest::None, None),
            AccountState::Absent
        );
        assert_eq!(
            account_state(true, AtRest::PresentButUnopenable, None),
            AccountState::Unopenable,
            "an account that would not open must NOT be reported as merely locked"
        );
    }

    /// An unsupported host wins over everything else — it cannot hold an account, so no amount of
    /// session or enrolment state changes what the user is told.
    #[test]
    fn an_unsupported_host_overrides_every_other_input() {
        for at_rest in [AtRest::None, AtRest::Present, AtRest::PresentButUnopenable] {
            for session in [
                None,
                Some(SessionFacts {
                    keys_unlocked: true,
                    recoverable: true,
                }),
            ] {
                assert_eq!(
                    account_state(false, at_rest, session),
                    AccountState::Unsupported
                );
            }
        }
    }

    /// `recoverable` must survive the derivation — it is what selects the reveal row over the warning.
    #[test]
    fn an_unlocked_state_carries_the_recoverable_flag_through() {
        for recoverable in [true, false] {
            assert_eq!(
                account_state(
                    true,
                    AtRest::Present,
                    Some(SessionFacts {
                        keys_unlocked: true,
                        recoverable
                    })
                ),
                AccountState::Unlocked { recoverable }
            );
        }
    }

    /// Before the first boot reports, the tray must render — defaulting to "no account" rather than
    /// panicking or showing a blank menu.
    #[test]
    fn an_unreported_account_defaults_to_absent() {
        let menu = build(&TrayView::default());
        assert!(menu.is_enabled(TrayAction::SetUpAccount));
        assert!(details_text(&TrayView::default()).contains("not set up yet"));
    }

    /// **The set in the module docs, asserted rather than claimed.** Exactly five rows are disabled
    /// across the account states, and each one is in the state that explains it.
    ///
    /// A count is precisely the kind of claim that drifts as rows move: an earlier revision of the module
    /// docs said "exactly one" while the model already rendered two. Pinning it means the docs, the SPEC and
    /// the code cannot disagree again without a red test.
    ///
    /// The assertion is on the (state, label) PAIRS, not the total, because a bare total of two would also
    /// be satisfied by two greyed rows in one state and none in the other — which would leave a state with a
    /// dead end and no remedy beside it.
    #[test]
    fn the_disabled_rows_are_exactly_the_ones_that_name_their_reason() {
        let mut disabled = Vec::new();
        for account in EVERY_STATE {
            for (label, enabled) in build(&view(account.clone())).all_actions() {
                if !enabled {
                    disabled.push((format!("{account}"), label.to_string()));
                }
            }
        }

        assert_eq!(
            disabled,
            vec![
                (
                    "not available on this system yet".to_string(),
                    "Set up my DIG Account (not supported on this system yet)".to_string()
                ),
                (
                    "locked".to_string(),
                    "Show my recovery phrase (unlock first)".to_string()
                ),
                (
                    "locked".to_string(),
                    "Copy my receive address (unlock first)".to_string()
                ),
                (
                    "needs a password — anyone using this computer can open it".to_string(),
                    "Show my recovery phrase (set a password first)".to_string()
                ),
                (
                    "needs a password — anyone using this computer can open it".to_string(),
                    "Copy my receive address (set a password first)".to_string()
                ),
                // The DID gate (dig_ecosystem#2350). `EVERY_STATE`'s unlocked fixtures carry no
                // minted DID, so both of them refuse pairing and name the remedy. The row is enabled
                // the moment a DID exists — asserted in
                // `the_identity_bearing_verbs_are_gated_on_a_did_and_reading_is_not`, which is what
                // keeps this pair from being a permanent refusal wearing a remedy's words.
                (
                    "unlocked".to_string(),
                    PAIR_AN_APP_NEEDS_DID_LABEL.to_string()
                ),
                (
                    "unlocked — NO recovery phrase".to_string(),
                    PAIR_AN_APP_NEEDS_DID_LABEL.to_string()
                ),
            ],
            "the disabled set changed; update the module docs and SPEC §3.1c to match"
        );
    }

    /// An account still sealed under the machine password must NOT be reported as `Locked`.
    ///
    /// Collapsing it into `Locked` is the tempting shortcut and it is exactly wrong: it would offer
    /// `Unlock…`, which asks for a password the user has never chosen and does not have — a control
    /// guaranteed to fail, with nothing said about why. This is the same collapse `Unopenable` was added
    /// to prevent, one state along.
    #[test]
    fn an_account_with_no_user_password_is_reported_as_needing_one_not_as_locked() {
        assert_eq!(
            account_state(true, AtRest::PresentUnderMachinePassword, None),
            AccountState::NeedsPassword
        );
        // The control: an account with a user password and no live session IS locked, so the assertion
        // above is reading the at-rest fact rather than reporting `NeedsPassword` for everything.
        assert_eq!(
            account_state(true, AtRest::Present, None),
            AccountState::Locked
        );
    }

    /// **The address row copies the MONEY key's address, and nothing else.**
    ///
    /// The fixture is the whole point: `profile_id` is present in EVERY state, so an implementation that
    /// wired the row to the identity public key — the mistake #1841 refused to make — would offer an
    /// enabled `Copy my receive address` for a locked account too, and pass any test that only checked
    /// the unlocked one. Varying ONLY `receive_address` is what makes the row's source observable.
    #[test]
    fn the_copy_address_row_follows_the_address_and_not_the_identity_key() {
        let unlocked = build(&view(AccountState::Unlocked { recoverable: true }));
        assert!(unlocked.is_enabled(TrayAction::CopyReceiveAddress));

        let locked_view = view(AccountState::Locked);
        assert!(
            locked_view.profile_id.is_some() && locked_view.receive_address.is_none(),
            "the fixture must hold an identity key and no address, or it cannot tell them apart"
        );
        let locked = build(&locked_view);
        assert!(
            locked.offers(TrayAction::CopyReceiveAddress),
            "an address is public — being locked is a reason to explain, not to hide the row"
        );
        assert!(!locked.is_enabled(TrayAction::CopyReceiveAddress));
        assert!(
            locked.is_enabled(TrayAction::Unlock),
            "the label names `unlock first`, so the remedy must be clickable"
        );
    }

    /// The states with no derivable address at all get an EXPLANATION, never a greyed row that cannot say
    /// when it would work.
    ///
    /// Both states are checked together because they fail differently: a brand-new user has nothing to
    /// wait for, and an unopenable account's key is gone — neither is "unlock first".
    #[test]
    fn a_wallet_with_no_derivable_address_explains_instead_of_greying_a_row() {
        for account in [AccountState::Absent, AccountState::Unopenable] {
            let menu = build(&view(account.clone()));
            assert!(
                !menu.offers(TrayAction::CopyReceiveAddress),
                "{account:?}: a row that can never work is a dead end, not a menu item"
            );
            assert!(
                menu.is_enabled(TrayAction::AboutWallet),
                "{account:?}: the wallet must still be able to explain itself"
            );
        }
    }

    /// The labels of the Wallet submenu's action rows, in render order.
    fn wallet_labels(account: AccountState) -> Vec<String> {
        wallet_labels_with(account, crate::wallet::overview::BalanceReading::default())
    }

    /// [`wallet_labels`] for a view carrying an explicit balance reading, so a test can drive the
    /// row from what the NODE reported rather than only from the not-yet-polled default.
    fn wallet_labels_with(
        account: AccountState,
        balance: crate::wallet::overview::BalanceReading,
    ) -> Vec<String> {
        let view = TrayView {
            balance,
            ..view(account)
        };
        every_action(&MenuModel {
            rows: submenu(&build(&view), "Wallet"),
        })
        .into_iter()
        .map(|(_, label, _)| label)
        .collect()
    }

    /// The balance row for `account`, whatever else the Wallet submenu holds.
    fn balance_row(labels: Vec<String>) -> String {
        labels
            .into_iter()
            .find(|label| label.starts_with("Balance"))
            .expect("a balance row in every state")
    }

    /// **The balance is on the submenu, in EVERY account state** (dig_ecosystem#1841's third row).
    ///
    /// The ticket asked for three things the app can honestly deliver today — the address, the balance
    /// or the reason it is unknown, and the explainer. The first and third shipped; this pins the
    /// second, and pins it in every state rather than only the unlocked one, because the states that
    /// CANNOT show a figure are exactly the ones where a person needs to be told why.
    #[test]
    fn the_wallet_submenu_reports_the_balance_in_every_state() {
        for account in EVERY_STATE {
            let labels = wallet_labels(account.clone());
            let balance: Vec<&String> = labels
                .iter()
                .filter(|label| label.starts_with("Balance"))
                .collect();
            assert_eq!(
                balance.len(),
                1,
                "{account:?}: exactly one balance row, got {labels:?}"
            );
        }
    }

    /// **The balance row is never greyed.** A greyed money row that could not say when it would work is
    /// the dead end #1800 removed; the row is always clickable and its LABEL carries the reason, with the
    /// window behind it carrying the full one.
    #[test]
    fn the_balance_row_is_always_clickable_and_never_a_greyed_dead_end() {
        for account in EVERY_STATE {
            let rows = every_action(&MenuModel {
                rows: submenu(&build(&view(account.clone())), "Wallet"),
            });
            for (action, label, enabled) in rows {
                if !label.starts_with("Balance") {
                    continue;
                }
                assert!(
                    enabled,
                    "{account:?}: a greyed balance row is a dead end: {label}"
                );
                assert_eq!(
                    action,
                    TrayAction::AboutWallet,
                    "{account:?}: the balance row must open the window that holds the full reason"
                );
            }
        }
    }

    /// **No unknown balance is ever rendered as a figure on the menu.**
    ///
    /// The fixture is the production case and the trap at once: no state the tray can build today has a
    /// chain source that answers, so every state's row must be words. An implementation that defaulted
    /// an unreadable balance to `0` would put a numeral here and fail.
    #[test]
    fn an_unreadable_balance_shows_words_on_the_menu_and_never_a_figure() {
        for account in EVERY_STATE {
            let label = wallet_labels(account.clone())
                .into_iter()
                .find(|label| label.starts_with("Balance"))
                .expect("a balance row in every state");
            assert!(
                !label.chars().any(|c| c.is_ascii_digit()),
                "{account:?}: nothing can read a balance today, so a figure here is a lie: {label}"
            );
        }
    }

    /// **With no account, the Wallet submenu SAYS there is nothing to show** rather than opening onto a
    /// bare explainer.
    ///
    /// `My wallet…` alone is not an answer to "what is in my wallet" — it is a row that makes the user
    /// click to find out there is nothing. The balance row states it on the menu.
    ///
    /// The two account-less states get DIFFERENT words, and that is the point rather than a detail: a
    /// host with no credential store cannot follow "set one up", so telling it the same thing as a
    /// brand-new machine would name a remedy that does not exist there.
    #[test]
    fn with_no_account_the_wallet_submenu_says_so_instead_of_opening_onto_a_bare_explainer() {
        for (account, expected) in [
            (AccountState::Absent, "no account on this computer yet"),
            (
                AccountState::Unsupported,
                "this computer cannot hold an account",
            ),
        ] {
            let labels = wallet_labels(account.clone());
            assert!(
                labels.iter().any(|label| label.contains(expected)),
                "{account:?}: the submenu must say there is nothing to show: {labels:?}"
            );
            assert!(
                labels.len() > 1,
                "{account:?}: a lone explainer row is the dead end this replaces: {labels:?}"
            );
        }
    }

    /// **No state is told to unlock when unlocking is not the way back.**
    ///
    /// This is the rule the balance row exists under (#1800) and the one an implementation drifts on
    /// first, because "the keys are out of reach" *feels* like one state and is three. Asserted as a
    /// full state → clause table so a future collapse is a red test rather than a wrong remedy shipped
    /// to the one user who cannot act on it.
    #[test]
    fn the_balance_row_names_a_remedy_each_state_can_actually_perform() {
        let expected = [
            (
                AccountState::Unsupported,
                "this computer cannot hold an account",
            ),
            (AccountState::Absent, "no account on this computer yet"),
            (AccountState::Locked, "unlock your account first"),
            (
                AccountState::NeedsPassword,
                "set a password for your account first",
            ),
            (AccountState::Unopenable, "your account cannot be opened"),
            // The unlocked states DO have an address, so their row carries the reading the poller
            // took — here the fixture's not-yet-polled default, which is honestly "still checking"
            // rather than a verdict on the user's node (dig_ecosystem#2325).
            (AccountState::Unlocked { recoverable: true }, "checking"),
            (AccountState::Unlocked { recoverable: false }, "checking"),
        ];
        for (account, clause) in expected {
            let label = balance_row(wallet_labels(account.clone()));
            assert!(
                label.contains(clause),
                "{account:?}: expected {clause:?}, got {label:?}"
            );
        }
    }

    /// **The row shows the money once the node has reported it** (dig_ecosystem#2206), and shows the
    /// node's own reason when it could not.
    ///
    /// The fixture varies ONE thing — the reading the poller carried in — against an account state
    /// that is otherwise identical, so a row still deriving its text from anything but that reading
    /// cannot pass both halves.
    #[test]
    fn the_balance_row_shows_the_figure_the_node_reported() {
        use crate::wallet::overview::{BalanceReading, BalanceUnknown, Balances};

        let held = balance_row(wallet_labels_with(
            AccountState::Unlocked { recoverable: true },
            BalanceReading::Known {
                balances: Balances::of_xch_and_dig(1_250_000_000_000, 2_500),
                as_of: crate::wallet::engine::BalanceAsOf::Replica {
                    height: 7_000_000,
                    caught_up: true,
                },
            },
        ));
        assert!(held.contains("2.5 $DIG"), "{held}");
        assert!(held.contains("1.25 XCH"), "{held}");
        assert!(!held.contains("not known"), "{held}");

        // The same account, the same menu, an older node: the row states that instead of a figure.
        let cannot = balance_row(wallet_labels_with(
            AccountState::Unlocked { recoverable: true },
            BalanceReading::Unknown(BalanceUnknown::NodeCannotRead),
        ));
        assert!(
            cannot.contains("this node cannot read balances yet"),
            "{cannot}"
        );
        assert!(
            !cannot.chars().any(|c| c.is_ascii_digit()),
            "an unknown must never show a figure: {cannot}"
        );
    }

    /// The balance row does not DISPLACE the explainer — both rows are present, and the explainer keeps
    /// its own label.
    ///
    /// Worth pinning because the two share an action ([`TrayAction::AboutWallet`], as the Cache submenu's
    /// two rows share [`TrayAction::AboutCache`]): every action-keyed assertion in this file would still
    /// pass if the explainer row silently vanished, since the balance row answers to the same key.
    #[test]
    fn the_balance_row_is_added_beside_the_explainer_and_not_instead_of_it() {
        for account in EVERY_STATE {
            let labels = wallet_labels(account.clone());
            assert!(
                labels.iter().any(|label| label == "My wallet…"),
                "{account:?}: the explainer must survive: {labels:?}"
            );
            assert!(
                labels.iter().any(|label| label.starts_with("Balance")),
                "{account:?}: {labels:?}"
            );
        }
    }

    /// **Before the first boot has reported, the two halves of the row must still agree.**
    ///
    /// `build` resolves a missing `account` through `TrayView::account()`, which defaults to
    /// `Absent`; `WalletOverview::of_tray` matches `view.account` directly. Two derivations of the
    /// same fact, in the one state (`None`) that `EVERY_STATE` cannot reach — so a divergence would
    /// show only on a real machine during startup, as a submenu whose row contradicted its own
    /// address gating.
    #[test]
    fn an_unreported_account_reads_the_same_in_the_wallet_submenu_as_an_absent_one() {
        // The submenu only exists on a host with no app window; elsewhere this content is the
        // Wallet TAB. `TrayView::default()` is otherwise exactly the pre-first-report state this
        // test is about, so only the host is overridden.
        let startup = TrayView {
            window_host: WindowHost::Unavailable,
            ..TrayView::default()
        };
        let unreported = MenuModel {
            rows: submenu(&build(&startup), "Wallet"),
        };
        let labels: Vec<String> = every_action(&unreported)
            .into_iter()
            .map(|(_, label, _)| label)
            .collect();

        assert!(
            labels
                .iter()
                .any(|label| label.contains("no account on this computer yet")),
            "startup must not invent a different reason: {labels:?}"
        );
        assert!(
            !unreported.offers(TrayAction::CopyReceiveAddress),
            "there is no address to copy before an account is reported: {labels:?}"
        );
    }

    /// The submenu's order is address → balance → explainer: what a person came for first, the figure
    /// second, and the prose last.
    #[test]
    fn the_wallet_submenu_leads_with_the_address_then_the_balance() {
        let labels = wallet_labels(AccountState::Unlocked { recoverable: true });
        let position = |needle: &str| {
            labels
                .iter()
                .position(|label| label.starts_with(needle))
                .unwrap_or_else(|| panic!("no {needle} row in {labels:?}"))
        };
        assert!(position("Copy my receive address") < position("Balance"));
        assert!(position("Balance") < position("My wallet"));
    }

    /// Neither disabled row is a DEAD END: each state that has one also offers an enabled row that resolves
    /// it. This is the property that makes two greyed rows acceptable rather than a defect — the count alone
    /// says nothing about whether the user can get anywhere.
    #[test]
    fn every_state_with_a_disabled_row_offers_the_remedy_beside_it() {
        // A locked account: the reveal is greyed, and `Unlock…` — which is what un-greys it — is clickable.
        let locked = build(&view(AccountState::Locked));
        assert!(!locked.is_enabled(TrayAction::ShowRecoveryPhrase));
        assert!(locked.is_enabled(TrayAction::Unlock));

        // An account with no password: the reveal is greyed, and the row that resolves it — setting a
        // password — is clickable. `Unlock…` deliberately is NOT offered, because there is no password
        // to type yet.
        let needs = build(&view(AccountState::NeedsPassword));
        assert!(!needs.is_enabled(TrayAction::ShowRecoveryPhrase));
        assert!(needs.is_enabled(TrayAction::SetAccountPassword));
        assert!(!needs.is_enabled(TrayAction::Unlock));

        // An unsupported host: setup is greyed, and the details window that explains the host is clickable.
        let unsupported = build(&view(AccountState::Unsupported));
        assert!(!unsupported.is_enabled(TrayAction::SetUpAccount));
        assert!(unsupported.is_enabled(TrayAction::ShowStatus));
        assert!(unsupported.is_enabled(TrayAction::Quit));
    }

    // ---- The cache size-limit surface (dig_ecosystem#2002). ----

    /// A view whose only difference from the default fixture is its cache field — so a cache test
    /// varies exactly one thing and keeps a truthful, connected control elsewhere.
    fn view_with_cache(cache: Option<crate::cache::CacheSnapshot>) -> TrayView {
        TrayView {
            cache,
            ..view(AccountState::Unlocked { recoverable: true })
        }
    }

    /// The rows of the Cache submenu for a given snapshot.
    fn cache_rows(cache: Option<crate::cache::CacheSnapshot>) -> Vec<MenuRow> {
        let model = build(&view_with_cache(cache));
        model
            .rows
            .iter()
            .find_map(|row| match row {
                MenuRow::Submenu { label, rows } if label.starts_with("Cache") => {
                    Some(rows.clone())
                }
                _ => None,
            })
            .expect("a Cache submenu must always be present")
    }

    #[test]
    fn the_cache_parent_label_shows_usage_against_the_cap() {
        // The figure a person needs — how full the cache is — must be visible on the spine row itself,
        // and it must name BOTH numbers, because a cap with no usage is not actionable (requirement 2).
        let model = build(&view_with_cache(Some(crate::cache::CacheSnapshot {
            cap_bytes: crate::cache::GIB,
            used_bytes: 350 * crate::cache::MIB,
        })));
        let label = model
            .rows
            .iter()
            .find_map(|row| match row {
                MenuRow::Submenu { label, .. } if label.starts_with("Cache") => Some(label.clone()),
                _ => None,
            })
            .expect("a Cache submenu");
        assert!(label.contains("350 MiB"), "shows usage: {label}");
        assert!(label.contains("1 GiB"), "shows the cap: {label}");
    }

    #[test]
    fn every_preset_is_offered_and_the_current_cap_is_marked() {
        // The node's cap is 2 GiB here, which is a preset — so that row, and ONLY that row, is marked
        // current. A test that only checked "a row is marked" would pass if the WRONG row were marked,
        // so this pins that the mark tracks the actual cap.
        let rows = cache_rows(Some(crate::cache::CacheSnapshot {
            cap_bytes: 2 * crate::cache::GIB,
            used_bytes: crate::cache::GIB,
        }));
        let actions: Vec<(TrayAction, String, bool)> =
            every_action(&MenuModel { rows }).into_iter().collect();

        let mut marked = Vec::new();
        for &bytes in &crate::cache::CACHE_PRESETS {
            let row = actions
                .iter()
                .find(|(a, _, _)| *a == TrayAction::SetCacheCap { bytes })
                .unwrap_or_else(|| panic!("preset {bytes} must be offered"));
            assert!(row.2, "a preset must be clickable");
            if row.1.contains("current") {
                marked.push(bytes);
            }
        }
        assert_eq!(
            marked,
            vec![2 * crate::cache::GIB],
            "exactly the current cap (2 GiB) is marked"
        );
    }

    #[test]
    fn the_default_preset_is_labelled_as_the_default() {
        let rows = cache_rows(Some(crate::cache::CacheSnapshot {
            cap_bytes: 2 * crate::cache::GIB,
            used_bytes: 0,
        }));
        let default_label = every_action(&MenuModel { rows })
            .into_iter()
            .find(|(a, _, _)| {
                *a == TrayAction::SetCacheCap {
                    bytes: crate::cache::DEFAULT_CACHE_CAP_BYTES,
                }
            })
            .map(|(_, label, _)| label)
            .expect("the default preset is offered");
        assert!(
            default_label.contains("default"),
            "the default cap must be findable deliberately: {default_label}"
        );
    }

    #[test]
    fn a_connected_cache_offers_a_custom_option() {
        let model = MenuModel {
            rows: cache_rows(Some(crate::cache::CacheSnapshot {
                cap_bytes: crate::cache::GIB,
                used_bytes: 0,
            })),
        };
        assert!(model.is_enabled(TrayAction::SetCustomCacheCap));
    }

    #[test]
    fn a_disconnected_node_offers_no_change_rows_but_never_a_dead_end() {
        // The error/empty async state (requirement 5): with no node there is nothing to set, so the
        // preset and custom rows are ABSENT rather than shown-but-broken — yet the submenu still has an
        // enabled row that explains why and an enabled explainer, so it is never a silent no-op.
        let model = MenuModel {
            rows: cache_rows(None),
        };
        assert!(!model.offers(TrayAction::SetCustomCacheCap));
        for &bytes in &crate::cache::CACHE_PRESETS {
            assert!(
                !model.offers(TrayAction::SetCacheCap { bytes }),
                "a preset must not be offered with no node to apply it"
            );
        }
        // The explainer is reachable and enabled — the way forward.
        assert!(model.is_enabled(TrayAction::AboutCache));
        // And no row in the submenu is a disabled dead end.
        let disconnected = MenuModel {
            rows: cache_rows(None),
        };
        for (label, enabled) in disconnected.all_actions() {
            assert!(
                enabled,
                "the disconnected cache row {label:?} must not be a greyed dead end"
            );
        }
    }

    #[test]
    fn the_explainer_is_offered_in_both_the_connected_and_disconnected_states() {
        assert!(MenuModel {
            rows: cache_rows(None)
        }
        .is_enabled(TrayAction::AboutCache));
        assert!(MenuModel {
            rows: cache_rows(Some(crate::cache::CacheSnapshot {
                cap_bytes: crate::cache::GIB,
                used_bytes: 0
            }))
        }
        .is_enabled(TrayAction::AboutCache));
    }

    #[test]
    fn the_status_details_window_carries_the_full_cache_figures() {
        let text = details_text(&view_with_cache(Some(crate::cache::CacheSnapshot {
            cap_bytes: crate::cache::GIB,
            used_bytes: 350 * crate::cache::MIB,
        })));
        assert!(text.contains("Cache: 350 MiB of 1 GiB used"), "got: {text}");
    }

    /// SPEC 3.1b-tp: a suppressed menu MUST be reported to the user, not only to the log.
    ///
    /// The tooltip is the only surface a person has for a menu that did not appear — they clicked
    /// the icon and got nothing, so the text has to say why AND that clicking again is the remedy.
    /// Asserted on the substance rather than the exact sentence: the requirement is that the user
    /// learns Windows blocked it and that a second click works, not any particular wording.
    #[test]
    fn a_suppressed_menu_says_so_on_the_tooltip_and_names_the_remedy() {
        let mut view = TrayView {
            running: true,
            node_connected: true,
            node: "connected".into(),
            ..Default::default()
        };

        let quiet = status(&view).tooltip;
        assert!(
            !quiet.to_lowercase().contains("blocked"),
            "an unsuppressed menu must not mention being blocked; got {quiet:?}"
        );

        view.menu_suppressed = true;
        let loud = status(&view).tooltip;
        assert!(
            loud.to_lowercase().contains("blocked"),
            "a suppressed menu must say so on the tooltip -- it is the only surface the user has \
             for a menu that did not appear (SPEC 3.1b-tp); got {loud:?}"
        );
        assert!(
            loud.to_lowercase().contains("again"),
            "the tooltip must name the remedy, because the suppression is per-click and clicking \
             again is the entire fix; got {loud:?}"
        );
    }

    /// The `Submenu` row whose label starts with `prefix`, or `None`.
    ///
    /// A prefix match rather than an exact one because the Cache row's label carries the live
    /// usage figure (see [`cache_label`]) and would otherwise have to be reconstructed here —
    /// which would make this helper a second copy of that formatting logic instead of a lookup.
    fn find_submenu<'a>(model: &'a MenuModel, prefix: &str) -> Option<&'a [MenuRow]> {
        model.rows.iter().find_map(|row| match row {
            MenuRow::Submenu { label, rows } if label.starts_with(prefix) => Some(rows.as_slice()),
            _ => None,
        })
    }

    /// **`build()` composes the six shared group builders verbatim — dig_ecosystem#2253.**
    ///
    /// This is PR1's whole point: the builders extracted for a second consumer (the window model,
    /// PR2) must still be EXACTLY what `build()` puts in each submenu, or the two containers would
    /// silently drift the moment either one changes. Rather than capturing `build()`'s own output
    /// and asserting it matches itself — which would kill no mutant, since any bug in `build`
    /// would land in both sides of the comparison — each submenu is checked against a call to the
    /// now-`pub(crate)` builder made from OUTSIDE `build`, exactly as PR2's window model will call
    /// it. If `build` ever stopped calling one of these functions, or called it with different
    /// arguments, this diverges; today, with the extraction unchanged, it must not.
    #[test]
    fn build_composes_the_six_shared_group_builders_verbatim() {
        for account_state in EVERY_STATE {
            for second_factor in [false, true] {
                for cache in [
                    None,
                    Some(crate::cache::CacheSnapshot {
                        cap_bytes: crate::cache::GIB,
                        used_bytes: 350 * crate::cache::MIB,
                    }),
                ] {
                    let mut fixture = view(account_state.clone());
                    fixture.second_factor = second_factor;
                    fixture.cache = cache;
                    let account = fixture.account();

                    let menu = build(&fixture);

                    assert_eq!(
                        find_submenu(&menu, "View Account"),
                        Some(view_account_actions(&fixture, &account).as_slice()),
                        "{account_state:?}/{second_factor}/{cache:?}: View Account drifted from \
                         view_account_actions"
                    );
                    assert_eq!(
                        find_submenu(&menu, "Manage Account"),
                        Some(management_actions(&account).as_slice()),
                        "{account_state:?}/{second_factor}/{cache:?}: Manage Account drifted from \
                         management_actions"
                    );
                    assert_eq!(
                        find_submenu(&menu, "Wallet"),
                        Some(wallet_actions(&fixture, &account).as_slice()),
                        "{account_state:?}/{second_factor}/{cache:?}: Wallet drifted from \
                         wallet_actions"
                    );
                    assert_eq!(
                        find_submenu(&menu, "Security"),
                        Some(
                            security_actions(&account, second_factor, fixture.did.as_deref())
                                .as_slice()
                        ),
                        "{account_state:?}/{second_factor}/{cache:?}: Security drifted from \
                         security_actions"
                    );
                    assert_eq!(
                        find_submenu(&menu, "Cache"),
                        Some(cache_actions(cache.as_ref()).as_slice()),
                        "{account_state:?}/{second_factor}/{cache:?}: Cache drifted from \
                         cache_actions"
                    );
                    assert_eq!(
                        find_submenu(&menu, "Apps"),
                        Some(apps_actions().as_slice()),
                        "{account_state:?}/{second_factor}/{cache:?}: Apps drifted from \
                         apps_actions"
                    );
                }
            }
        }
    }

    // ---- The trim (dig_ecosystem#2253). ----

    /// **A host with an app window gets exactly four action rows, in every account state.**
    ///
    /// Counted from the RENDERED menu rather than from a list this test also writes: a count derived
    /// from the same constant the builder uses would agree with any bug the builder had. Separators
    /// are excluded because a separator is not a row a person can click, and the promise is about
    /// what they can click.
    #[test]
    fn a_windowed_host_gets_four_rows_in_every_account_state() {
        for account_state in EVERY_STATE {
            let view = TrayView {
                window_host: WindowHost::Available,
                ..view(account_state.clone())
            };
            let menu = build(&view);
            let actions: Vec<TrayAction> = menu
                .rows
                .iter()
                .filter_map(|row| match row {
                    MenuRow::Action { action, .. } => Some(*action),
                    _ => None,
                })
                .collect();
            assert_eq!(
                actions.len(),
                4,
                "{account_state:?}: the trimmed tray must be four rows, not {actions:?}"
            );
            assert!(
                menu.rows
                    .iter()
                    .all(|row| !matches!(row, MenuRow::Submenu { .. })),
                "{account_state:?}: the trimmed tray has no submenus left to open"
            );
            // The last three are fixed. The first is polymorphic — that is the whole point of
            // `urgent_account_row` — so it is checked by state below rather than pinned here.
            assert_eq!(
                &actions[1..],
                &[TrayAction::Open, TrayAction::OpenWindow, TrayAction::Quit],
                "{account_state:?}: read, the way in, and the way out are not negotiable"
            );
        }
    }

    /// **The first row always names the one thing THIS account needs**, and the verb differs by state.
    ///
    /// Pinned per state, because the row being merely PRESENT is what a `SetUpAccount`-everywhere bug
    /// would also satisfy — and offering "Set up my DIG Account" to someone whose account is simply
    /// locked is worse than offering nothing.
    #[test]
    fn the_trimmed_trays_first_row_is_the_verb_that_state_actually_needs() {
        let expected = [
            (AccountState::Unsupported, TrayAction::SetUpAccount),
            (AccountState::Absent, TrayAction::SetUpAccount),
            (AccountState::Locked, TrayAction::Unlock),
            (AccountState::NeedsPassword, TrayAction::SetAccountPassword),
            (AccountState::Unopenable, TrayAction::ExplainUnopenable),
            (
                AccountState::Unlocked { recoverable: true },
                TrayAction::LockNow,
            ),
            (
                AccountState::Unlocked { recoverable: false },
                TrayAction::LockNow,
            ),
        ];
        assert_eq!(
            expected.len(),
            EVERY_STATE.len(),
            "a state was added without deciding what its urgent row says"
        );
        for (account_state, action) in expected {
            let view = TrayView {
                window_host: WindowHost::Available,
                ..view(account_state.clone())
            };
            let first = build(&view)
                .rows
                .into_iter()
                .find_map(|row| match row {
                    MenuRow::Action { action, .. } => Some(action),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{account_state:?}: the trimmed tray has no first row"));
            assert_eq!(first, action, "{account_state:?}: wrong urgent row");
        }
    }

    /// **A host with NO app window keeps the whole menu**, because the tray is then the only surface.
    ///
    /// The control for the trim tests above: without it, a `build()` that trimmed unconditionally
    /// would pass every one of them while stranding macOS and every display-less Linux session.
    #[test]
    fn a_windowless_host_keeps_the_full_menu() {
        for account_state in EVERY_STATE {
            let windowless = TrayView {
                window_host: WindowHost::Unavailable,
                ..view(account_state.clone())
            };
            let windowed = TrayView {
                window_host: WindowHost::Available,
                ..view(account_state.clone())
            };
            let full = build(&windowless);
            let trimmed = build(&windowed);

            assert_ne!(
                full, trimmed,
                "{account_state:?}: the two hosts must render differently, or nothing was trimmed"
            );
            assert!(
                full.rows
                    .iter()
                    .any(|row| matches!(row, MenuRow::Submenu { .. })),
                "{account_state:?}: a windowless host lost its submenus and has nowhere left to go"
            );
            for escape in [TrayAction::OpenLogs, TrayAction::Quit] {
                assert!(
                    full.is_enabled(escape),
                    "{account_state:?}: {escape:?} must stay on a tray that is the only surface"
                );
            }
            // `OpenWindow` is the one verb that must NOT be offered here: a row that opens a window
            // this host cannot open is a control guaranteed to do nothing, which is the dead end
            // dig_ecosystem#1800 removed.
            assert!(
                !full.offers(TrayAction::OpenWindow),
                "{account_state:?}: a host with no window must not offer to open one"
            );
        }
    }

    /// **Every action the full menu offers is either kept on the trimmed tray or reachable in the
    /// window.** The reachability invariant, asserted from the TRAY's side.
    ///
    /// `window_model` states the same property from the window's side over a much wider fixture set;
    /// this one exists because the trim lives HERE, and a change to `trimmed` that dropped a spine
    /// row would otherwise only be caught in another module's suite.
    #[test]
    fn the_trim_strands_nothing() {
        use crate::window_model::{build as window, Tab, SUBSUMED_BY_TAB, TRAY_SPINE};
        for account_state in EVERY_STATE {
            let view = TrayView {
                window_host: WindowHost::Available,
                ..view(account_state.clone())
            };
            let windowless = TrayView {
                window_host: WindowHost::Unavailable,
                ..view.clone()
            };

            let mut reachable: Vec<TrayAction> = build(&view)
                .rows
                .iter()
                .filter_map(|row| match row {
                    MenuRow::Action { action, .. } => Some(*action),
                    _ => None,
                })
                .collect();
            reachable.extend(window(&view).tabs.iter().flat_map(Tab::actions));
            reachable.extend(SUBSUMED_BY_TAB.iter().map(|(action, _)| *action));

            for (_, offered) in action_ids(&build(&windowless).rows) {
                assert!(
                    reachable.contains(&offered),
                    "{account_state:?}: {offered:?} is offered on a windowless host and reachable \
                     nowhere once the tray is trimmed"
                );
            }
            // Every kept row is a declared spine action, so the spine and the trim cannot drift.
            for kept in build(&view).rows.iter().filter_map(|row| match row {
                MenuRow::Action { action, .. } => Some(*action),
                _ => None,
            }) {
                assert!(
                    TRAY_SPINE.contains(&kept),
                    "{account_state:?}: {kept:?} was kept on the tray but is not in TRAY_SPINE"
                );
            }
        }
    }
}
