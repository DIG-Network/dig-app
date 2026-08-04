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
    /// The live cause is a **legacy raw-seed blob**: every Windows/macOS host that has ever run dig-app
    /// auto-enrolled `account.default` at first boot, and those blobs carry the old `DIGVK1` shape. Under
    /// `dig-account` 0.2 they neither unlock (`SessionError::LegacySeedFormat`) nor re-enrol at the same id
    /// (`AlreadyExists`) — they are WEDGED, not merely fail-closed. Before this state existed the boot
    /// swallowed that into a `tracing::warn!` and returned `None`, so the tray reported a locked account and
    /// the user silently lost signing with no in-app route out. This state is what makes that impossible.
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

/// Everything the tray is rendered from — one snapshot, read once per repaint.
#[derive(Debug, Clone, Default)]
pub struct TrayView {
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
    /// Whether the SAME observation that produced [`receive_address`](Self::receive_address) found the
    /// residency unlocked yet unable to derive an address — a genuine defect, not the ordinary "not
    /// unlocked" case (dig_ecosystem#2059).
    ///
    /// Only meaningful when `receive_address` is `None`: it is what tells
    /// `wallet::overview::WalletOverview::of_tray` apart the two reasons a `None` can mean — an account
    /// that is simply not unlocked (say "unlock it"), versus one that WAS unlocked at the moment of
    /// observation and still failed to derive (saying "unlock it" would name a remedy the user already
    /// performed). The shell fills both fields from a single call to
    /// `AccountResidency::observe_receiving_address` so the two facts describe the SAME instant —
    /// reading unlock-state and the address as two separate calls lets an idle relock or `Lock now` land
    /// between them and misreport an ordinary lock as this fault.
    pub address_derivation_failed: bool,
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
    /// The node's content-cache cap + usage, or `None` when no node is connected to report it
    /// (dig_ecosystem#2002).
    ///
    /// Filled from the node's `control.status` snapshot, so the tray shows the node's real numbers.
    /// `None` is the honest value when the node is unreachable — the cache submenu then says the cap
    /// cannot be changed until a node is connected rather than inventing a figure.
    pub cache: Option<crate::cache::CacheSnapshot>,
}

impl TrayView {
    /// The account state, defaulting to [`AccountState::Absent`] before the first boot has reported.
    fn account(&self) -> AccountState {
        self.account.clone().unwrap_or(AccountState::Absent)
    }
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
/// wants to be; `stable_ids_are_unique_across_every_menu_this_shell_can_build` holds the uniqueness.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrayAction {
    /// Show everything the tray knows, in full, in a window that can hold it.
    ///
    /// This is where the five former greyed status rows went. It is enabled in every state, because what
    /// it promises — telling the user what is going on — is something the app can always do, even (and
    /// especially) when everything else is broken.
    ShowStatus,
    /// Ask for a DIG link in a native input window, then open it through the local node.
    ///
    /// The tray equivalent of `dign open` (dig_ecosystem#1821). Enabled in EVERY state, deliberately:
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
    /// There is deliberately no `CreateDid` action: `dig-account`'s minter is a Phase-2 stub, so an action
    /// that mints does not exist and therefore is not offered — not even disabled. Because no
    /// [`TrayAction`] can mint, "the tray cannot spend XCH on a DID" is structural rather than a property
    /// of one `enabled: false`.
    AboutDid,
    /// Copy the account's `xch1…` receive address to the clipboard (dig_ecosystem#1850).
    ///
    /// The address comes from [`TrayView::receive_address`], which the shell fills from the account's own
    /// MONEY key — never from [`profile_id`](TrayView::profile_id), which is the identity public key and
    /// would be a confidently wrong string to hand someone who means to pay you. Offered only where an
    /// address can exist; see `wallet_actions`.
    CopyReceiveAddress,
    /// Show the wallet: the receive address, the balance (or precisely why it is not known), and what the
    /// wallet cannot do yet.
    ///
    /// There is deliberately no `Send`: spending needs the money path, which is parked (#1702). Because no
    /// [`TrayAction`] can move funds, "the tray cannot spend" is STRUCTURAL rather than one
    /// `enabled: false` away from being wrong — the same discipline [`AboutDid`](Self::AboutDid) follows
    /// for minting (dig_ecosystem#1841).
    AboutWallet,
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
    /// Open another DIG app from the **Apps** group (dig_ecosystem#2101).
    ///
    /// Carries the [`AppId`](crate::apps::AppId) of the registry row clicked, so ONE action serves
    /// every app and adding one (dig-email, dig-video-chat — §5.4) is a [`crate::apps::APPS`] row, not
    /// a new variant here. The shell decides launch-vs-notice through the pure
    /// [`plan_launch`](crate::apps::plan_launch) seam and, when the app is present, spawns it DETACHED
    /// off the prompt thread (#78) with no argv identity — never a silent no-op when it is absent
    /// (§6.1), which today is the only reachable case.
    LaunchApp(crate::apps::AppId),
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
/// explainer — and nothing that moves money, since the money path is parked (#1702). Its parent label is
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
///   first-run dead end #1800 removed and #1826 exists to prevent. In the ordinary unlocked state it is
///   absent and the menu is exactly the spine.
pub fn build(view: &TrayView) -> MenuModel {
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
        security_actions(&account, view.second_factor),
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
fn urgent_account_row(account: &AccountState) -> Option<MenuRow> {
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
        // Unlocked and working: nothing is owed. Locking lives under Security.
        AccountState::Unlocked { .. } => None,
    }
}

/// **View Account** — the read-only views of the account. Nothing here changes anything.
///
/// That is the submenu's whole contract, and it is why the destructive verbs are NOT here: a person opening
/// "View" must not find "Remove this account from this computer" one mis-click away.
///
/// The recovery-phrase row is *either* "show it" or "you don't have one" — never both, because offering a
/// disabled "show my recovery phrase" to someone who has none tells them nothing about why (#1800).
fn view_account_actions(view: &TrayView, account: &AccountState) -> Vec<MenuRow> {
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
/// The money path is PARKED (#1702). A `Send…` row would therefore be permanently greyed, and a greyed row
/// that cannot say when it will work is the exact defect #1800 removed from this menu. So spending is not
/// offered *at all* — no [`TrayAction`] can spend, which makes "the tray cannot move funds" a structural
/// fact rather than one `enabled: false` away from being wrong. [`AboutWallet`](TrayAction::AboutWallet)
/// explains the situation in a window that has room for it.
///
/// The same reasoning already governs DIDs ([`AboutDid`](TrayAction::AboutDid)): the tray does not offer
/// verbs the app cannot perform.
///
/// # The balance row
///
/// "What do I hold?" is half of what a wallet is for, so the answer belongs on the menu rather than one
/// click into a window. It is ALWAYS present and ALWAYS enabled: today nothing can read a balance — the
/// node's control catalog serves no wallet method — so in practice the row reads
/// `Balance not known — no DIG node is running…`, and that sentence is the honest content the ticket
/// asked for, not a placeholder. Its label carries the short reason and clicking it opens the window
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
fn wallet_actions(view: &TrayView, account: &AccountState) -> Vec<MenuRow> {
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
        crate::wallet::overview::menu_balance_label(
            &crate::wallet::overview::WalletOverview::of_tray(view).balance,
        ),
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
fn security_actions(account: &AccountState, second_factor: bool) -> Vec<MenuRow> {
    match account {
        AccountState::Unlocked { .. } => {
            let mut rows = vec![MenuRow::action(TrayAction::LockNow, "Lock now", true)];
            rows.extend(two_factor_row(true, second_factor));
            rows.push(MenuRow::Separator);
            rows.extend(paired_app_rows());
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
/// leaving each caller to remember the condition. Neither is ever greyed: a locked account sees no row
/// at all, and the `Unlock…` row above it is the way forward (#1800).
fn paired_app_rows() -> Vec<MenuRow> {
    vec![
        MenuRow::action(TrayAction::PairAnApp, "Pair an app…", true),
        MenuRow::action(TrayAction::ManagePairedApps, "Paired apps…", true),
    ]
}

/// The `Manage my DIG Account` submenu — **reachable in every state**, which is the whole point.
///
/// Before #1800, `Set up` and `Restore` were enabled only while `account == Absent`, so the machine this
/// was measured on — which had an account with no recovery phrase — offered setup greyed, restore greyed,
/// show-phrase greyed, and a single explainer whose advice ("create a new account") named a control that
/// was greyed out. Four dead rows and no way forward.
///
/// The verbs here are therefore gated on their REAL precondition — whether an account exists, which
/// decides whether the verb CREATES or REPLACES — never on it being absent.
fn management_actions(account: &AccountState) -> Vec<MenuRow> {
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
fn apps_actions() -> Vec<MenuRow> {
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
fn cache_label(cache: Option<&crate::cache::CacheSnapshot>) -> String {
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
fn cache_actions(cache: Option<&crate::cache::CacheSnapshot>) -> Vec<MenuRow> {
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

/// One preset row's label, marking the preset that is the node's CURRENT cap so the active choice is
/// visible at a glance, and tagging the default so a person can find it deliberately.
fn cache_preset_label(bytes: u64, current_cap: u64) -> String {
    use crate::cache::{format_cap, DEFAULT_CACHE_CAP_BYTES};
    let mut label = format_cap(bytes);
    if bytes == DEFAULT_CACHE_CAP_BYTES {
        label.push_str(" (default)");
    }
    if bytes == current_cap {
        label.push_str("  ✓ current");
    }
    label
}

/// The DID explainer's label.
///
/// It names the cost rather than hiding it in the dialog, so a person knows before they open it that a
/// DID is a real spend (§3.7 — mainnet is real money). It deliberately no longer says "optional": a DID
/// is the bedrock of a DIG Account (dig_ecosystem#1820), and calling it optional was the copy that made a
/// required step look like a nicety. It must not promise to CREATE one either: nothing can mint yet.
const DID_LABEL: &str = "About on-chain DIDs (required, costs XCH)…";

/// The DID line. Absent is the state of every account today, because minting is not implemented — so it
/// names the remaining step AND why it cannot be taken, rather than reading as something the user has
/// neglected (dig_ecosystem#1820).
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
            account_state(true, at_rest_of(true, false, OpenAttempt::NotAttempted), None),
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

    fn view(account: AccountState) -> TrayView {
        // Only an UNLOCKED account can derive an address, so the fixture mirrors that rather than handing
        // every state an address the shell could never have produced for it.
        let receive_address =
            matches!(account, AccountState::Unlocked { .. }).then(|| FIXTURE_ADDRESS.to_string());
        TrayView {
            running: true,
            node_connected: true,
            node: "Node v0.65.0 · 3 capsule(s) cached · 1 store(s) hosted".to_string(),
            account: Some(account),
            receive_address,
            address_derivation_failed: false,
            profile_id: Some("a".repeat(96)),
            did: None,
            second_factor: false,
            hotkey: None,
            // A connected node reporting a default 1 GiB cap with 350 MiB in use — the ordinary
            // success case. Tests that need the disconnected surface null this out explicitly.
            cache: Some(crate::cache::CacheSnapshot {
                cap_bytes: crate::cache::GIB,
                used_bytes: 350 * crate::cache::MIB,
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

        let ids_before: std::collections::HashMap<_, _> = action_ids(&before.rows)
            .into_iter()
            .map(|(id, a)| (a, id))
            .collect();
        let ids_after: std::collections::HashMap<_, _> = action_ids(&after.rows)
            .into_iter()
            .map(|(id, a)| (a, id))
            .collect();

        assert!(!ids_before.is_empty(), "the fixture menu must offer verbs");
        for (action, id) in &ids_before {
            assert_eq!(
                ids_after.get(action),
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

    /// The rows appear ONLY while the account is unlocked, and are never greyed anywhere.
    ///
    /// Both halves matter and neither implies the other: an implementation that always offered them
    /// would pass a greyness check while putting a row in front of a locked user that could only fail,
    /// and one that always hid them would pass the "never greyed" check by offering nothing at all.
    #[test]
    fn the_paired_app_rows_appear_only_when_the_account_is_unlocked_and_never_greyed() {
        for account in EVERY_STATE {
            let model = build(&view(account.clone()));
            let unlocked = matches!(account, AccountState::Unlocked { .. });
            for action in [TrayAction::PairAnApp, TrayAction::ManagePairedApps] {
                assert_eq!(
                    model.offers(action),
                    unlocked,
                    "{action:?} in {account:?}: pairing seals under the account key, so an unlocked                      account is its real precondition"
                );
                if model.offers(action) {
                    assert!(
                        model.is_enabled(action),
                        "{action:?} must never be offered greyed"
                    );
                }
            }
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
                for banned in ["terminal", "command line", "console", "dign ", "cmd"] {
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

    /// **Regression (#1773).** No tray row may offer to MINT a DID, in any account state — minting does
    /// not exist (`dig-account`'s minter is a Phase-2 stub). The guarantee is STRUCTURAL (no `TrayAction`
    /// mints), so this also guards a future lane reintroducing one before the minter exists.
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
        assert!(
            !top_level.contains(&TrayAction::LockNow),
            "locking belongs under Security, not beside the escapes: {top_level:?}"
        );
        assert!(
            menu.is_enabled(TrayAction::LockNow),
            "…but it must still be reachable there"
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
    /// to a `dign` command, because the installed `dign` on a shared bin dir is dig-node's alias, not
    /// dig-app's CLI (dig_ecosystem#1788), so that advice hands them the wrong tool.
    #[test]
    fn linux_tray_advice_names_the_missing_library_and_not_a_wrong_cli() {
        let advice = tray_unavailable_advice("no display", crate::Os::Linux);
        assert!(advice.contains("libayatana-appindicator3-1"), "{advice}");
        assert!(
            advice.contains("no display"),
            "the real reason must survive: {advice}"
        );
        assert!(
            !advice.contains("dign"),
            "`dign` on a shared bin dir is dig-node's alias (#1788), not dig-app's CLI: {advice}"
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
        every_action(&MenuModel {
            rows: submenu(&build(&view(account)), "Wallet"),
        })
        .into_iter()
        .map(|(_, label, _)| label)
        .collect()
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
            // The unlocked states DO have an address, so their row fails for the only remaining
            // reason: nothing can read a balance for it yet.
            (
                AccountState::Unlocked { recoverable: true },
                "this node cannot read balances yet",
            ),
            (
                AccountState::Unlocked { recoverable: false },
                "this node cannot read balances yet",
            ),
        ];
        for (account, clause) in expected {
            let label = wallet_labels(account.clone())
                .into_iter()
                .find(|label| label.starts_with("Balance"))
                .expect("a balance row in every state");
            assert!(
                label.contains(clause),
                "{account:?}: expected {clause:?}, got {label:?}"
            );
        }
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
        let unreported = MenuModel {
            rows: submenu(&build(&TrayView::default()), "Wallet"),
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
}
