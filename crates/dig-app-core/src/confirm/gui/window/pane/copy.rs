//! Every word a content pane says, named, in one place.
//!
//! # Why this module exists rather than string literals at the call sites
//!
//! dig-app has no i18n layer today (dig_ecosystem#2328). The interim rule that keeps the eventual
//! catalog swap mechanical is this: a pane never holds a literal inside a paint call, and
//! state-dependent copy is keyed by its state in an EXHAUSTIVE match — so adding a state makes the
//! compiler ask for its sentence rather than letting a pane fall through to a wrong one.
//!
//! When a catalog does arrive, each `const` here becomes a lookup and no call site moves.
//!
//! # The voice
//!
//! Plain language, complete sentences, and never a dead end: a sentence that says something is
//! unavailable also says what would change that (`window_model::label_names_a_remedy` is the same
//! rule one level down, on row labels).

use crate::window_model::TabId;

/// The sentence under a tab's title, saying what the tab is for.
///
/// # Why this is one exhaustive match and not a field each pane may set (dig_ecosystem#2356)
///
/// It was optional, and two of seven panes used it — so five tabs opened with a bare word above a
/// card. A lead a pane can forget is a lead most panes forget. Here, a new [`TabId`] cannot compile
/// without writing its sentence, and every tab opens identically because the frame draws it.
///
/// # The voice
///
/// A lead says what the TAB IS FOR, addressed to the person reading it. It never explains the app's
/// own design conventions back to them: Settings used to close with *"Each group says what a change
/// costs before you make it"*, which is a sentence about how the tab was built, and the Cache tab
/// carried *"This form is the finished layout"*, which is a sentence about the project. Both are
/// true and neither is the reader's business.
pub(crate) fn lead(tab: TabId) -> &'static str {
    match tab {
        TabId::Home => {
            "What DIG is doing on this computer, the other DIG apps it can open, and where to look \
             when something is wrong."
        }
        TabId::Account => {
            "The DIG Account this computer holds: what it is, how it is protected, and how to \
             change which account this is."
        }
        TabId::Wallet => "Where money arrives, and what this account is holding.",
        TabId::Content => {
            "What this computer keeps on disk for the network, and how much room to give it."
        }
        TabId::Settings => "How DIG looks after itself on this computer.",
    }
}

/// The persistent header strip the whole window carries, under the chrome and above every tab.
///
/// # Why these two facts, on every tab (dig_ecosystem#2358)
///
/// They used to live on the Status tab, which meant a person on Wallet had to change tabs to learn
/// the node was down — and a down node is frequently WHY the balance beside them reads "Not known".
/// The agent and the node are the two facts that explain the rest of the window, so the window
/// carries them wherever the reader is standing.
pub(crate) mod header {
    /// The label before the agent's state.
    pub(crate) const AGENT_LABEL: &str = "DIG";
    /// The label before the node's state.
    pub(crate) const NODE_LABEL: &str = "Node";
    /// The label before the wallet chain replica's state.
    ///
    /// "Chain", not "Sync": the badge beside it is frequently a statement that no syncing is
    /// happening, and a label promising a sync would contradict its own value.
    pub(crate) const CHAIN_LABEL: &str = "Chain";
    /// The label before the block the chain replica has reached (dig_ecosystem#2806).
    ///
    /// "Chain height", not "Block" or "Peak": it has to be distinguishable at a glance from the two
    /// peer COUNTS it is drawn beside, and a seven-digit figure under a one-word label is exactly
    /// what a reader would otherwise take for a third count.
    pub(crate) const CHAIN_HEIGHT_LABEL: &str = "Chain height";
    /// The label before the peak this node's own Chia peers announced.
    ///
    /// Names WHOSE height it is, for the same reason the two peer counts name their networks. It
    /// sits beside a `Chain height` that is this machine's replica, and the two legitimately differ
    /// — the replica trails while it catches up. Under a bare label like `Network height` a reader
    /// would take the pair for one number reported twice and read the gap as a contradiction; naming
    /// the peers makes it the ordinary reading it is.
    pub(crate) const CHIA_PEER_HEIGHT_LABEL: &str = "Chia peer height";
    /// The label before how far the replica trails its peers (dig_ecosystem#2820).
    ///
    /// "Behind" states the RELATION, which is the thing being asked about — the two heights beside
    /// it already state the positions. A person watching a sync wants to know the distance is
    /// shrinking, and a label naming the distance is what makes the figure under it a progress
    /// rather than a third height to compare by eye.
    pub(crate) const BEHIND_LABEL: &str = "Behind";
}

/// The Home pane.
pub(crate) mod home {
    /// The card grouping the facts about the running agent.
    pub(crate) const AGENT_CARD: &str = "This computer";
    /// The card grouping what the node is doing.
    pub(crate) const NODE_CARD: &str = "Node connection";
    /// The card grouping the content cache.
    pub(crate) const CACHE_CARD: &str = "Content cached";
    /// The card holding the pane's actions.
    pub(crate) const ACTIONS_CARD: &str = "Diagnostics";

    /// The readout naming whether the background agent is running.
    pub(crate) const AGENT_LABEL: &str = "DIG agent";
    /// The readout naming the installed version.
    pub(crate) const VERSION_LABEL: &str = "Version";
    /// The card holding the figures about what this computer shares.
    pub(crate) const SHARING_CARD: &str = "What this computer is sharing";
    /// The four figures that card reports, in render order.
    ///
    /// # Why the first one is not called `Stores hosted` (dig_ecosystem#2397)
    ///
    /// It was, and the word named two different sets on one screen. The figure behind it is
    /// `control.status`'s `hosted_store_count`, which counts only stores with content CACHED. The
    /// Content tab's list comes from `control.hostedStores.list`, which dig-node's `SPEC.md` §7.6
    /// defines normatively as cached ∪ pinned — a pinned-but-uncached store MUST appear there. On the
    /// live node those are 3 and 5.
    ///
    /// Both numbers are right, so the fix is the label rather than the arithmetic. Saying what the
    /// figure actually counts lets the two coexist: a reader who notices the difference resolves it
    /// on the Content tab, where the two extra rows say plainly that nothing is cached for them yet.
    pub(crate) const SHARING_LABELS: [&str; 4] = [
        "Stores with cached content",
        "Capsules cached",
        "Stores pinned",
        "Uptime",
    ];

    /// Said in place of the sharing figures when no node has reported them, naming THIS machine's
    /// situation rather than the project's build order.
    ///
    /// # One sentence per state, and each one names its own remedy
    ///
    /// It used to be a single const, *"Not read from the node yet."*, which described dig-app's
    /// wiring rather than the reader's computer — the voice dig_ecosystem#2356 removed from the
    /// unwired caveat. The three states have three different remedies: start DIG, wait for it to find
    /// a node, or wait for the first read. Keyed on the same two facts
    /// [`PaneFacts::node_state`](super::super::facts::PaneFacts::node_state) reads, in an exhaustive
    /// match, so the badge above the card and this sentence cannot come to describe different
    /// machines.
    pub(crate) fn sharing_unknown(agent_running: bool, node_connected: bool) -> &'static str {
        match (agent_running, node_connected) {
            (false, _) => {
                "The DIG agent has not started yet, so nothing has asked a node what this computer \
                 is sharing."
            }
            (true, false) => {
                "DIG has not found a node on this computer yet, and only a node can say what is \
                 being shared from here."
            }
            (true, true) => {
                "DIG is talking to a node but has not read these figures from it yet. They fill in \
                 within a few seconds."
            }
        }
    }

    /// Said in place of a cache reading when no node has reported one.
    pub(crate) const CACHE_UNKNOWN: &str =
        "No node has reported its cache yet. Connect a node to see how much space DIG is using.";
    /// Said beneath the diagnostics actions.
    pub(crate) const DIAGNOSTICS_HINT: &str =
        "If DIG is not behaving, the log folder is the first place to look.";
}

/// The Apps pane.
pub(crate) mod apps {
    /// The card holding any verb the model put beside the launchers that is not an app's own.
    pub(crate) const OTHER_CARD: &str = "Also in the launcher";
    /// The closing line, which is the tab's answer to "where do I install these?".
    ///
    /// The honest form of the presence question while dig-app cannot READ presence
    /// (dig_ecosystem#2330). It says how apps arrive and what a click will tell you, which is
    /// everything a person can act on — where an "Installed" chip would be a guess drawn as a fact.
    pub(crate) const INSTALL_NOTE: &str =
        "DIG apps are installed alongside DIG itself, so there is nothing to download here. Open \
         one and DIG will either start it or say that this install does not carry it yet.";
}

/// The Settings pane.
///
/// The order the groups are declared in is the order they are drawn in, and it is deliberate:
/// updates first because it is the one a person comes here for, then the node, then the shortcut.
pub(crate) mod settings {
    /// The updates group.
    pub(crate) const UPDATES_CARD: &str = "Automatic updates";
    /// What the updates group controls.
    pub(crate) const UPDATES_ABOUT: &str =
        "Whether DIG installs its own updates, and which builds it follows.";
    /// Said before the update controls, because every one of them costs this.
    ///
    /// The row labels carry it too — that is [`crate::tray_menu`]'s rule, and this does not replace
    /// it. Saying it once above the group is what makes the cost visible to someone reading the
    /// card rather than reading a button.
    pub(crate) const UPDATES_COST: &str =
        "Changing any of these asks Windows for an administrator, because the update schedule \
         belongs to the whole computer rather than to your account.";
    /// The readout naming which feed DIG follows.
    pub(crate) const CHANNEL_LABEL: &str = "Following";
    /// The readout naming whether the daily check exists.
    pub(crate) const SCHEDULE_LABEL: &str = "Daily check";
    /// The panel grouping the channel choice.
    pub(crate) const CHANNEL_PANEL: &str = "Which builds to follow";
    /// The label above the channel dropdown.
    pub(crate) const CHANNEL_FIELD: &str = "Channel";
    /// Shown in the chooser when no beacon has reported a channel — never the first option, which
    /// would be a setting nobody reported drawn as one that was.
    pub(crate) const CHANNEL_UNKNOWN: &str = "Not reported";

    /// The connection group.
    pub(crate) const NODE_CARD: &str = "Node connection";
    /// What the connection group controls.
    pub(crate) const NODE_ABOUT: &str =
        "Which DIG node this computer reads content through. Leave it automatic unless you run a \
         node of your own.";
    /// The field label.
    pub(crate) const NODE_FIELD: &str = "Node address";
    /// What an empty field means — never a fake value.
    pub(crate) const NODE_PLACEHOLDER: &str = "Automatic";
    /// The field's help text.
    pub(crate) const NODE_HELP: &str =
        "A host, or a full http address. Leave it empty and DIG finds a node itself.";
    /// The readout naming what DIG will actually dial.
    pub(crate) const NODE_EFFECTIVE: &str = "DIG will use";
    /// The cost of changing the node, said before the field.
    pub(crate) const NODE_COST: &str =
        "A saved address is used the next time DIG starts, so restart DIG after changing it.";
    /// The button that saves the typed address.
    pub(crate) const NODE_SAVE: &str = "Save address";
    /// The escape back to the automatic ladder — always offered, so a bad address is never a trap.
    pub(crate) const NODE_AUTOMATIC: &str = "Go back to automatic";
    /// The button that dials the address to see whether anything is there.
    pub(crate) const NODE_TEST: &str = "Test connection";

    /// The shortcut group.
    pub(crate) const SHORTCUT_CARD: &str = "Keyboard shortcut";
    /// What the shortcut group controls.
    pub(crate) const SHORTCUT_ABOUT: &str = "The keys that open the DIG address bar from anywhere.";
    /// The field label.
    pub(crate) const SHORTCUT_FIELD: &str = "Shortcut";
    /// The field's help text.
    pub(crate) const SHORTCUT_HELP: &str =
        "Modifiers and one key, written as Ctrl+Shift+D. Leave it empty for the default.";
    /// The cost of the default, stated because DIG takes the chord from Windows.
    pub(crate) const SHORTCUT_COST: &str =
        "While DIG is running it owns this chord, so Windows will not use it for anything else. \
         The default, Alt+Space, is the chord Windows uses for a window's own menu.";
    /// The button that saves the typed chord.
    pub(crate) const SHORTCUT_SAVE: &str = "Save shortcut";
    /// The escape back to the shipped chord.
    pub(crate) const SHORTCUT_DEFAULT: &str = "Go back to the default";
    /// The readout naming the chord in force.
    pub(crate) const SHORTCUT_EFFECTIVE: &str = "In use";

    /// The notifications group (dig_ecosystem#2548).
    pub(crate) const NOTIFY_CARD: &str = "Notifications";
    /// What the notifications group controls.
    pub(crate) const NOTIFY_ABOUT: &str =
        "Whether DIG tells you when money arrives in your wallet.";
    /// The limitation, said in the card rather than discovered.
    ///
    /// A person who is told "DIG will notify me when I am paid" and then is not has been misled by
    /// an omission, so the real condition is named. It is the BACKGROUND SERVICE that has to be
    /// running, not this window: the service keeps the record of what arrived, and closing DIG
    /// delays the notification rather than losing it. An earlier version of this sentence said the
    /// opposite — that a payment arriving while DIG was closed would never be announced — which was
    /// never what the code did (dig_ecosystem#2548).
    pub(crate) const NOTIFY_COST: &str =
        "DIG tells you about a payment once it is confirmed on the blockchain. Payments that \
         arrive while this window is closed are still noticed, and you are told the next time you \
         open DIG. Nothing is noticed while the DIG background service is stopped.";
    /// The label above the on/off chooser.
    pub(crate) const NOTIFY_FIELD: &str = "When money arrives";
    /// The readout naming what DIG will actually do.
    pub(crate) const NOTIFY_EFFECTIVE: &str = "DIG will";
    /// What the readout says for each choice, in the words of the thing that will happen.
    pub(crate) const NOTIFY_ON: &str = "Show a notification";
    /// The other choice.
    pub(crate) const NOTIFY_OFF: &str = "Say nothing";

    /// Said after a setting has been written and read back.
    pub(crate) const SAVED: &str = "Saved.";
    /// Said when the settings file cannot be found or read at all, in place of the controls.
    ///
    /// The controls are REMOVED rather than disabled in this state, which is the rule PR #120
    /// established for the beacon: a switch that cannot move is a switch that will be tried.
    pub(crate) const NO_CONFIG: &str =
        "DIG cannot read its settings file on this computer, so these cannot be changed here. Open \
         the log folder from the Home tab to find out why.";

    /// What the connection test says while it is running.
    pub(crate) const TESTING: &str = "Asking the node…";
}

/// The Account pane.
pub(crate) mod account {
    use super::super::facts::AccountKind;

    /// The badge word for an account nothing has reported on yet.
    pub(crate) const UNREAD_BADGE: &str = "Not read yet";

    /// The wait, said in place of a state that has not been reported.
    ///
    /// # It denies the ROWS as well as the summary, deliberately
    ///
    /// `TrayView::account()` defaults an unreported account to `Absent`, so during the wait the
    /// verbs underneath are the ones for a computer with no account. A sentence that only said
    /// "still loading" would leave a person reading `Set up a new DIG Account…` as though their
    /// machine had none — which is the same wrong claim one step down.
    pub(crate) const UNREAD: &str =
        "DIG has not finished reading this computer's account yet. Neither this summary nor the \
         actions below are settled until it has.";

    /// The card naming the account's identity.
    pub(crate) const IDENTITY_CARD: &str = "Account identity";
    /// The readout naming the id a person hands to someone else.
    pub(crate) const DIG_ID_LABEL: &str = "DIG ID";
    /// Said in place of a DIG ID when this computer has no profile to identify.
    pub(crate) const DIG_ID_UNKNOWN: &str =
        "This computer has no DIG ID yet. Set up a DIG Account and one appears here.";

    /// Said above the verbs that destroy custody.
    ///
    /// It states what is LOST rather than that the action is dangerous: "be careful" is advice, and a
    /// person about to replace an account needs to know that the money at its address goes with it.
    pub(crate) const DESTRUCTIVE_CAVEAT: &str =
        "Replacing or removing this account erases its keys from this computer. Its identity, its \
         receive address, and anything held at that address go with it, and only its recovery \
         phrase can bring them back. Each of these asks you to confirm before anything happens.";

    /// What the account's state means, and how protected it is — in the reader's terms.
    ///
    /// # This is the ONE per-state sentence set, and it used to be two (dig_ecosystem#2357)
    ///
    /// The Account tab and the Security tab each carried a hand-maintained six-arm match over one
    /// [`AccountKind`]: `account::summary` said what the state MEANT, `security::protection` said
    /// whether the account was SAFE. They said mostly the same thing in different words — the locked
    /// arms were near-paraphrases — and each had a test asserting only its OWN internal consistency.
    /// Nothing compared them, so they could drift apart indefinitely while both suites stayed green,
    /// and a reader who visited both tabs would eventually be told two different things about one
    /// state. Merging the panes (dig_ecosystem#2358) removed the reason for the split, and this is
    /// the merge: one sentence per state, doing both jobs.
    ///
    /// [`the_account_pane_has_exactly_one_per_state_sentence`](super::super::account::tests::the_account_pane_has_exactly_one_per_state_sentence)
    /// is what keeps it one. It asserts the property directly — a second parallel set would put a
    /// second state-varying sentence on the pane — rather than checking that each set is internally
    /// consistent, which is the shape that let the drift persist.
    ///
    /// # Why every sentence is written per state, and why none of them flatters
    ///
    /// dig_ecosystem#2059: three different states were all told to "unlock", a remedy two of them
    /// cannot perform — an account sealed under a machine-generated password has no password to
    /// type, and one whose seal will not open has already failed at unlocking. An exhaustive match
    /// makes a seventh state ask for its own sentence instead of quietly inheriting one.
    ///
    /// And the two states that read calmly at a glance say plainly what they are, because the one
    /// failure a custody surface cannot have is implying an account is safer than it is:
    /// [`AccountKind::NeedsPassword`] is a lock anyone at this keyboard can open, and
    /// [`AccountKind::Unopenable`] is not protection at all — it is an account nobody can use.
    pub(crate) fn summary(kind: AccountKind) -> &'static str {
        match kind {
            AccountKind::Unsupported => {
                "This system cannot hold a DIG Account yet — it has no per-application credential \
                 store for DIG to seal one with, so there is nothing here to set up or to protect \
                 until that changes."
            }
            AccountKind::Absent => {
                "There is no DIG Account on this computer, so there is nothing here to protect yet. \
                 Setting one up creates your identity and your wallet, and gives you a recovery \
                 phrase to write down and keep."
            }
            AccountKind::Locked => {
                "Your account is here and sealed. Its identity and its funds are safe: nothing on \
                 this computer can sign with it or reveal its recovery phrase until you open it."
            }
            AccountKind::Unopenable => {
                "Your account's seal will not open, so nothing can sign with it or reveal anything. \
                 That is not protection — the account is unusable, and there is no repair. \
                 Replacing it below is the way forward, and its recovery phrase brings the same \
                 account back."
            }
            AccountKind::NeedsPassword => {
                "Your account is sealed with a password this computer made up, not one you chose. \
                 Anyone who can use this computer can open it. Choosing your own password is the \
                 single biggest thing you can do here, and your identity, your address and your \
                 funds all survive the change."
            }
            AccountKind::Unlocked => {
                "Your account is open right now, so anything on this computer that asks DIG to sign \
                 will be answered until you seal it again. Everything on this tab acts on this \
                 account."
            }
        }
    }
}

/// The protection half of the Account pane — the cards that answer "is my account safe right now".
///
/// A module of its own inside one pane's copy, because it is one of the pane's three narrative beats
/// (who you are, whether it is protected, how to change which account this is) and grouping it keeps
/// that structure legible. What it no longer holds is a second per-state sentence set: see
/// [`account::summary`].
pub(crate) mod protection {
    /// The card answering "is my account safe right now".
    pub(crate) const PROTECTION_CARD: &str = "How this account is protected";
    /// The card holding the second factor.
    pub(crate) const SECOND_FACTOR_CARD: &str = "Two-factor codes";
    /// The card holding the apps paired with this computer.
    pub(crate) const PAIRED_APPS_CARD: &str = "Paired apps";

    /// Said under the second-factor control once a factor is enrolled.
    pub(crate) const SECOND_FACTOR_ON: &str =
        "A code from your authenticator app is required before this account can be replaced or \
         removed.";
    /// Said under the second-factor control when one can be set up right now.
    pub(crate) const SECOND_FACTOR_OFF: &str =
        "Not set up. A second factor asks for a code from your authenticator app before this \
         account can be replaced or removed.";
    /// Said under the paired-apps controls.
    pub(crate) const PAIRED_APPS_HINT: &str =
        "Apps you pair can ask this computer to act for you. Review them here and unpair anything \
         you no longer use.";

    /// Said where a second factor could be OFFERED but is not, naming the way forward VERBATIM.
    ///
    /// # Why the remedy is quoted from the model rather than written here
    ///
    /// The row that opens the account differs by state — it is `Unlock…` for a sealed account and
    /// `Set a password for my DIG Account…` for one that has never had a password — and writing
    /// either literally here is how dig_ecosystem#2059 happened. Quoting whatever the model put at
    /// the top of this pane means the sentence cannot name a remedy this pane does not offer.
    pub(crate) fn second_factor_needs(lead: &str) -> String {
        format!(
            "Not set up. Setting one up seals a record with your account's own key, so your account \
             has to be open first. Use “{lead}” above."
        )
    }

    /// Said where paired apps could be MANAGED but are not, naming the way forward verbatim.
    pub(crate) fn pairing_needs(lead: &str) -> String {
        format!("Pairing an app needs your account open. Use “{lead}” above.")
    }
}

/// The profile half of the Account pane — which identity this account is presenting
/// (dig_ecosystem#2403).
///
/// # The one word this module may never use
///
/// **Delete.** A minted profile is a DID singleton and a store on the Chia blockchain, both
/// permanent; hiding one is a preference about THIS computer's lists and nothing else. Copy that
/// implies otherwise would be describing an act the app cannot perform and the chain would not
/// honour, and a person who believed it would think they had removed an identity that is still there
/// for anyone to resolve. [`no_profile_copy_implies_a_profile_can_be_deleted`](super::tests) is that
/// rule as an assertion.
pub(crate) mod profiles {
    use crate::profiles::CreationBlocked;

    /// The card holding the list and its controls.
    pub(crate) const CARD: &str = "Profiles on this account";
    /// The panel holding what a profile is and why one cannot be created yet.
    pub(crate) const CREATE_PANEL: &str = "Creating a profile";

    /// Said while nobody has yet measured whether this node can create a profile.
    ///
    /// Delegated to [`crate::profiles::copy::CHECKING_CREATION`] rather than written again here, for
    /// the reason [`cannot_create`] is: the card and the tray's About notice must say one sentence.
    pub(crate) const CHECKING_CREATION: &str = crate::profiles::copy::CHECKING_CREATION;

    /// The badge on the profile the account is deriving at.
    pub(crate) const ACTIVE_BADGE: &str = "In use";
    /// The badge on a profile the user has taken out of this computer's lists.
    pub(crate) const HIDDEN_BADGE: &str = "Hidden here";
    /// The readout naming a profile's on-chain identity.
    pub(crate) const DID_LABEL: &str = "DID";

    /// Said while the profile list is still being read.
    ///
    /// Names the read rather than the answer: an account with several profiles and one with none
    /// look identical during this moment, and claiming either would be a claim no read supports.
    pub(crate) const PENDING: &str =
        "DIG is still reading which profiles this account has. Nothing here is settled until it has.";

    /// Said when the registry ANSWERED and the account holds no profile.
    ///
    /// # Why this sentence is long, and why the length is the point
    ///
    /// It is the state every real user is in, so it is not an edge case being apologised for — it is
    /// the pane's ordinary content, and it has three jobs: say what a profile IS, say that the
    /// account works without one, and say why there is no button. The third matters most: an empty
    /// list with no explanation reads as a fault, and a person who thinks their profiles failed to
    /// load will go looking for a way to reload them.
    ///
    /// The wallet half is not decoration. This pane sits inches below a real, fundable receive
    /// address, and an empty profile list that said nothing would read as the account being
    /// unusable.
    pub(crate) const EMPTY: &str =
        "This account has no profiles yet. A profile is an on-chain identity — a DID and a store — \
         that lets you publish, sign for an app and be found by other people.\n\n\
         Your account already holds funds, receives at the address on the Wallet tab, and reads \
         everything on the DIG Network without one.";

    /// Said when the registry could not be read at all.
    ///
    /// Deliberately NOT [`EMPTY`]: an account whose registry will not load may well hold several
    /// profiles, and telling that person they have none is a claim about their identity that no read
    /// supports. Carries the loader's own words, because a hand-edited file and a permissions fault
    /// need different things done about them.
    pub(crate) fn unreadable(why: &str) -> String {
        format!(
            "DIG could not read this account's profile list, so it cannot say which profiles you \
             have. Your account, its funds and its recovery phrase are unaffected — they come from \
             your recovery phrase, not from this list. The log folder has the detail: {why}"
        )
    }

    /// Why a profile cannot be created on this build — the ecosystem's one wording for it.
    ///
    /// Delegated to [`crate::profiles::copy::cannot_create`] rather than written again here,
    /// because the shell says the same thing in a native notice and two constants stating one fact
    /// is how the account state machine came to have two sentence sets that drifted (#2357).
    pub(crate) fn cannot_create(blocked: CreationBlocked) -> String {
        crate::profiles::copy::cannot_create(blocked)
    }

    /// Said above the switch controls, BEFORE anything is pressed.
    ///
    /// # Why it is on the card and not only in the confirmation
    ///
    /// "Say so before it happens" means before the decision, not between the decision and the act. A
    /// person scanning this card is choosing which profile to use, and the cost of that choice — a
    /// different receive address, a different signing key — belongs where they are choosing, not in
    /// a dialog that appears once they already have. The confirmation repeats it with the two
    /// profiles named ([`crate::profiles::copy::switching`]); this is the standing statement.
    pub(crate) const SWITCH_CAUTION: &str =
        "Switching profiles changes the address money arrives at and the key that signs for you. \
         Anything already sent to your current address stays where it is, and switching back \
         restores it.";

    /// Said beside the hide controls, so the word "hide" cannot be read as "delete".
    ///
    /// The ecosystem's one wording, shared verbatim with the shell's own notices: a profile is
    /// permanent on chain, and this control changes one computer's list.
    pub(crate) const HIDE_NOTE: &str = crate::profiles::copy::HIDE_NOTE;

    /// Said where the profile in use has no hide control, so its absence is not read as a fault.
    pub(crate) const ACTIVE_CANNOT_HIDE: &str =
        "The profile in use is always listed. Switch to another profile first if you want to hide \
         this one.";
}

/// The words for the agent's two states, chosen by an exhaustive match rather than a boolean.
pub(crate) fn agent_state(running: bool) -> &'static str {
    match running {
        true => "Running",
        false => "Starting",
    }
}

/// The copy-to-clipboard affordance.
pub(crate) mod clipboard {
    /// The control's resting label.
    pub(crate) const COPY: &str = "Copy";
    /// What it says immediately after a successful copy, before returning to [`COPY`].
    pub(crate) const COPIED: &str = "Copied";
}

/// The scannable-code block.
pub(crate) mod qr {
    /// The caption under a receive-address code.
    pub(crate) const RECEIVE_CAPTION: &str =
        "Scan this with a Chia wallet to send $DIG or XCH to this account.";
}

/// The Wallet pane.
pub(crate) mod wallet {
    /// The card carrying the address and its code — now DISCLOSED by the Receive control rather
    /// than drawn permanently at the top of the tab (dig_ecosystem#2967).
    pub(crate) const RECEIVE_CARD: &str = "Receive";
    /// The card that leads the tab: the headline figure and the assets under it.
    ///
    /// Named for the question it answers rather than for what it contains. A person opens this tab
    /// to learn what they have, and the first words on it should be that question's title.
    pub(crate) const BALANCE_CARD: &str = "Balance";

    /// The control that discloses the receive card.
    ///
    /// Bare "Receive", not "Show my address": the pair reads `Send` / `Receive`, which is the verb
    /// pair every wallet uses, and a control named for its mechanism rather than its purpose breaks
    /// that recognition.
    pub(crate) const RECEIVE_BUTTON: &str = "Receive";
    /// The control that discloses the send form.
    ///
    /// "Send", where the form's own submit is "Send XCH" — one opens the form, the other commits
    /// the payment, and the two must not read as the same control.
    pub(crate) const SEND_BUTTON_OPEN: &str = "Send";
    /// The control that closes a disclosed card.
    ///
    /// Present even though the control that opened it also closes it: `professional-ui`'s never-trap
    /// rule wants the way out to be VISIBLE from inside the thing it exits, and a person who
    /// scrolled down to the code cannot see the button that opened it.
    pub(crate) const CLOSE_BUTTON: &str = "Done";

    // A refused Receive carries NO prefix constant: `wallet::overview::address_line` already writes
    // a whole sentence for each account state, and prefixing it produced "No address yet — Your
    // address is not shown because your account is locked" — the same fact twice, capitalised
    // mid-sentence. See `pane::wallet::receive_refusal`.
    /// The card that reserves the place sending will take (dig_ecosystem#2207).
    pub(crate) const SENDING_CARD: &str = "Sending";
    /// The card holding the tab's own verbs.
    pub(crate) const ACTIONS_CARD: &str = "Wallet actions";

    /// The readout naming the receive address.
    pub(crate) const ADDRESS_LABEL: &str = "Receive address";
    /// The readout naming the native-coin balance. The ticker is in the value's unit, so the label
    /// is the thing a person who does not know the ticker can still read.
    pub(crate) const XCH_LABEL: &str = "Chia";
    /// The readout naming the DIG CAT balance.
    pub(crate) const DIG_LABEL: &str = "DIG token";
    /// The one readout shown in place of both figures when there is no reading.
    pub(crate) const BALANCE_LABEL: &str = "Balance";

    /// The words a not-known balance's reason completes.
    ///
    /// `wallet::overview`'s reasons are written as CLAUSES — "your account is locked, so DIG cannot
    /// tell which address to read" — because the tray window puts "Balance: not known — " in front
    /// of them. Reusing the clauses keeps one set of sentences for both surfaces; this const is what
    /// makes a clause read as a sentence under a bare `Balance` label instead of starting
    /// mid-thought in lower case.
    pub(crate) const BALANCE_NOT_KNOWN: &str = "Not known —";

    /// The badge shown BESIDE the figures while the node is still catching up
    /// (dig_ecosystem#2869).
    ///
    /// Beside them, not only beneath: the as-of sentence under the card explains, and a person who
    /// takes the number at a glance never reaches it. Two words, so it reads as a state on the
    /// holding rather than as a warning about it — the figure is real, and the node is working.
    pub(crate) const BALANCE_SYNCING_BADGE: &str = "Still syncing";

    /// The unit shown beside the native-coin figure.
    pub(crate) const XCH_UNIT: &str = "XCH";
    /// The unit shown beside the DIG CAT figure.
    pub(crate) const DIG_UNIT: &str = "$DIG";

    /// Said while a balance read is in flight.
    ///
    /// Names the duration because the read genuinely takes 2.5–6 seconds (dig_ecosystem#2325), and a
    /// wait a person has not been warned about is a wait they read as a hang. It states no figure —
    /// this sentence stands where the numbers will be.
    pub(crate) const BALANCE_PENDING: &str =
        "Reading your balance from your node. A balance is a blockchain lookup, so this usually \
         takes a few seconds.";

    /// The label above the destination field.
    pub(crate) const SEND_TO_LABEL: &str = "Pay to";
    /// What an empty destination field expects. A shape, never a plausible address.
    pub(crate) const SEND_TO_PLACEHOLDER: &str = "xch1…";
    /// The sentence under the destination field while nothing is wrong with it.
    pub(crate) const SEND_TO_HINT: &str =
        "The address you are paying. Money sent to a mistyped address cannot be recovered by \
         anyone, so check it against the one you were given.";
    /// The label above the amount field.
    pub(crate) const SEND_AMOUNT_LABEL: &str = "Amount";
    /// What an empty amount field expects.
    pub(crate) const SEND_AMOUNT_PLACEHOLDER: &str = "0.00";
    /// The sentence under the amount field while nothing is wrong with it.
    ///
    /// It names the asset because the tab shows two figures and only one of them can be sent from
    /// here: a person who has just read their $DIG balance would otherwise reasonably type it in.
    pub(crate) const SEND_AMOUNT_HINT: &str =
        "In XCH. $DIG cannot be sent from here yet — only the XCH above it.";
    /// The control that starts a payment.
    pub(crate) const SEND_BUTTON: &str = "Send XCH";

    /// What the fee costs, stated before the person presses anything.
    ///
    /// A FIXED figure rather than an estimate, so what is shown is exactly what will be paid — see
    /// [`DEFAULT_SEND_FEE_MOJOS`](crate::wallet::send::DEFAULT_SEND_FEE_MOJOS).
    pub(crate) fn send_fee(fee: &str) -> String {
        format!("A network fee of {fee} XCH is added. That is the whole cost of sending.")
    }

    /// The glance-level word while the confirmation is in front of the person.
    pub(crate) const SEND_SIGNING_BADGE: &str = "Waiting for you";
    /// Said while the confirmation is up.
    pub(crate) const SEND_SIGNING_BODY: &str =
        "DIG is asking you to approve this payment. Nothing is sent until you do, and closing the \
         request sends nothing.";

    /// The glance-level word for a payment a mempool has taken but the chain has not settled.
    pub(crate) const SEND_PENDING_BADGE: &str = "On its way";
    /// Said while a pushed payment is waiting to settle.
    ///
    /// The block count is what makes the wait legible: a Chia block is roughly 19 seconds, so a
    /// screen that only said "waiting" would be indistinguishable from a hang after a minute.
    pub(crate) fn send_pending_body(blocks: u32) -> String {
        format!(
            "The network has taken this payment and is settling it. {blocks} block(s) have been \
             produced since it was sent; a few more and it is final. Keep the payment coin below if \
             you want to follow it yourself — DIG watches it only until you close the app."
        )
    }

    /// The glance-level word for a payment whose fate nobody can state yet.
    pub(crate) const SEND_UNKNOWN_BADGE: &str = "Not known yet";
    /// Said when the node never answered the broadcast.
    ///
    /// It says *keep watching* and never *it did not send*, because the payment may be in a mempool
    /// right now — and sending it again is the one action that could pay the recipient twice.
    ///
    /// The last sentence is the app being honest about its own memory: the transfer is held in this
    /// process and nowhere else, so a restart forgets it. Telling someone not to send again while
    /// silently losing the one identifier that lets them check is the worse half of that.
    pub(crate) fn send_unknown_body(detail: &str) -> String {
        format!(
            "Your node did not answer when DIG sent this payment, so whether it went out is not yet \
             known ({detail}). It may already be settling. DIG is watching the coin below and will \
             say when the chain decides — do not send it again in the meantime. Write the payment \
             coin down: DIG forgets it if you close the app, and it is how you check afterwards."
        )
    }

    /// The glance-level word for money that has arrived.
    pub(crate) const SEND_CONFIRMED_BADGE: &str = "Arrived";
    /// Said once the payment coin is buried on chain.
    pub(crate) const SEND_CONFIRMED_BODY: &str =
        "This payment is settled on chain. It cannot be reversed, by DIG or by anyone.";

    /// The glance-level word for a payment that never left.
    pub(crate) const SEND_FAILED_BADGE: &str = "Not sent";
    /// The lead-in above the verbatim reason a send that was NEVER BROADCAST failed.
    ///
    /// It may promise that no money moved only because nothing was ever pushed. A transfer that died
    /// AFTER a push gets [`SEND_DIED_BODY`] instead — see [`SendProgress::Failed`] for the two paths.
    ///
    /// [`SendProgress::Failed`]: crate::wallet::sending::SendProgress::Failed
    pub(crate) const SEND_FAILED_BODY: &str =
        "Nothing was sent and no money has moved. The reason, as it was given:";

    /// The glance-level word for a pushed payment the chain has ruled out.
    pub(crate) const SEND_DIED_BADGE: &str = "Did not go through";
    /// The lead-in for a payment that WAS broadcast and can no longer be included.
    ///
    /// It must not claim nothing happened: this state is reached only when a coin the payment was
    /// built from is observed SPENT while the payment coin is absent, so something did move on chain
    /// — just not this payment. The coin id is shown with it, because it is the one thing a person can
    /// take to a block explorer to see that for themselves.
    pub(crate) const SEND_DIED_BODY: &str =
        "This payment will not go through: one of the coins it was built from has been spent \
         elsewhere, so the network can no longer include it. This payment did not reach the \
         recipient. The reason, as it was given:";

    /// The label on the payment coin a person can look up themselves.
    pub(crate) const SEND_COIN_LABEL: &str = "Payment coin";
    /// The label on the block height a payment settled at.
    pub(crate) const SEND_HEIGHT_LABEL: &str = "Settled at block";

    /// The aside under the sending copy.
    pub(crate) const SENDING_HINT: &str =
        "Reading DIG content never needs an account or a wallet at all.";
    /// The caption under the receive address.
    pub(crate) const RECEIVE_HINT: &str =
        "Only ever share this address. It receives money; it cannot spend it.";
}

/// The Content pane — what this computer keeps on disk for the network.
pub(crate) mod content {
    /// The card carrying the usage meter.
    pub(crate) const USAGE_CARD: &str = "Disk used by cached content";
    /// The card carrying the size-limit choices.
    pub(crate) const LIMIT_CARD: &str = "Size limit";
    /// The card listing what this computer is mirroring.
    pub(crate) const CAPSULES_CARD: &str = "Capsules mirrored here";
    /// The card holding the add-by-store-id form.
    pub(crate) const ADD_CARD: &str = "Mirror another store";

    /// The label above the usage bar.
    pub(crate) const METER_LABEL: &str = "Used against the limit";
    /// Said in place of the meter when no node has reported a cache.
    ///
    /// A meter at zero is not available as a fallback: it would say the cache is empty, which is a
    /// different claim from not having been told.
    pub(crate) const USAGE_UNKNOWN: &str =
        "No node has reported its cache yet, so how much disk DIG is using is not known. Start the \
         DIG node and this fills in.";
    /// The label above the size-limit chooser.
    pub(crate) const LIMIT_FIELD: &str = "Limit";
    /// Said in the closed chooser when no node has reported a cap at all.
    ///
    /// Never the first preset: a chooser resting on `256 MiB` is indistinguishable from one
    /// reporting that 256 MiB is the limit, which is a setting nobody has told this window about.
    pub(crate) const LIMIT_UNKNOWN: &str = "Not reported";
    /// Said in the closed chooser when the node's cap is real but is not one of the presets.
    ///
    /// A cap set through `Custom size…` matches no option in the list, and the honest answer is the
    /// figure itself — saying "not reported" about a limit the node has plainly reported would deny
    /// a setting that exists.
    pub(crate) fn limit_custom(size: &str) -> String {
        format!("{size} (a custom size)")
    }

    /// The aside under the size-limit chooser.
    pub(crate) const LIMIT_HINT: &str =
        "Choosing a limit below what is already used makes the node delete cached content to fit. \
         DIG asks before it does that.";

    /// The word marking a capsule the node keeps regardless of the cache's limit.
    pub(crate) const PINNED_BADGE: &str = "Pinned";

    /// Said while the node is being asked what it holds.
    ///
    /// A WAIT, not a fault and not an empty list: the read walks the node's on-disk cache index, so
    /// on a large cache it legitimately takes seconds
    /// ([`crate::hosted_stores::STORES_READ_TIMEOUT`]).
    pub(crate) const CAPSULES_PENDING: &str =
        "Asking the node what this computer is mirroring. A large cache takes a moment to list.";

    /// What one listed store's second line says about its contents.
    ///
    /// # Why a store with nothing cached does not report `0 B` (dig_ecosystem#2397)
    ///
    /// The node's list is cached ∪ pinned stores (dig-node `SPEC.md` §7.6), so a store pinned before
    /// its content arrived is listed with no capsules and no bytes. That is the ordinary state of a
    /// store somebody has just asked for — but drawn as `Pinned · 0 B` it reads as a broken row, and
    /// a reader goes looking for a fault that is not there. So the zero is written as the situation
    /// it is rather than as a measurement.
    pub(crate) fn store_contents(capsule_count: u64, size: &str) -> String {
        match capsule_count {
            0 => "Nothing cached yet".to_string(),
            1 => format!("1 capsule · {size}"),
            n => format!("{n} capsules · {size}"),
        }
    }

    /// Why no list of mirrored stores could be read — **one sentence per remedy**.
    ///
    /// # Why this match is exhaustive over the reason, not over a rough category
    ///
    /// [`HostedStoresUnknown`](crate::hosted_stores::HostedStoresUnknown) is documented as one
    /// variant per REMEDY, and that only reaches a person if the remedies survive to the sentence
    /// they read. Two of them are the reason it exists: `Unauthorized` is a permission fault on a
    /// perfectly capable node, so sending that reader after an upgrade wastes their afternoon; and
    /// `TimedOut` must never be worded as an absent node, because only `Unreachable` is evidence
    /// about whether a node exists at all (dig_ecosystem#2325).
    ///
    /// The node's own words are carried where it gave any, after the sentence rather than instead of
    /// it: a diagnostic detail is for the person who can use it, and a remedy is for everyone else.
    pub(crate) fn stores_unknown(reason: &crate::hosted_stores::HostedStoresUnknown) -> String {
        use crate::hosted_stores::HostedStoresUnknown as Why;
        match reason {
            Why::NoNode => "No node is connected, so there is nothing to ask what this computer is \
                            mirroring. Start the DIG node and this list fills in."
                .to_string(),
            Why::NodeCannotRead => {
                "This node is an older build that cannot list what it holds. Update DIG on this \
                 computer and the list appears."
                    .to_string()
            }
            Why::Unauthorized => {
                "The node refused to list what it holds, because DIG could not read this computer's \
                 node control token. The node itself is fine — reinstall DIG, or run it as the \
                 account that installed the node, to restore access."
                    .to_string()
            }
            Why::TimedOut(detail) => format!(
                "The node is running but took too long to list what it holds, so the read was \
                 abandoned. This usually means a large cache on slow storage; DIG asks again \
                 shortly. The node said: {detail}"
            ),
            Why::Unreachable(detail) => format!(
                "The node could not be reached for this read, so it may have stopped since DIG last \
                 spoke to it. Check the DIG node is still running. The reason was: {detail}"
            ),
            Why::ReadFailed(detail) => format!(
                "The node refused this read and DIG cannot tell why. The log folder on the Home tab \
                 has the details. The node said: {detail}"
            ),
        }
    }

    /// Said when the cache holds bytes but no capsule is listed.
    ///
    /// This is the state that reads as a fault and is not one: content arrives as blocks and is only
    /// a *capsule* once a store has finished syncing, so a large figure above an empty list is
    /// ordinary. Without this sentence a person concludes the list is broken and goes looking.
    pub(crate) const CAPSULES_EMPTY_WITH_BYTES: &str =
        "Nothing is mirrored in full yet. The disk figure above is real — content is fetched in \
         pieces, and a store only becomes a capsule here once it has finished syncing, so a cache \
         with content in it can still list nothing.";
    /// Said when the cache is listing nothing and holding nothing.
    pub(crate) const CAPSULES_EMPTY: &str =
        "This computer is not mirroring anything yet. Open a DIG link, or add a store below, and \
         what it caches appears here.";

    /// The label on the add-a-store field.
    pub(crate) const ADD_FIELD_LABEL: &str = "Store id";
    /// The placeholder shape, shown as help text rather than inside the field.
    pub(crate) const ADD_FIELD_HINT: &str =
        "A store id is 64 hexadecimal characters, from a DIG link or from whoever published the \
         store.";
    /// The label on the control that would begin mirroring.
    pub(crate) const ADD_BUTTON: &str = "Mirror this store";

    /// The aside under that control, saying why it cannot be pressed.
    ///
    /// A caption rather than a banner: an absence is stated once, in the place it is about, as a
    /// note under the control it is about. A banner would repeat what the caption already says.
    pub(crate) const ADD_NOT_WIRED: &str = concat!(
        "DIG cannot ask the node to mirror a store yet, so the control above does nothing. The id ",
        "you type is still checked, so you can tell a good one from a typo."
    );

    /// The inline error under a store id that is not 64 hex characters.
    ///
    /// Attached to the field, and it says what was typed rather than only what was wanted: "64
    /// characters" beside a value the reader has to count themselves is a slower correction.
    pub(crate) fn add_field_error(typed: usize) -> String {
        format!(
            "A store id is 64 hexadecimal characters. This one has {typed} — check you copied the \
             whole id."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **No sentence carries a run of spaces from the way its literal was wrapped.**
    ///
    /// Found on screen, not in review: a continued literal lost its `\` and rendered *"so the
    /// ␣␣␣␣␣␣␣␣␣ control above does nothing"* in the middle of a card. The reader sees a typographic
    /// fault; the file looks fine, because the spaces are the source's own indentation. Asserted over
    /// every string this module hands a paint call, so the next wrapped sentence cannot reintroduce
    /// it.
    /// Every sentence this module hands a paint call, so a guard asserted "over all the copy" is.
    ///
    /// Written out because these are `const`s in nested modules and nothing enumerates them. The
    /// tab LEADS are appended from [`TabId::all`], which IS exhaustive — it is derived from the enum
    /// rather than hand-listed (dig_ecosystem#2358), so a new tab's lead arrives here on its own.
    fn every_sentence() -> Vec<String> {
        let mut all: Vec<&'static str> = vec![
            home::CACHE_UNKNOWN,
            home::DIAGNOSTICS_HINT,
            qr::RECEIVE_CAPTION,
            wallet::BALANCE_PENDING,
            wallet::SEND_TO_HINT,
            wallet::SEND_AMOUNT_HINT,
            wallet::SEND_SIGNING_BODY,
            wallet::SEND_UNKNOWN_BADGE,
            wallet::SEND_CONFIRMED_BODY,
            wallet::SEND_FAILED_BODY,
            wallet::SENDING_HINT,
            wallet::RECEIVE_HINT,
            content::USAGE_UNKNOWN,
            content::LIMIT_HINT,
            content::CAPSULES_EMPTY,
            content::CAPSULES_EMPTY_WITH_BYTES,
            content::ADD_FIELD_HINT,
            content::ADD_NOT_WIRED,
            content::CAPSULES_PENDING,
            protection::SECOND_FACTOR_ON,
            protection::SECOND_FACTOR_OFF,
            protection::PAIRED_APPS_HINT,
            settings::UPDATES_ABOUT,
            settings::UPDATES_COST,
            settings::CHANNEL_UNKNOWN,
            settings::NODE_ABOUT,
            settings::NODE_HELP,
            settings::NODE_COST,
            settings::SHORTCUT_ABOUT,
            settings::SHORTCUT_HELP,
            settings::SHORTCUT_COST,
            settings::SAVED,
            settings::NO_CONFIG,
            settings::TESTING,
            account::UNREAD,
            account::DESTRUCTIVE_CAVEAT,
            account::DIG_ID_UNKNOWN,
            apps::INSTALL_NOTE,
            profiles::PENDING,
            profiles::CHECKING_CREATION,
            profiles::EMPTY,
            profiles::SWITCH_CAUTION,
            profiles::HIDE_NOTE,
            profiles::ACTIVE_CANNOT_HIDE,
            crate::profiles::copy::WHAT_A_PROFILE_IS,
            crate::profiles::copy::ABOUT_HEADING,
        ];
        all.extend(TabId::all().into_iter().map(lead));
        all.extend(
            super::super::facts::AccountKind::ALL
                .iter()
                .map(|kind| account::summary(*kind)),
        );
        // The three sharing absences, keyed the same way the card keys them.
        all.extend([
            home::sharing_unknown(false, false),
            home::sharing_unknown(true, false),
            home::sharing_unknown(true, true),
        ]);

        let mut said: Vec<String> = all.into_iter().map(str::to_owned).collect();
        // Every arm of the create explainer, enumerated rather than sampled: a sweep that visits
        // one of them is a sweep for one of them. The indentation guard below found a real defect
        // in exactly these the day they were written, which is why they are here rather than
        // trusted. Built rather than constant since dig_ecosystem#2939 gave one arm a payload.
        said.extend(crate::profiles::CreationBlocked::EVERY.map(profiles::cannot_create));
        // Every reason a store list can be missing, enumerated from the reading's own list rather
        // than sampled — a sweep that visits some of the sentences is a sweep for some of them.
        said.extend(
            crate::hosted_stores::HostedStoresUnknown::all()
                .iter()
                .map(content::stores_unknown),
        );
        said.push(content::store_contents(0, "0 B"));
        said.push(content::store_contents(1, "12 MiB"));
        said.push(content::store_contents(4, "407 MiB"));
        // The two profile sentences that are built rather than constant.
        said.push(profiles::unreadable("the stored registry is not JSON"));
        said.push(crate::profiles::copy::switching("“home”", "“work”"));
        said
    }

    /// The phrasings that describe how dig-app was BUILT rather than what the reader is looking at.
    ///
    /// Each was found on screen, not in review: two in tab leads (dig_ecosystem#2356) and one in the
    /// unwired caveat, which is why the check below is asserted over every sentence rather than over
    /// the leads alone — the voice rule is about the copy, and it leaked into the copy that is not a
    /// lead the moment it was enforced only on leads.
    const DEVELOPER_VOICE: [&str; 6] = [
        "Each group",
        "finished layout",
        "this form",
        "This form",
        "this tab was",
        "wired up to it",
    ];

    #[test]
    fn no_sentence_carries_its_own_indentation() {
        for sentence in every_sentence() {
            assert!(
                !sentence.contains("  "),
                "a sentence carries a run of spaces from its source indentation: {sentence}"
            );
        }
        assert!(!content::add_field_error(63).contains("  "));
    }

    /// **Every tab has its own lead, and no lead explains the app's design back to the reader.**
    ///
    /// The two halves are the two defects dig_ecosystem#2356 names. Distinctness is what makes the
    /// lead worth drawing — a shared sentence across seven tabs is seven tabs with no orientation,
    /// which is the state five of them were already in. The VOICE half is asserted over every
    /// sentence, not only the leads, by
    /// [`no_sentence_explains_the_app_to_the_reader`](tests::no_sentence_explains_the_app_to_the_reader).
    #[test]
    fn every_tab_leads_with_its_own_sentence_about_what_the_tab_is_for() {
        let leads: Vec<&str> = TabId::all().into_iter().map(lead).collect();
        assert_eq!(
            leads.len(),
            TabId::all().len(),
            "the tab set changed and this guard did not"
        );

        let mut unique = leads.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            leads.len(),
            "two tabs open with the same sentence, so at least one of them says nothing about \
             where the reader is: {leads:?}"
        );

        for (tab, said) in TabId::all().iter().zip(&leads) {
            assert!(
                !said.is_empty() && said.ends_with('.'),
                "the {tab:?} lead is not a sentence: {said}"
            );
            assert!(
                !said.contains("  "),
                "the {tab:?} lead carries a run of spaces from its source indentation: {said}"
            );
        }
    }

    /// **No sentence anywhere in this module explains dig-app's construction to its reader.**
    ///
    /// The guard this replaces ran over the tab LEADS only, and the same voice was live on two panes
    /// at the time in the unwired caveat — *"It is the finished layout, waiting for the node to be
    /// wired up to it"* — because a caveat is not a lead. A voice rule enforced on one kind of
    /// sentence is a voice rule for one kind of sentence.
    ///
    /// The fixture is [`every_sentence`], the leads INCLUDED, so a phrasing moving from a lead into
    /// a caption is caught where moving it used to launder it.
    #[test]
    fn no_sentence_explains_the_app_to_the_reader() {
        let sentences = every_sentence();
        // Without this the sweep is over a list someone could empty, which would pass loudest of
        // all. The leads alone are five, so anything near that means the consts stopped arriving.
        assert!(
            sentences.len() > TabId::all().len(),
            "the sentence list no longer carries the copy that is not a lead, so this sweep is \
             back to being the leads-only guard it replaced"
        );
        for said in sentences {
            for leak in DEVELOPER_VOICE {
                assert!(
                    !said.contains(leak),
                    "a sentence says {leak:?}, which describes how dig-app was BUILT rather than \
                     what the reader is looking at: {said}"
                );
            }
        }
    }

    /// **No sentence sends the reader to a tab that does not exist.**
    ///
    /// The Settings pane's error state — the one state where the reader is already lost — told them
    /// to *"open the log folder from the Status tab"* for a whole review cycle after
    /// dig_ecosystem#2358 deleted the Status tab. Nothing caught it: `every_sentence` did not
    /// enumerate `copy::settings` at all, which is the dig_ecosystem#2356 shape again — a sweep
    /// scoped to one KIND of sentence is a sweep for one kind of sentence.
    ///
    /// So the vocabulary is taken from [`TabId::label`] itself rather than a second hand-kept list,
    /// and deleting a tab now fails this test until the copy that names it is rewritten.
    #[test]
    fn no_sentence_names_a_tab_the_window_does_not_have() {
        let real: Vec<&str> = TabId::all().into_iter().map(TabId::label).collect();
        assert!(
            !real.contains(&"Status"),
            "the Status tab is back, so this guard's own example no longer discriminates"
        );

        for said in every_sentence() {
            for named in tabs_named(&said) {
                assert!(
                    real.contains(&named.as_str()),
                    "a sentence sends the reader to the {named:?} tab, which this window does not \
                     have — the tabs are {real:?}: {said}"
                );
            }
        }
    }

    /// Every capitalised name used as `<Name> tab` in `sentence`.
    ///
    /// Capitalisation is what separates a NAME from a reference to the tab the reader is already on
    /// (*"everything on this tab"*), which is always true and never needs checking.
    fn tabs_named(sentence: &str) -> Vec<String> {
        let words: Vec<&str> = sentence.split_whitespace().collect();
        words
            .windows(2)
            .filter(|pair| pair[1].trim_end_matches(['.', ',', ';', ':']) == "tab")
            .map(|pair| pair[0].to_owned())
            .filter(|name| name.starts_with(|c: char| c.is_uppercase()))
            .collect()
    }

    /// **Every state's copy is distinct, so a match arm cannot silently share another's sentence.**
    ///
    /// A copy-by-state helper whose arms return the same string is a state the reader cannot tell
    /// apart from its opposite — which is the whole failure mode "Starting" exists to prevent.
    #[test]
    fn each_state_says_something_different_from_its_opposite() {
        assert_ne!(agent_state(true), agent_state(false));

        assert_ne!(clipboard::COPY, clipboard::COPIED);
    }

    /// **Every reason a store list is missing gets its OWN sentence** (dig_ecosystem#2397).
    ///
    /// The property [`content::stores_unknown`] exists for. `HostedStoresUnknown` is documented as
    /// one variant per REMEDY, and a remedy only reaches a person through the sentence they read —
    /// so two reasons sharing words is two remedies collapsed back together at the last step.
    ///
    /// Asserted over the WHOLE set rather than a sample, in the shape `no_two_account_states_share_a
    /// _word` uses, so a seventh reason cannot silently inherit another's sentence. The two pairs
    /// named individually are the ones that have actually gone wrong: `Unauthorized` is a permission
    /// fault on a capable node, and `TimedOut` is a node that is UP.
    #[test]
    fn no_two_reasons_for_a_missing_store_list_share_a_sentence() {
        use crate::hosted_stores::HostedStoresUnknown as Why;

        let reasons = Why::all();
        let mut said: Vec<String> = reasons.iter().map(content::stores_unknown).collect();
        let total = said.len();
        said.sort();
        said.dedup();
        assert_eq!(
            said.len(),
            total,
            "two reasons a store list is missing are shown the same sentence, so one of the two \
             readers is being sent after the wrong remedy: {said:?}"
        );

        // An upgrade is the remedy for exactly ONE reason. Telling a user with a token problem to
        // update DIG sends them after a fault that is not there.
        let refused = content::stores_unknown(&Why::Unauthorized).to_lowercase();
        assert!(
            !refused.contains("update") && !refused.contains("older"),
            "a permission fault is worded as an out-of-date node: {refused}"
        );
        assert!(
            refused.contains("token"),
            "the permission fault never names what is actually missing: {refused}"
        );
        let old = content::stores_unknown(&Why::NodeCannotRead).to_lowercase();
        assert!(
            old.contains("update"),
            "the one reason an upgrade fixes does not mention one: {old}"
        );

        // A slow node is UP. Only `Unreachable` is evidence about whether a node exists
        // (dig_ecosystem#2325), so the timeout sentence must not deny one.
        let slow = content::stores_unknown(&Why::TimedOut("4s".to_string())).to_lowercase();
        assert!(
            slow.contains("running"),
            "a node that answered late is not reported as a node that is running: {slow}"
        );
        for absence in ["no node", "not running", "stopped"] {
            assert!(
                !slow.contains(absence),
                "a slow node is worded as an absent one, which is dig_ecosystem#2325 in a new \
                 pane: {slow}"
            );
        }
    }

    /// **A store with nothing cached reads as a state, not as a measurement of zero.**
    ///
    /// The live node lists two pinned stores whose content has not arrived. `Pinned · 0 B` is the
    /// nearest wrong rendering: every figure in it is true, and it reads as a broken row. Both sides
    /// are asserted, because a helper that ALWAYS said "Nothing cached yet" would satisfy the first
    /// half alone while erasing every real size on the card.
    #[test]
    fn a_store_with_nothing_cached_does_not_report_a_size() {
        let empty = content::store_contents(0, "0 B");
        assert!(
            !empty.contains('0') && !empty.contains(" B"),
            "a store awaiting its content reports a measurement of zero: {empty}"
        );
        assert!(empty.to_lowercase().contains("yet"), "{empty}");

        let held = content::store_contents(4, "407 MiB");
        assert!(
            held.contains("407 MiB") && held.contains("4 capsules"),
            "a store with content does not report what it holds: {held}"
        );
        assert!(
            content::store_contents(1, "12 MiB").contains("1 capsule "),
            "one capsule is reported in the plural"
        );
    }

    /// **Each way of having no sharing figures names its own situation**, and none of them describes
    /// dig-app's build order.
    ///
    /// The const this replaced said *"Not read from the node yet."* for all three — true, and useless
    /// to the reader whose agent has not started. Distinctness is asserted over the whole set; the
    /// voice half is covered for these sentences too by
    /// [`no_sentence_explains_the_app_to_the_reader`](tests::no_sentence_explains_the_app_to_the_reader),
    /// because [`every_sentence`] now carries them.
    #[test]
    fn each_reason_the_sharing_figures_are_absent_names_its_own_machine() {
        let states = [(false, false), (false, true), (true, false), (true, true)];
        let said: Vec<&str> = states
            .iter()
            .map(|(running, connected)| home::sharing_unknown(*running, *connected))
            .collect();

        assert_eq!(
            said[0], said[1],
            "an agent that has not started is not looking for a node either way, so both must read \
             the same"
        );
        let mut distinct = vec![said[0], said[2], said[3]];
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            3,
            "two different machines are described in the same words: {said:?}"
        );
        assert!(
            said[0].to_lowercase().contains("agent"),
            "a stopped agent is not named as the thing to start: {}",
            said[0]
        );
        assert!(
            said[2].to_lowercase().contains("node"),
            "a running agent with no node does not name the node: {}",
            said[2]
        );
    }
}
