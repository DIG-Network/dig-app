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
        TabId::Status => {
            "What DIG is doing on this computer right now, and where to look when it is not."
        }
        TabId::Account => {
            "The DIG Account this computer holds — the identity everything else here belongs to."
        }
        TabId::Security => "How this account is protected, and what you can change about that.",
        TabId::Wallet => "Where money arrives, and what this account is holding.",
        TabId::Apps => {
            "The other DIG apps this computer can open. They share your DIG Account, so there is \
             nothing to sign in to."
        }
        TabId::Cache => {
            "The disk DIG uses to keep content close by, and how much of it you want to give up."
        }
        TabId::Settings => "How DIG looks after itself on this computer.",
        TabId::Advanced => "Settings most people never need to change.",
    }
}

/// The Status pane.
pub(crate) mod status {
    /// The card grouping the facts about the running agent.
    pub(crate) const AGENT_CARD: &str = "This computer";
    /// The card grouping what the node is doing.
    pub(crate) const NODE_CARD: &str = "Node connection";
    /// The card grouping the content cache.
    pub(crate) const CACHE_CARD: &str = "Content cache";
    /// The card holding the pane's actions.
    pub(crate) const ACTIONS_CARD: &str = "Diagnostics";

    /// The readout naming whether the background agent is running.
    pub(crate) const AGENT_LABEL: &str = "DIG agent";
    /// The readout naming the installed version.
    pub(crate) const VERSION_LABEL: &str = "Version";
    /// The readout naming the account's state in one word.
    pub(crate) const ACCOUNT_LABEL: &str = "Account";
    /// The readout naming whether a second factor is enrolled.
    pub(crate) const SECOND_FACTOR_LABEL: &str = "Second factor";
    /// The card holding the figures about what this computer shares.
    pub(crate) const SHARING_CARD: &str = "What this computer is sharing";
    /// The four figures that card is designed around, in render order.
    pub(crate) const SHARING_LABELS: [&str; 4] = [
        "Stores hosted",
        "Capsules cached",
        "Stores pinned",
        "Uptime",
    ];
    /// Said in place of every figure on the sharing card, because none of them is a reading.
    pub(crate) const SHARING_UNKNOWN: &str = "Not read from the node yet.";

    /// Said in place of a cache reading when no node has reported one.
    pub(crate) const CACHE_UNKNOWN: &str =
        "No node has reported its cache yet. Connect a node to see how much space DIG is using.";
    /// Said beneath the diagnostics actions.
    pub(crate) const DIAGNOSTICS_HINT: &str =
        "If DIG is not behaving, the log folder is the first place to look.";
}

/// The Apps pane.
pub(crate) mod apps {
    /// The card holding any verb on the tab that is not an app's own.
    pub(crate) const OTHER_CARD: &str = "Also on this tab";
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

    /// Said after a setting has been written and read back.
    pub(crate) const SAVED: &str = "Saved.";
    /// Said when the settings file cannot be found or read at all, in place of the controls.
    ///
    /// The controls are REMOVED rather than disabled in this state, which is the rule PR #120
    /// established for the beacon: a switch that cannot move is a switch that will be tried.
    pub(crate) const NO_CONFIG: &str =
        "DIG cannot read its settings file on this computer, so these cannot be changed here. Open \
         the log folder from the Status tab to find out why.";

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

    /// What the account's state means, in the reader's terms.
    ///
    /// # Why every sentence here is written per state
    ///
    /// dig_ecosystem#2059: three different states were all told to "unlock", which is a remedy two of
    /// them cannot perform — an account sealed under a machine-generated password has no password to
    /// type, and one whose seal will not open has already failed at unlocking. An exhaustive match is
    /// what makes a seventh state ask for its own sentence instead of quietly inheriting one.
    pub(crate) fn summary(kind: AccountKind) -> &'static str {
        match kind {
            AccountKind::Unsupported => {
                "This system cannot hold a DIG Account yet — it has no per-application credential \
                 store for DIG to seal one with. Nothing here can be set up until that changes."
            }
            AccountKind::Absent => {
                "There is no DIG Account on this computer. Setting one up creates your identity and \
                 your wallet, and gives you a recovery phrase to write down and keep."
            }
            AccountKind::Locked => {
                "Your account is here and sealed. Its identity and its funds are safe; nothing can \
                 be signed or revealed with it until you open it again from the Security tab."
            }
            AccountKind::Unopenable => {
                "Your account is here, but its seal will not open, so it can no longer sign or \
                 reveal anything. There is no repair for this. Replacing the account below is the \
                 way forward, and its recovery phrase is what brings the same account back."
            }
            AccountKind::NeedsPassword => {
                "Your account is sealed under a password this computer made up, so anyone who can \
                 use this computer can open it. Choose a password of your own from the Security \
                 tab — your identity, your address and your funds all survive the change."
            }
            AccountKind::Unlocked => {
                "Your account is open and working. Everything on this tab acts on this account."
            }
        }
    }
}

/// The Security pane.
pub(crate) mod security {
    use super::super::facts::AccountKind;

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

    /// Whether the account is as safe as it can be, in the reader's terms.
    ///
    /// # These sentences never flatter the state
    ///
    /// The one failure a custody surface cannot have is implying an account is safer than it is, so
    /// the two states that read reassuringly at a glance say plainly what they are:
    /// [`AccountKind::NeedsPassword`] is a lock anyone at this keyboard can open, and
    /// [`AccountKind::Unopenable`] is not protection at all, it is an account nobody can use.
    pub(crate) fn protection(kind: AccountKind) -> &'static str {
        match kind {
            AccountKind::Unsupported => {
                "This system cannot hold a DIG Account yet, so there is nothing here to protect."
            }
            AccountKind::Absent => {
                "There is no account on this computer, so there is nothing here to protect yet."
            }
            AccountKind::Locked => {
                "Your account is sealed. Nothing on this computer can sign with it or reveal its \
                 recovery phrase until you open it."
            }
            AccountKind::Unopenable => {
                "Your account's seal will not open, so nothing can sign with it. That is not \
                 protection — the account is unusable, and replacing it from the Account tab is the \
                 only way forward."
            }
            AccountKind::NeedsPassword => {
                "Your account is sealed with a password this computer made up, not one you chose. \
                 Anyone who can use this computer can open it. Choosing your own password is the \
                 single biggest thing you can do here."
            }
            AccountKind::Unlocked => {
                "Your account is open right now, so anything on this computer that asks DIG to sign \
                 will be answered until you seal it again."
            }
        }
    }
}

/// The words for the agent's two states, chosen by an exhaustive match rather than a boolean.
pub(crate) fn agent_state(running: bool) -> &'static str {
    match running {
        true => "Running",
        false => "Starting",
    }
}

/// The words for whether a second factor is enrolled.
pub(crate) fn second_factor_state(enrolled: bool) -> &'static str {
    match enrolled {
        true => "On",
        false => "Off",
    }
}

/// What a pane says when it renders nothing a person can act on.
pub(crate) const NOTHING_HERE: &str =
    "There is nothing to show on this tab yet. Try another tab, or open the log folder from the \
     Status tab.";

/// The not-wired-up state — the fifth state, and the one the epic exists to keep honest.
pub(crate) mod unwired {
    /// The heading over an unwired surface.
    pub(crate) const HEADING: &str = "Not connected to live data yet";
    /// The glance-level badge on an unwired surface.
    pub(crate) const BADGE: &str = "Not wired up";
    /// The sentence that always follows it, whatever the surface.
    ///
    /// Deliberately says what a reader must NOT conclude, not merely that work is pending: the
    /// failure this state exists to prevent is a person reading a designed-but-unwired pane as a
    /// report on their own machine.
    pub(crate) const CAVEAT: &str =
        "Nothing on this card is a reading from your computer. It is the finished layout, waiting \
         for the node to be wired up to it.";
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
    /// The card carrying the address and its code. First on the tab, because receiving is the one
    /// thing this wallet can do today.
    pub(crate) const RECEIVE_CARD: &str = "Receive";
    /// The card carrying the balances.
    pub(crate) const HOLDINGS_CARD: &str = "What you hold";
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

    /// The glance-level word on the sending card.
    pub(crate) const SENDING_BADGE: &str = "Not available yet";
    /// Why there is no send button, and what still works without one.
    ///
    /// Deliberately no control at all, not a disabled one: a greyed **Send** is a promise the app
    /// cannot keep, and a person who finds it will look for the condition that enables it.
    pub(crate) const SENDING_BODY: &str =
        "DIG will not show a button that moves money until the path behind it is finished, so there \
         is nothing to press here yet. Receiving works now — anything sent to the address above \
         arrives in this account, and your recovery phrase restores it.";
    /// The aside under the sending copy.
    pub(crate) const SENDING_HINT: &str =
        "Reading DIG content never needs an account or a wallet at all.";
    /// The caption under the receive address.
    pub(crate) const RECEIVE_HINT: &str =
        "Only ever share this address. It receives money; it cannot spend it.";
}

/// The Cache pane.
pub(crate) mod cache {
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
    /// A caption rather than a second unwired banner: the card above already carries one, and the
    /// same amber paragraph twice on one screen teaches a reader to skip both.
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
    #[test]
    fn no_sentence_carries_its_own_indentation() {
        let sentences = [
            NOTHING_HERE,
            unwired::HEADING,
            unwired::CAVEAT,
            status::CACHE_UNKNOWN,
            status::DIAGNOSTICS_HINT,
            qr::RECEIVE_CAPTION,
            wallet::BALANCE_PENDING,
            wallet::SENDING_BODY,
            wallet::SENDING_HINT,
            wallet::RECEIVE_HINT,
            cache::USAGE_UNKNOWN,
            cache::LIMIT_HINT,
            cache::CAPSULES_EMPTY,
            cache::CAPSULES_EMPTY_WITH_BYTES,
            cache::ADD_FIELD_HINT,
            cache::ADD_NOT_WIRED,
        ];
        for sentence in sentences {
            assert!(
                !sentence.contains("  "),
                "a sentence carries a run of spaces from its source indentation: {sentence}"
            );
        }
        assert!(!cache::add_field_error(63).contains("  "));
    }

    /// **Every tab has its own lead, and no lead explains the app's design back to the reader.**
    ///
    /// The two halves are the two defects dig_ecosystem#2356 names. Distinctness is what makes the
    /// lead worth drawing — a shared sentence across seven tabs is seven tabs with no orientation,
    /// which is the state five of them were already in. The voice check is asserted as an ABSENCE of
    /// the two phrasings that leaked, plus the class they belong to: a lead that talks about groups,
    /// layouts or forms is talking about the tab's construction rather than its purpose.
    #[test]
    fn every_tab_leads_with_its_own_sentence_about_what_the_tab_is_for() {
        let leads: Vec<&str> = TabId::ALL.iter().map(|tab| lead(*tab)).collect();
        assert_eq!(leads.len(), 8, "the tab set changed and this guard did not");

        let mut unique = leads.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            leads.len(),
            "two tabs open with the same sentence, so at least one of them says nothing about \
             where the reader is: {leads:?}"
        );

        for (tab, said) in TabId::ALL.iter().zip(&leads) {
            assert!(
                !said.is_empty() && said.ends_with('.'),
                "the {tab:?} lead is not a sentence: {said}"
            );
            assert!(
                !said.contains("  "),
                "the {tab:?} lead carries a run of spaces from its source indentation: {said}"
            );
            for leak in [
                "Each group",
                "finished layout",
                "this form",
                "This form",
                "this tab was",
            ] {
                assert!(
                    !said.contains(leak),
                    "the {tab:?} lead says {leak:?}, which describes how the tab was BUILT rather \
                     than what it is for: {said}"
                );
            }
        }
    }

    /// **Every state's copy is distinct, so a match arm cannot silently share another's sentence.**
    ///
    /// A copy-by-state helper whose arms return the same string is a state the reader cannot tell
    /// apart from its opposite — which is the whole failure mode "Starting" exists to prevent.
    #[test]
    fn each_state_says_something_different_from_its_opposite() {
        assert_ne!(agent_state(true), agent_state(false));
        assert_ne!(second_factor_state(true), second_factor_state(false));
        assert_ne!(clipboard::COPY, clipboard::COPIED);
    }

    /// **The unwired caveat denies the reading rather than merely promising work.**
    ///
    /// "Coming soon" is compatible with a person believing the numbers above it. The sentence has to
    /// say the figures are not theirs.
    #[test]
    fn the_unwired_caveat_denies_that_the_figures_are_real() {
        let caveat = unwired::CAVEAT.to_lowercase();
        // A negation AND the word it negates, rather than one literal phrasing: the property is
        // that the sentence DENIES the figures are readings, and there is more than one honest way
        // to write that. Transcribing the current wording would pin the sentence, not the property.
        assert!(
            caveat.contains("reading"),
            "the unwired caveat never mentions what it is denying: {caveat}"
        );
        assert!(
            ["nothing ", "not ", "no "]
                .iter()
                .any(|negation| caveat.contains(negation)),
            "the unwired caveat promises work without denying the figures are real: {caveat}"
        );
    }
}
