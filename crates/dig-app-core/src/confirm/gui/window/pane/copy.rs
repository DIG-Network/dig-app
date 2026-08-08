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
    /// The meter above the cache bar.
    pub(crate) const CACHE_METER_LABEL: &str = "Cache used against its limit";

    /// Said in place of a cache reading when no node has reported one.
    pub(crate) const CACHE_UNKNOWN: &str =
        "No node has reported its cache yet. Connect a node to see how much space DIG is using.";
    /// Said beneath the diagnostics actions.
    pub(crate) const DIAGNOSTICS_HINT: &str =
        "If DIG is not behaving, the log folder is the first place to look.";
}

/// The Apps pane.
pub(crate) mod apps {
    /// The sentence under the tab's title, saying what the tab is for.
    pub(crate) const LEAD: &str =
        "The other DIG apps this computer can open. They share your DIG Account, so there is \
         nothing to sign in to.";
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
    /// The sentence under the tab's title.
    pub(crate) const LEAD: &str =
        "How DIG looks after itself on this computer. Each group says what a change costs before \
         you make it.";

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

#[cfg(test)]
mod tests {
    use super::*;

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
