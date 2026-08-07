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
