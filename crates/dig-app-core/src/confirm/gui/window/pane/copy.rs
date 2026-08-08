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
    /// The aside under the size-limit buttons.
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
