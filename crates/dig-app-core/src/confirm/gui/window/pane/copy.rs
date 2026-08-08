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

/// The Account pane.
pub(crate) mod account {
    use super::super::facts::AccountKind;

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
