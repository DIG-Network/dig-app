//! What a person is really agreeing to, said in their terms, on the confirm prompt
//! (dig_ecosystem#3109).
//!
//! # The defect this module exists to close
//!
//! [`render_spend`](crate::account::ceremony) draws a [`SpendSummary`](dig_account::SpendSummary):
//! the recipients dig-account independently re-derived from the coin spends, and the fee. That is
//! exactly right for an ordinary send, where the recipients ARE the act.
//!
//! It is not right for a swap. A take pays the settlement puzzle and receives its side back at the
//! taker's own change address, which the re-derivation drops as change — so the prompt named the
//! paid leg and stayed silent on what arrived. On a make it is worse: the maker signs away an asset
//! and the prompt shows a payment to a settlement puzzle hash with nothing about what was asked for
//! in return. And on a cancel, a spend that reclaims a person's own coins reads as an ordinary
//! self-payment with no hint that the outstanding offer is about to become unfillable.
//!
//! An NFT or CAT leg makes this sharp rather than theoretical: it nets ~0 XCH, so the
//! mojo-denominated summary shows a dust figure, the human approves the dust, and an asset changes
//! hands.
//!
//! # The rule
//!
//! **A narrative ADDS the missing side; it never replaces the re-derived one.** The figures
//! dig-account derived from the bytes being signed are still printed, under their own heading, so a
//! narrative that were ever wrong could be caught against them rather than hiding them. The
//! narrative itself is built from the same value the surface showed and the builder consumed — a
//! parsed offer, or the draft the maker filled in — never from a second reading.

/// What a person is about to do, in their own terms, and both sides of it.
///
/// Every field is prose the user reads. Nothing here is derived from the coin spends — that is the
/// [`SpendSummary`](dig_account::SpendSummary)'s job, and the two are printed side by side precisely
/// so they can be compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeNarrative {
    /// The question at the top, naming the ACT ("Make this offer?", "Cancel this offer?").
    pub headline: String,
    /// What leaves the person's ownership, one line per leg. Empty means nothing leaves.
    pub you_give: Vec<String>,
    /// What arrives, one line per leg. Empty means nothing arrives.
    pub you_receive: Vec<String>,
    /// The consequence a value delta cannot express — that an offer becomes unfillable, that a swap
    /// is irreversible. Printed last, where a person's eye lands before the buttons.
    pub caution: Option<String>,
}

impl TradeNarrative {
    /// Render the narrative as the plain-text block that leads the confirm body.
    ///
    /// A side with no legs is written as an explicit "Nothing", never omitted: a heading that simply
    /// disappeared would render a one-sided trade as though it had only the side that was populated,
    /// which is the silence this module exists to end.
    #[must_use]
    pub fn render(&self) -> String {
        let mut body = format!(
            "{}\n\nYou give: {}\nYou receive: {}",
            self.headline,
            Self::side(&self.you_give),
            Self::side(&self.you_receive),
        );
        if let Some(caution) = &self.caution {
            body.push_str("\n\n");
            body.push_str(caution);
        }
        body
    }

    /// One side, as a comma-joined list or the stated absence.
    fn side(legs: &[String]) -> String {
        match legs.is_empty() {
            true => "Nothing".to_string(),
            false => legs.join(", "),
        }
    }
}

/// The one narrative the next confirmation should carry, shared between the code that starts an
/// operation and the ceremony that renders it.
///
/// # Why a slot rather than a ceremony field
///
/// The money gate — and the [`PromptedCeremony`](crate::account::ceremony::PromptedCeremony) inside
/// it — is built ONCE per unlock and reused across every operation that unlock authorizes, because
/// the rolling-period cap it owns must span them. The narrative, by contrast, is different for every
/// operation. So the gate holds a handle to this slot and each operation writes its own narrative in
/// immediately before asking for a signature.
///
/// [`set`](Self::set) returns a [`Staged`] guard that clears the slot on drop, so a narrative can
/// never outlive the operation that wrote it and be shown against an unrelated spend — the failure a
/// bare setter would eventually produce.
#[derive(Clone, Default)]
pub struct NarrativeSlot(std::sync::Arc<std::sync::Mutex<Option<TradeNarrative>>>);

impl NarrativeSlot {
    /// Stage `narrative` for the confirmations that happen while the returned guard is alive.
    pub fn set(&self, narrative: TradeNarrative) -> Staged<'_> {
        self.write(Some(narrative));
        Staged(self)
    }

    /// The staged narrative, if an operation is in flight.
    #[must_use]
    pub fn get(&self) -> Option<TradeNarrative> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Replace the slot's contents, recovering from a lock an earlier panic poisoned.
    fn write(&self, narrative: Option<TradeNarrative>) {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = narrative;
    }
}

/// A staged narrative, cleared when this guard is dropped.
///
/// Held for the duration of one operation. Dropping it — including by an early return or a panic —
/// puts the slot back to empty, so the NEXT spend cannot inherit the last one's story.
pub struct Staged<'a>(&'a NarrativeSlot);

impl Drop for Staged<'_> {
    fn drop(&mut self) {
        self.0.write(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_swap() -> TradeNarrative {
        TradeNarrative {
            headline: "Take this offer?".to_string(),
            you_give: vec!["0.000000001 XCH".to_string()],
            you_receive: vec!["1 NFT abcd".to_string()],
            caution: None,
        }
    }

    /// **Both sides appear, and they are distinguishable.**
    ///
    /// The legs differ in asset AND in wording, so a renderer that printed one side twice — the
    /// nearest wrong version of this function — produces a body missing the other, rather than one
    /// that merely looks odd.
    #[test]
    fn a_rendered_swap_names_what_leaves_and_what_arrives() {
        let body = a_swap().render();

        assert!(body.contains("You give: 0.000000001 XCH"), "{body}");
        assert!(body.contains("You receive: 1 NFT abcd"), "{body}");
    }

    /// **An empty side is STATED, not omitted.**
    ///
    /// This is the make case: the maker gives an asset now and receives nothing until somebody takes
    /// the offer. A body that dropped the empty heading would read as a gift with no explanation.
    #[test]
    fn a_side_with_no_legs_is_written_as_nothing_rather_than_left_out() {
        let one_sided = TradeNarrative {
            you_receive: Vec::new(),
            ..a_swap()
        };

        let body = one_sided.render();
        assert!(body.contains("You receive: Nothing"), "{body}");
    }

    /// **The caution survives rendering and lands last.**
    ///
    /// NC-14: a destructive act must be NAMED, and a value delta is not consent. The position is
    /// asserted, not merely the presence, because a warning printed above the figures is one a person
    /// reads before they know what it applies to.
    #[test]
    fn a_caution_is_rendered_after_both_sides() {
        let destructive = TradeNarrative {
            caution: Some("Nobody will be able to fill this offer afterwards.".to_string()),
            ..a_swap()
        };

        let body = destructive.render();
        let caution_at = body
            .find("Nobody will be able")
            .expect("the caution is printed");
        let receive_at = body.find("You receive").expect("the sides are printed");
        assert!(caution_at > receive_at, "the caution comes last: {body}");
    }

    /// **A staged narrative does not outlive its operation.**
    ///
    /// The guard is dropped inside a scope and the slot is read AFTER it, which is exactly the
    /// sequence a second, unrelated spend would perform. A bare setter passes the first assertion and
    /// fails this one.
    #[test]
    fn a_narrative_is_cleared_when_its_operation_ends() {
        let slot = NarrativeSlot::default();
        assert_eq!(slot.get(), None, "nothing is staged before an operation");

        {
            let _staged = slot.set(a_swap());
            assert_eq!(slot.get(), Some(a_swap()));
        }

        assert_eq!(
            slot.get(),
            None,
            "the next spend must not inherit the last one's story"
        );
    }
}
