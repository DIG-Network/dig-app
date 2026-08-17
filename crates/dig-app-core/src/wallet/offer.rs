//! Reading and taking a Chia offer (dig_ecosystem#3077, slices O1 + O2).
//!
//! # The one rule this module exists to enforce
//!
//! **What a person is shown derives from the very bytes that would be broadcast.** A
//! [`ReviewedOffer`] owns the `offer1…` string it was read from, and [`ReviewedOffer::terms`] is the
//! [`dig_offers::summarize`] of THAT string, computed once in [`ReviewedOffer::read`]. There is no
//! constructor that takes terms, so no cache, re-parse or reconstruction can drift from the offer a
//! take would actually settle — the display and the spend are two borrows of one value.
//!
//! # Where the money boundary is
//!
//! `dig-offers` is pure: it never holds a key, never signs and never broadcasts. So the take is a
//! three-party flow and each party does exactly one thing:
//!
//! 1. **`dig-offers`** — [`take_build`](dig_offers::take_build) produces the taker's UNSIGNED coin
//!    spends and the parsed maker [`Offer`](dig_offers::Offer), whose half is already signed.
//! 2. **`dig-account`** — [`MoneyPath::authorize_and_sign`](crate::account::money::MoneyPath::authorize_and_sign)
//!    rules on those bytes at the custody gate and, if permitted, signs them. The key never leaves it.
//! 3. **`dig-node`** — receives the combined, fully-signed bundle and broadcasts it (§908).
//!
//! [`take_combine`](dig_offers::take_combine) welds the two signed halves into one atomic settlement
//! bundle between steps 2 and 3.
//!
//! # What "taken" does NOT mean
//!
//! Nothing in this module reports settlement. A broadcast's acceptance says only that a node took the
//! bundle; the settled verdict comes from a later chain read, which is
//! [`InFlightSend::status`](crate::wallet::send::InFlightSend::status)'s job, and the progress surface
//! is the centralized one every broadcast already raises.

use dig_offers::{OfferAsset, OfferSummary};

/// A failure reading or taking an offer, named by WHICH step refused.
///
/// The distinction a person needs is between *this text is not an offer* (retype or re-scan) and
/// *this offer cannot be taken by you* (a policy or a funding answer), so the two never collapse into
/// one grey failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OfferError {
    /// The text is not a decodable Chia offer. Carries the parser's own reason, never a guess.
    #[error("that is not a readable Chia offer: {0}")]
    Unreadable(String),

    /// This profile's custody policy forbids taking offers at all.
    ///
    /// Separate from every other refusal because it is a property of the PROFILE, not of the offer:
    /// no amount of funding or retrying changes it, so the control that would take the offer must be
    /// disabled up front with this sentence attached rather than failing at signing time.
    #[error("{0}")]
    CustodyForbids(String),
}

/// One leg of an offer, in the terms a person reads rather than the terms the chain stores.
///
/// The variants mirror [`dig_offers::OfferAsset`] exactly. It is restated here rather than re-exported
/// because a rendering surface must never be handed a type it could construct itself — the only route
/// to one of these is [`ReviewedOffer::read`], via the parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferLeg {
    /// Native XCH, in mojos.
    Xch { mojos: u64 },
    /// A CAT — `$DIG` and every other token — in the asset's own base units.
    Cat { asset_id: String, amount: u64 },
    /// A single NFT, named by its launcher id.
    Nft { launcher_id: String },
}

impl OfferLeg {
    /// Restate one parsed asset as a display leg.
    fn of(asset: &OfferAsset) -> Self {
        match asset {
            OfferAsset::Xch(mojos) => Self::Xch { mojos: *mojos },
            OfferAsset::Cat { asset_id, amount } => Self::Cat {
                asset_id: hex::encode(asset_id),
                amount: *amount,
            },
            OfferAsset::Nft { launcher_id } => Self::Nft {
                launcher_id: hex::encode(launcher_id),
            },
        }
    }
}

/// Both sides of a swap, named explicitly (NC-14).
///
/// A take is irreversible once it confirms, and its effect is a change of OWNERSHIP rather than a
/// change in a number. So the surface names what leaves and what arrives; it never renders a single
/// net figure, which would describe the same act as an arithmetic result and hide half of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferTerms {
    /// What taking this offer delivers to you.
    pub you_receive: Vec<OfferLeg>,
    /// What taking this offer costs you.
    pub you_pay: Vec<OfferLeg>,
    /// Royalty legs the offer carries, as `(launcher id, basis points)`.
    pub royalties: Vec<(String, u16)>,
}

impl OfferTerms {
    /// Restate a parser summary in display terms, in the parser's own direction.
    ///
    /// [`OfferSummary::offered`] is what the offer DELIVERS to whoever takes it, and `requested` is
    /// what it asks that person to pay — so the mapping is `offered → you_receive`. Inverting it
    /// would show a person the maker's point of view while asking them to act as the taker.
    fn of(summary: &OfferSummary) -> Self {
        Self {
            you_receive: summary.offered.iter().map(OfferLeg::of).collect(),
            you_pay: summary.requested.iter().map(OfferLeg::of).collect(),
            royalties: summary
                .royalties
                .iter()
                .map(|(launcher_id, bps)| (hex::encode(launcher_id), *bps))
                .collect(),
        }
    }

    /// Whether the offer has nothing to show on either side — an offer no surface should present as
    /// takeable, because a person cannot consent to a swap with no named sides.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.you_receive.is_empty() && self.you_pay.is_empty()
    }
}

/// An `offer1…` string that has been read, together with the terms read FROM it.
///
/// The two are inseparable by construction: [`read`](Self::read) is the only constructor and it
/// derives the terms from the string it stores. A take spends [`offer`](Self::offer) — the same
/// bytes — so there is no window in which a surface could show one offer and settle another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedOffer {
    offer: String,
    terms: OfferTerms,
}

impl ReviewedOffer {
    /// Read `offer` and summarize it, or say why it cannot be read.
    ///
    /// Leading and trailing whitespace is trimmed because an offer usually arrives pasted from a
    /// chat message or decoded from a QR frame, and neither delivers a bare token. The trimmed form
    /// is what is STORED, so the bytes summarized and the bytes taken stay identical.
    pub fn read(offer: &str) -> Result<Self, OfferError> {
        let offer = offer.trim().to_string();
        let summary =
            dig_offers::summarize(&offer).map_err(|e| OfferError::Unreadable(e.to_string()))?;
        Ok(Self {
            terms: OfferTerms::of(&summary),
            offer,
        })
    }

    /// The exact offer bytes these terms describe — and the bytes a take settles.
    #[must_use]
    pub fn offer(&self) -> &str {
        &self.offer
    }

    /// What this offer gives and asks, in the direction the person reading it acts.
    #[must_use]
    pub fn terms(&self) -> &OfferTerms {
        &self.terms
    }
}

/// Why a vault-tier profile cannot take an offer, in the words the disabled control carries.
///
/// dig-account's `reject_vault_outflow_to_anyone_but_the_hot_wallet` denies a vault spend that pays a
/// `ProtocolStructure` BY NAME, and the offer settlement puzzle is exactly that. The refusal is
/// correct — it is what keeps the 24-hour clawback window unavoidable — so the surface states the
/// remedy rather than presenting a control that would fail at signing time.
pub const VAULT_CANNOT_TAKE: &str = "This profile keeps its funds in the vault, and vault funds may \
                                     only be paid to your own hot wallet. Move what you want to \
                                     spend to the hot wallet first — it clears after the 24-hour \
                                     clawback window — then take the offer from there.";

/// Whether a profile on `custody` may take an offer at all, refusing with [`VAULT_CANNOT_TAKE`] when
/// it may not.
///
/// This is checked BEFORE a spend is built, so the answer reaches the control that would start the
/// take rather than the dialog at the end of it.
pub fn take_permitted_by(custody: &dig_account::CustodyPolicy) -> Result<(), OfferError> {
    match custody {
        dig_account::CustodyPolicy::Hot(_) => Ok(()),
        dig_account::CustodyPolicy::Vault(_) => {
            Err(OfferError::CustodyForbids(VAULT_CANNOT_TAKE.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::offer_fixture::{an_offer_of, XCH_FOR_XCH};

    #[test]
    fn text_that_is_not_an_offer_is_refused_with_the_parsers_own_reason() {
        let err = ReviewedOffer::read("hello").expect_err("plain text is not an offer");
        assert!(
            matches!(&err, OfferError::Unreadable(why) if why.contains("offer1")),
            "the refusal must carry what the parser actually said: {err}"
        );
    }

    /// **The stored bytes are the trimmed input, not the raw input.**
    ///
    /// A pasted offer carries whitespace, and if `read` summarized the trimmed form while storing the
    /// raw one, the take would hand `take_build` bytes the display never saw. The fixture therefore
    /// wraps the offer in whitespace on BOTH sides — a one-sided fixture cannot tell a full trim from
    /// a `trim_start`.
    #[test]
    fn the_bytes_stored_are_the_bytes_summarized() {
        let offer = an_offer_of(XCH_FOR_XCH);
        let padded = format!("\n  {offer}\t\n");

        let reviewed = ReviewedOffer::read(&padded).expect("a real offer must read");

        assert_eq!(reviewed.offer(), offer);
        assert_eq!(
            reviewed.terms(),
            &OfferTerms::of(&dig_offers::summarize(reviewed.offer()).unwrap()),
            "the terms shown must be the summary of the bytes stored"
        );
    }

    /// **The two sides are named in the taker's direction, and are distinguishable.**
    ///
    /// The fixture offers 1,000 mojos and requests 400 — two DIFFERENT amounts, because an offer
    /// whose sides were equal would read identically under an implementation that swapped them, and
    /// swapping them is the nearest wrong version of this mapping.
    #[test]
    fn both_sides_of_the_swap_are_named_from_the_takers_point_of_view() {
        let reviewed = ReviewedOffer::read(&an_offer_of(XCH_FOR_XCH)).expect("a real offer reads");

        assert_eq!(
            reviewed.terms().you_receive,
            vec![OfferLeg::Xch { mojos: 1_000 }],
            "the offered side is what the taker receives"
        );
        assert_eq!(
            reviewed.terms().you_pay,
            vec![OfferLeg::Xch { mojos: 400 }],
            "the requested side is what the taker pays"
        );
        assert!(!reviewed.terms().is_empty());
    }

    #[test]
    fn a_hot_profile_may_take_and_a_vault_profile_is_told_why_it_may_not() {
        use dig_account::{CustodyPolicy, HotWallet, Vault};

        assert!(take_permitted_by(&CustodyPolicy::Hot(HotWallet::default())).is_ok());

        let err = take_permitted_by(&CustodyPolicy::Vault(Vault::default()))
            .expect_err("a vault profile cannot commit funds to the settlement puzzle");
        let OfferError::CustodyForbids(why) = err else {
            panic!("a vault refusal is a custody refusal, not a parse failure");
        };
        assert!(
            why.contains("hot wallet") && why.contains("clawback"),
            "the refusal must name the remedy, not merely deny: {why}"
        );
    }
}
