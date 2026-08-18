//! The sentences the custody confirm prompt says about an offer (dig_ecosystem#3109, NC-14).
//!
//! # Why these live beside the offer logic rather than in the window's copy module
//!
//! They are not window text. They are read at the OS-native confirm gate, which the window does not
//! draw and cannot test, and they are written by [`taking`](crate::wallet::taking),
//! [`making`](crate::wallet::making) and [`cancelling`](crate::wallet::cancelling) — three modules
//! that must not each invent their own wording for the same three acts.
//!
//! # The rule every sentence here obeys
//!
//! **Name the act and its consequence, not the arithmetic.** A person approving a swap or a
//! cancellation is not consenting to a value delta; they are consenting to something that cannot be
//! undone. The figures come from the narrative and the re-derived summary; these sentences say what
//! the figures MEAN.

/// The question over a take: it is a swap, and it settles both ways.
pub const TAKE_HEADLINE: &str = "Take this offer?";

/// What a take cannot be undone from, said before the buttons.
pub const TAKE_CAUTION: &str =
    "Once this settles it cannot be reversed. Both sides move together, or neither does.";

/// The question over a make.
pub const MAKE_HEADLINE: &str = "Make this offer?";

/// The consequence a make's figures cannot express.
///
/// The asymmetry is the whole point and it is why a make is the most misread of the three: what the
/// maker gives is committed NOW, and what they asked for arrives only if somebody takes the offer.
/// A person who reads a make as a completed trade has misunderstood it in the one direction that
/// costs them.
pub const MAKE_CAUTION: &str =
    "What you give is committed to this offer as soon as it is made. What you asked for arrives \
     only when somebody takes it, and nobody is obliged to. You can cancel the offer to reclaim \
     your coins while it is still unfilled.";

/// The question over a cancel — NAMED as the destructive act it is (NC-14, dig_ecosystem#3079).
///
/// "Cancel" is the word for it, and it is the word a person searched for, so it stays. What makes
/// this honest is the caution beside it, which states the effect a reclaim figure alone does not.
pub const CANCEL_HEADLINE: &str = "Cancel this offer? This cannot be undone.";

/// What cancelling destroys, stated because a value delta is not consent.
///
/// A cancel LOOKS like a payment to yourself, and a confirm prompt showing only the re-derived
/// figures would read as exactly that. The destroyed thing — an outstanding offer somebody may be
/// about to accept — appears in no number on the screen.
pub const CANCEL_CAUTION: &str =
    "The offer string you shared stops working. Anybody still holding it will not be able to fill \
     it, and you cannot un-cancel it — you would have to make a new offer.";

/// What a cancel gives back, phrased for the narrative's "you receive" side.
///
/// A cancel is a reclaim, not an arrival of anything new, and the wording says so rather than
/// implying the person has gained something.
pub const CANCEL_RECLAIM_PREFIX: &str = "back the ";
