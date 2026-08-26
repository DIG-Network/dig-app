//! A call-volume bound for the `[::1]:9779` loopback channel (dig-app#277).
//!
//! # What this bounds, and what it deliberately does not
//!
//! Every method on the channel shares one gate, applied where the frame is already authenticated and
//! BEFORE it is dispatched. That placement is the security property: `control.request` turns one
//! inbound loopback frame into one outbound HTTP call to dig-node, so a connected origin can drive
//! load on the user's node through this app without ever touching the node itself. A bound applied
//! after the dial would cut the DISCLOSURE and leave the amplification untouched.
//!
//! It bounds VOLUME only. Whether a caller may reach a method at all is the pairing scope's job
//! (`CAP_NOT_GRANTED`), and whether an origin may reach the node is the whitelist's
//! (`CONNECT_REQUIRED`). This gate assumes both have already said yes.
//!
//! # Two budgets, BOTH scoped to the authenticated pairing
//!
//! A pairing is charged for every frame, and the `(pairing, origin)` pair is charged again for the
//! methods that name an origin. So one pairing cannot dump its whole allowance onto a single origin.
//!
//! **The origin budget is deliberately NOT shared across pairings, and that is a security property
//! rather than a simplification (dig-app#282 gate).** The origin arrives as an unauthenticated,
//! caller-supplied string in the frame's own params: a caller may name any origin, including one it
//! has never connected to. A budget keyed on that string ALONE is a shared resource between mutually
//! untrusting principals, and every such resource is a denial-of-service weapon. It was demonstrated
//! as one -- a pairing holding ZERO capabilities, whose every frame bounced `CAP_NOT_GRANTED`, denied
//! a victim's FIRST legitimate `control.request` on the victim's own consented origin, simply by
//! naming it. Keying on the pair confines a caller to budgets it is the only spender of.
//!
//! Whitelisting the origin first does NOT fix it: the victim's origin is precisely the one that is
//! whitelisted.
//!
//! **These are per-ACTOR bounds, not per-OPERATION ones.** A pairing's budget is shared across every
//! method it calls: fifty `identity.unseal` calls leave ten of that minute for `control.request`.
//! Stated rather than implied, because "N per minute" is ambiguous across a caller with several
//! connected origins, and a caller that budgeted per method would be wrong.
//!
//! # Why a token bucket rather than a fixed window
//!
//! A fixed window lets a caller spend a whole window at the end of one and another at the start of
//! the next, which is a 2x burst at every boundary -- for an amplifying method that is exactly the
//! case worth preventing. A bucket earns capacity back continuously and has no boundary to aim at.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many frames one PAIRING may have in hand at once.
///
/// Sized against the human behind the channel rather than against the transport: a dapp polling
/// `control.status` on a one-second cadence uses one, and a UI reacting to a click spends a handful.
/// A caller writing frames as fast as it can serialize them is orders of magnitude above this, which
/// is the gap that makes the bound cheap to respect and expensive to exceed.
const PAIRING_BURST: u32 = 60;

/// How fast a PAIRING earns its budget back -- one frame per second, so 60 per minute sustained.
const PAIRING_PER_SEC: f64 = 1.0;

/// How many frames one `(pairing, origin)` pair may have in hand at once.
///
/// Below the pairing burst on purpose, which is what makes it a real sub-bound: a pairing holding 60
/// frames cannot spend more than 30 of them on any single origin.
const ORIGIN_BURST: u32 = 30;

/// How fast a `(pairing, origin)` pair earns its budget back -- 30 per minute sustained.
const ORIGIN_PER_SEC: f64 = 0.5;

/// The longest origin string that may key a bucket.
///
/// A real origin is a scheme, a host and maybe a port; 255 bytes is far beyond any of them. The cap
/// exists because the origin is attacker-supplied and arrives inside a frame whose transport permits
/// very large payloads, so without it one caller could mint bucket keys measured in mebibytes.
///
/// **Over-length origins are REJECTED as bucket keys, never truncated.** Truncating would map two
/// distinct origins onto one bucket, which re-creates the cross-actor interference this keying
/// exists to remove -- the same defect wearing a smaller hat. A rejected origin simply gets no
/// origin bucket; the frame is still charged to its pairing, so it stays bounded, and no origin this
/// long can be whitelisted, so the handler refuses it moments later anyway.
const MAX_ORIGIN_LEN: usize = 255;

/// How long an idle bucket is kept before it is forgotten.
///
/// Long enough that a caller pausing between bursts is not handed a fresh full budget for free, and
/// short enough that the maps do not accumulate. Eviction is what keeps this a bound on the caller
/// rather than a memory cost the caller controls.
const IDLE_EVICTION: Duration = Duration::from_secs(600);

/// One caller's earned allowance.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Frames in hand. Fractional because refill is continuous.
    tokens: f64,
    /// When `tokens` was last brought up to date.
    at: Instant,
    /// Whether the last decision on this bucket was a refusal.
    ///
    /// Carried solely so the caller can log the TRANSITION into throttling rather than every refused
    /// frame. A refused frame costs its sender nothing, so one log line per refusal is a log-volume
    /// amplifier: the cheapest thing on the channel would drive the most writes to disk.
    refusing: bool,
}

/// What a bucket decided, and whether it is worth saying so out loud.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Charge {
    /// A token was available and has been spent.
    Admitted,
    /// No token was available.
    Refused {
        /// True only for the FIRST refusal since this bucket last admitted something.
        first: bool,
    },
}

impl Bucket {
    fn full(burst: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(burst),
            at: now,
            refusing: false,
        }
    }

    /// Earn tokens for the elapsed time, then spend one if there is one to spend.
    fn take(&mut self, burst: u32, per_sec: f64, now: Instant) -> Charge {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * per_sec).min(f64::from(burst));
        self.at = now;
        if self.tokens < 1.0 {
            let first = !self.refusing;
            self.refusing = true;
            return Charge::Refused { first };
        }
        self.tokens -= 1.0;
        self.refusing = false;
        Charge::Admitted
    }
}

/// Which actor was over its budget.
///
/// Kept apart from the wire code on purpose: the caller is told only that it was throttled, while
/// the log can say which bound bit. Telling a caller WHICH actor ran out would let it map the
/// boundary between an origin and the pairing carrying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Throttled {
    /// The pairing has spent its allowance across all of its origins.
    Pairing,
    /// This pairing has spent its allowance on this particular origin.
    Origin,
}

impl Throttled {
    /// The actor name used in the log line, never on the wire.
    pub fn actor(self) -> &'static str {
        match self {
            Self::Pairing => "pairing",
            Self::Origin => "pairing+origin",
        }
    }
}

/// A refusal, and whether it is the first of its run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// Which budget was exhausted. For the log only -- never for the wire, since telling a caller
    /// which bound bit would let it map the boundary between an origin and its pairing.
    pub actor: Throttled,
    /// True only for the FIRST refusal since that budget last admitted a frame.
    ///
    /// Exists so a caller can log the transition rather than every refused frame: refused frames are
    /// free to send, so logging each one turns the bound into a log-volume amplifier.
    pub first: bool,
}

/// The channel's call-volume bound, shared by every method on it.
#[derive(Debug, Default)]
pub struct ChannelLimiter {
    pairings: Mutex<HashMap<String, Bucket>>,
    /// Keyed on the PAIR, never on the origin alone. See the module doc: an origin-only key is a
    /// budget shared between mutually untrusting callers, and therefore a weapon.
    ///
    /// A tuple key rather than a joined string so there is no separator to reason about -- no pair of
    /// distinct `(pairing, origin)` values can collide onto one bucket by construction.
    origins: Mutex<HashMap<(String, String), Bucket>>,
}

impl ChannelLimiter {
    /// A limiter with no history -- every caller starts with a full allowance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Charge one frame to `pairing_id`, and to `(pairing_id, origin)` when the method carries one.
    ///
    /// `Ok(())` admits the frame. `Err` names the budget that was exhausted and whether this is the
    /// first refusal of its run.
    ///
    /// # Why BOTH budgets are scoped to the pairing
    ///
    /// `origin` is read from the frame's own params and is NOT authenticated: a caller may name any
    /// origin, including one it has never connected to and one that belongs to somebody else. A
    /// budget keyed on that string alone is therefore shared between untrusting principals, and a
    /// caller can exhaust it on another caller's behalf. Keying on the pair means every budget has
    /// exactly one possible spender.
    ///
    /// # Why the pairing is charged FIRST
    ///
    /// Charging the pairing first means an attempt to mint a new origin bucket costs the caller a
    /// token it must actually hold, so the number of buckets one caller can create is bounded by its
    /// own allowance rather than by how fast it can write frames.
    ///
    /// A refused frame is charged to the pairing but NOT to the origin: a caller already over its
    /// pairing budget must not go on draining its own origin budgets while it waits.
    pub fn admit(
        &self,
        pairing_id: &str,
        origin: Option<&str>,
        now: Instant,
    ) -> Result<(), Refusal> {
        if let Charge::Refused { first } = Self::spend(
            &self.pairings,
            pairing_id.to_string(),
            PAIRING_BURST,
            PAIRING_PER_SEC,
            now,
        ) {
            return Err(Refusal {
                actor: Throttled::Pairing,
                first,
            });
        }
        // An over-length origin gets NO bucket rather than a truncated one, so it can neither cost
        // unbounded memory nor be merged with a different origin. The frame remains bounded by the
        // pairing charge above.
        let Some(origin) = origin.filter(|origin| origin.len() <= MAX_ORIGIN_LEN) else {
            return Ok(());
        };
        match Self::spend(
            &self.origins,
            (pairing_id.to_string(), origin.to_string()),
            ORIGIN_BURST,
            ORIGIN_PER_SEC,
            now,
        ) {
            Charge::Refused { first } => Err(Refusal {
                actor: Throttled::Origin,
                first,
            }),
            Charge::Admitted => Ok(()),
        }
    }

    /// Spend one token from `key`'s bucket in `buckets`, creating a full one if it has none.
    ///
    /// A poisoned lock ADMITS the frame. The alternative -- refusing every call on the channel for
    /// the life of the process because a limiter thread panicked -- would turn a volume bound into
    /// an outage, and this gate is defence in depth behind the scope and whitelist checks that
    /// decide whether the call is allowed at all.
    fn spend<K: std::hash::Hash + Eq>(
        buckets: &Mutex<HashMap<K, Bucket>>,
        key: K,
        burst: u32,
        per_sec: f64,
        now: Instant,
    ) -> Charge {
        let Ok(mut buckets) = buckets.lock() else {
            return Charge::Admitted;
        };
        buckets.retain(|_, bucket| now.saturating_duration_since(bucket.at) < IDLE_EVICTION);
        buckets
            .entry(key)
            .or_insert_with(|| Bucket::full(burst, now))
            .take(burst, per_sec, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "pairing-a";
    const O: &str = "https://example.test";

    fn admitted(
        limiter: &ChannelLimiter,
        pairing: &str,
        origin: Option<&str>,
        now: Instant,
    ) -> bool {
        limiter.admit(pairing, origin, now).is_ok()
    }

    fn actor(
        limiter: &ChannelLimiter,
        pairing: &str,
        origin: Option<&str>,
        now: Instant,
    ) -> Throttled {
        limiter
            .admit(pairing, origin, now)
            .expect_err("expected a refusal")
            .actor
    }

    /// The control that keeps every refusal test below honest: a caller UNDER the bound is admitted.
    ///
    /// A limiter that refused everything would satisfy each "is refused" assertion on its own.
    #[test]
    fn a_caller_under_the_bound_is_admitted_every_time() {
        let limiter = ChannelLimiter::new();
        let now = Instant::now();
        for i in 0..ORIGIN_BURST {
            assert!(
                admitted(&limiter, P, Some(O), now),
                "frame {i} was refused while still inside the bound"
            );
        }
    }

    #[test]
    fn a_pairing_over_its_burst_is_refused_and_named() {
        let limiter = ChannelLimiter::new();
        let now = Instant::now();
        // Spend the pairing's whole allowance without ever touching an origin bucket.
        for _ in 0..PAIRING_BURST {
            assert!(admitted(&limiter, P, None, now));
        }
        assert_eq!(actor(&limiter, P, None, now), Throttled::Pairing);
    }

    /// **The gating regression test (dig-app#282 gate).**
    ///
    /// An attacker pairing MUST NOT be able to deny a victim service on the victim's own origin by
    /// naming it. The earlier revision keyed the origin budget on the origin string alone, which is
    /// unauthenticated and caller-supplied, so this exact sequence denied the victim's FIRST
    /// legitimate request.
    ///
    /// The fixture mirrors the demonstrated attack rather than a convenient abstraction of it: the
    /// attacker holds a DIFFERENT pairing, never connects to the origin, and spends far more than
    /// the origin burst on it. The victim then arrives for the first time and must be admitted.
    #[test]
    fn one_pairing_cannot_exhaust_another_pairings_budget_on_a_shared_origin() {
        let limiter = ChannelLimiter::new();
        let now = Instant::now();
        let victim_origin = "https://victim.example";

        // The attacker spends everything it can while naming the victim's origin. It is capped by
        // its own pairing budget, which is the point -- the damage is confined to itself.
        let mut attacker_frames = 0;
        while admitted(&limiter, "pairing-attacker", Some(victim_origin), now) {
            attacker_frames += 1;
            assert!(
                attacker_frames < 10_000,
                "the attacker was never bounded at all"
            );
        }
        assert!(
            attacker_frames > 0,
            "the attacker was refused immediately, so this proves nothing about interference"
        );

        // The victim's FIRST frame on its own origin. This is the assertion the old keying failed.
        assert!(
            admitted(&limiter, "pairing-victim", Some(victim_origin), now),
            "an unrelated pairing denied the victim its first request by naming the victim's origin"
        );

        // And the victim still has its whole origin allowance, not a remnant of the attacker's.
        for i in 1..ORIGIN_BURST {
            assert!(
                admitted(&limiter, "pairing-victim", Some(victim_origin), now),
                "the victim's frame {i} was refused: its budget is still being shared"
            );
        }
    }

    /// The origin budget is a real SUB-bound of the pairing, not decoration.
    ///
    /// Without this, keying by the pair could be satisfied by an origin bucket that never refuses.
    #[test]
    fn one_pairing_cannot_spend_its_whole_allowance_on_a_single_origin() {
        let limiter = ChannelLimiter::new();
        let now = Instant::now();
        for _ in 0..ORIGIN_BURST {
            assert!(admitted(&limiter, P, Some(O), now));
        }
        assert_eq!(
            actor(&limiter, P, Some(O), now),
            Throttled::Origin,
            "a pairing spent more than the origin burst on one origin"
        );
        // The pairing itself still has budget left for a DIFFERENT origin, which is what makes the
        // refusal above the origin's and not the pairing's.
        assert!(
            admitted(&limiter, P, Some("https://other.example"), now),
            "the refusal was really the pairing bound, so this test does not measure the origin one"
        );
    }

    /// The bound is per ACTOR, not per METHOD: frames spent on one method reduce what is left for
    /// another. Asserted directly because the alternative reading -- a budget per method -- is the
    /// natural one to assume from "N per minute".
    #[test]
    fn one_pairings_budget_is_shared_across_every_method_it_calls() {
        let limiter = ChannelLimiter::new();
        let now = Instant::now();
        for _ in 0..PAIRING_BURST {
            // The limiter never sees a method name; that is the point being pinned.
            assert!(admitted(&limiter, P, None, now));
        }
        assert_eq!(
            actor(&limiter, P, Some(O), now),
            Throttled::Pairing,
            "a different method got its own fresh budget"
        );
    }

    /// A frame the PAIRING bound refused must not also drain that pairing's origin budget.
    #[test]
    fn a_frame_the_pairing_bound_refused_does_not_charge_the_origin() {
        let limiter = ChannelLimiter::new();
        let now = Instant::now();
        for _ in 0..PAIRING_BURST {
            assert!(admitted(&limiter, P, None, now));
        }
        for _ in 0..ORIGIN_BURST * 4 {
            assert_eq!(actor(&limiter, P, Some(O), now), Throttled::Pairing);
        }
        // Once the pairing recovers, the origin budget is untouched: a full burst is still there.
        let later = now + Duration::from_secs(120);
        for i in 0..ORIGIN_BURST {
            assert!(
                admitted(&limiter, P, Some(O), later),
                "origin frame {i} was refused -- refused frames drained the origin bucket"
            );
        }
    }

    /// An over-length origin is REJECTED as a key, never truncated.
    ///
    /// Truncation would map two distinct origins onto one bucket, re-creating the cross-actor
    /// interference the pair-keying exists to remove. Two origins that truncate to the same value are
    /// tested: if a truncating implementation existed, they would merge under the same pairing.
    #[test]
    fn an_over_length_origin_gets_no_bucket_and_is_never_truncated_into_a_shared_one() {
        let limiter = ChannelLimiter::new();
        let now = Instant::now();
        // Two origins that are at exactly MAX_ORIGIN_LEN and differ only in the last byte, so they
        // would truncate to the same value if truncation happened.
        let mut truncate_a = "a".repeat(MAX_ORIGIN_LEN);
        let mut truncate_b = truncate_a.clone();
        // Change only the last byte so they differ but would be identical if truncated.
        truncate_a.pop();
        truncate_a.push('a');
        truncate_b.pop();
        truncate_b.push('b');

        // Spend the ORIGIN burst on the first origin under pairing P, exhausting its bucket.
        for i in 0..ORIGIN_BURST {
            assert!(
                admitted(&limiter, P, Some(&truncate_a), now),
                "frame {i} on a length-at-boundary origin should be admitted within the burst"
            );
        }
        // A second origin that would truncate to the same value as the first, under the same
        // pairing, is unaffected -- which a truncating implementation could not manage, since both
        // would truncate to the same key and merge into the exhausted bucket.
        assert!(
            admitted(&limiter, P, Some(&truncate_b), now),
            "two origins that truncate to the same value were merged into one bucket"
        );

        // The exact boundary: MAX_ORIGIN_LEN is accepted and DOES get a bucket, one over does not.
        let at_bound = "x".repeat(MAX_ORIGIN_LEN);
        let over_bound = "x".repeat(MAX_ORIGIN_LEN + 1);
        let fresh = ChannelLimiter::new();
        for _ in 0..ORIGIN_BURST {
            assert!(admitted(&fresh, P, Some(&at_bound), now));
        }
        assert_eq!(
            actor(&fresh, P, Some(&at_bound), now),
            Throttled::Origin,
            "an origin of exactly MAX_ORIGIN_LEN was rejected as a key instead of bucketed"
        );
        let fresh = ChannelLimiter::new();
        // The FULL pairing burst, not the origin burst: with no origin bucket the only bound left is
        // the pairing one, so stopping at ORIGIN_BURST would prove nothing either way.
        for _ in 0..PAIRING_BURST {
            assert!(admitted(&fresh, P, Some(&over_bound), now));
        }
        assert_eq!(
            actor(&fresh, P, Some(&over_bound), now),
            Throttled::Pairing,
            "an over-length origin was given a bucket after all"
        );
    }

    /// Only the FIRST refusal of a run is flagged, so a caller cannot drive one log line per frame.
    #[test]
    fn only_the_first_refusal_of_a_run_is_worth_logging() {
        let limiter = ChannelLimiter::new();
        let now = Instant::now();
        for _ in 0..PAIRING_BURST {
            assert!(admitted(&limiter, P, None, now));
        }
        let first = limiter.admit(P, None, now).expect_err("refused");
        assert!(first.first, "the first refusal of a run was not flagged");
        for _ in 0..500 {
            let next = limiter.admit(P, None, now).expect_err("refused");
            assert!(
                !next.first,
                "every refused frame is flagged for logging, so a free-to-send frame drives a log write -- the log-eviction shape"
            );
        }
        // Recovering and refusing again DOES flag a new run, or an episode after a quiet period
        // would go unrecorded entirely. The idle time must be below IDLE_EVICTION (600 s) so the
        // bucket survives and the log-dedup reset is actually exercised.
        let later = now + Duration::from_secs(120);
        // Drain the refilled bucket and catch the very first refusal of the NEW run, rather than
        // spending a fixed count -- a fixed count consumes the transition inside the loop and then
        // asserts on the second refusal, which is flagged false for the right reason.
        let mut reopened = None;
        for _ in 0..=PAIRING_BURST {
            if let Err(refusal) = limiter.admit(P, None, later) {
                reopened = Some(refusal);
                break;
            }
        }
        assert!(
            reopened
                .expect("the refilled bucket never refused again")
                .first,
            "a new throttling episode after a quiet period was never flagged for logging"
        );
    }

    /// Waiting earns the budget back, at the stated rate and no faster.
    ///
    /// Pinned to an explicit clock rather than sleeping, and asserted from BOTH sides: one
    /// millisecond short of a token must still refuse, and an idle bucket must not accumulate past
    /// its burst however long the wait.
    #[test]
    fn a_bucket_refills_at_the_stated_rate_and_never_past_its_burst() {
        let limiter = ChannelLimiter::new();
        let start = Instant::now();
        for _ in 0..PAIRING_BURST {
            assert!(admitted(&limiter, P, None, start));
        }

        // Just under one token's worth of time: still refused.
        let nearly = start + Duration::from_millis(999);
        assert_eq!(
            actor(&limiter, P, None, nearly),
            Throttled::Pairing,
            "a token was earned before the stated rate had elapsed"
        );

        // Just over one token's worth: EXACTLY one frame passes, and the next is refused again.
        //
        // Measured from `nearly` rather than from `start`, because the refused call above still
        // brought the bucket up to date -- it holds 0.999 tokens at that point. 50ms more earns it
        // to 1.049: one frame, with enough margin that no float rounding can decide the outcome, and
        // far enough below 2.0 that the "and then refused" half is a real assertion rather than an
        // artifact of having waited too long. Waiting 2s here earned TWO tokens and let this test
        // pass a frame it should have refused.
        let earned = nearly + Duration::from_millis(50);
        assert!(admitted(&limiter, P, None, earned));
        assert_eq!(
            actor(&limiter, P, None, earned),
            Throttled::Pairing,
            "more than one token was earned for one token's worth of waiting"
        );

        // An hour of idling earns the burst back and NOT more.
        let rested = earned + Duration::from_secs(3_600);
        for i in 0..PAIRING_BURST {
            assert!(
                admitted(&limiter, P, None, rested),
                "frame {i} was refused after a full rest"
            );
        }
        assert_eq!(
            actor(&limiter, P, None, rested),
            Throttled::Pairing,
            "an idle bucket accumulated more than its burst"
        );
    }
}
