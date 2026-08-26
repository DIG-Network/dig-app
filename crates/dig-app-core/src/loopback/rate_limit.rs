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
//! # Per PAIRING and per ORIGIN, because those are different actors
//!
//! A pairing carries no origin, so one paired app spreading calls across many whitelisted origins is
//! a different budget from one origin arriving through many pairings. Both are charged, and either
//! can refuse.
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

/// How many frames one ORIGIN may have in hand at once, across every pairing it arrives through.
///
/// Below the pairing burst on purpose. The pairing is the authenticated actor and the origin is the
/// consented one, and a single web origin has less reason to burst than an installed app does.
const ORIGIN_BURST: u32 = 30;

/// How fast an ORIGIN earns its budget back -- 30 per minute sustained.
const ORIGIN_PER_SEC: f64 = 0.5;

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
}

impl Bucket {
    fn full(burst: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(burst),
            at: now,
        }
    }

    /// Earn tokens for the elapsed time, then spend one if there is one to spend.
    fn take(&mut self, burst: u32, per_sec: f64, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * per_sec).min(f64::from(burst));
        self.at = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
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
    /// This origin has spent its allowance across all of the pairings carrying it.
    Origin,
}

impl Throttled {
    /// The actor name used in the log line, never on the wire.
    pub fn actor(self) -> &'static str {
        match self {
            Self::Pairing => "pairing",
            Self::Origin => "origin",
        }
    }
}

/// The channel's call-volume bound, shared by every method on it.
#[derive(Debug, Default)]
pub struct ChannelLimiter {
    pairings: Mutex<HashMap<String, Bucket>>,
    origins: Mutex<HashMap<String, Bucket>>,
}

impl ChannelLimiter {
    /// A limiter with no history -- every caller starts with a full allowance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Charge one frame to `pairing_id`, and to `origin` when the method carries one.
    ///
    /// `Ok(())` admits the frame. `Err` names the actor that was over, for the log.
    ///
    /// # Why the pairing is charged FIRST, and why that ordering is load-bearing
    ///
    /// The origin string is read from the frame's own params and is not yet known to be whitelisted
    /// at this point, so a caller can name origins this app has never seen. Charging the pairing
    /// first means every such attempt costs the caller a token it actually has to hold, which bounds
    /// how many distinct origin buckets one caller can cause to exist to that caller's own budget.
    /// Without that ordering the origin map would be a memory cost sized by the attacker.
    ///
    /// A refused frame is charged to the pairing but NOT to the origin: an actor already over its
    /// budget must not be able to burn a second actor's.
    pub fn admit(
        &self,
        pairing_id: &str,
        origin: Option<&str>,
        now: Instant,
    ) -> Result<(), Throttled> {
        if !Self::spend(
            &self.pairings,
            pairing_id,
            PAIRING_BURST,
            PAIRING_PER_SEC,
            now,
        ) {
            return Err(Throttled::Pairing);
        }
        match origin {
            Some(origin)
                if !Self::spend(&self.origins, origin, ORIGIN_BURST, ORIGIN_PER_SEC, now) =>
            {
                Err(Throttled::Origin)
            }
            _ => Ok(()),
        }
    }

    /// Spend one token from `key`'s bucket in `buckets`, creating a full one if it has none.
    ///
    /// A poisoned lock ADMITS the frame. The alternative -- refusing every call on the channel for
    /// the life of the process because a limiter thread panicked -- would turn a volume bound into
    /// an outage, and this gate is defence in depth behind the scope and whitelist checks that
    /// decide whether the call is allowed at all.
    fn spend(
        buckets: &Mutex<HashMap<String, Bucket>>,
        key: &str,
        burst: u32,
        per_sec: f64,
        now: Instant,
    ) -> bool {
        let Ok(mut buckets) = buckets.lock() else {
            return true;
        };
        buckets.retain(|_, bucket| now.saturating_duration_since(bucket.at) < IDLE_EVICTION);
        buckets
            .entry(key.to_string())
            .or_insert_with(|| Bucket::full(burst, now))
            .take(burst, per_sec, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "pairing-a";
    const O: &str = "https://example.test";

    /// The control that keeps every refusal test below honest: a caller UNDER the bound is admitted.
    ///
    /// A limiter that refused everything would satisfy each "is refused" assertion on its own.
    #[test]
    fn a_caller_under_the_bound_is_admitted_every_time() {
        let limiter = ChannelLimiter::new();
        let now = Instant::now();
        for i in 0..ORIGIN_BURST {
            assert_eq!(
                limiter.admit(P, Some(O), now),
                Ok(()),
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
            assert_eq!(limiter.admit(P, None, now), Ok(()));
        }
        assert_eq!(limiter.admit(P, None, now), Err(Throttled::Pairing));
    }

    #[test]
    fn an_origin_over_its_burst_is_refused_even_on_a_fresh_pairing() {
        let limiter = ChannelLimiter::new();
        let now = Instant::now();
        // Spread the origin's allowance across enough pairings that no pairing is near its own
        // bound -- so the refusal below can only be the ORIGIN's budget, never the pairing's.
        for i in 0..ORIGIN_BURST {
            assert_eq!(limiter.admit(&format!("pairing-{i}"), Some(O), now), Ok(()));
        }
        assert_eq!(
            limiter.admit("pairing-never-used", Some(O), now),
            Err(Throttled::Origin),
            "an origin's budget did not follow it across pairings"
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
            assert_eq!(limiter.admit(P, None, now), Ok(()));
        }
        assert_eq!(
            limiter.admit(P, Some(O), now),
            Err(Throttled::Pairing),
            "a different method got its own fresh budget"
        );
    }

    /// A refused frame must not burn the ORIGIN's budget. Otherwise one exhausted pairing could
    /// deny service to every other pairing that shares that origin.
    #[test]
    fn a_frame_the_pairing_bound_refused_does_not_charge_the_origin() {
        let limiter = ChannelLimiter::new();
        let now = Instant::now();
        for _ in 0..PAIRING_BURST {
            assert_eq!(limiter.admit(P, None, now), Ok(()));
        }
        // Hammer the exhausted pairing while naming the origin.
        for _ in 0..ORIGIN_BURST * 4 {
            assert_eq!(limiter.admit(P, Some(O), now), Err(Throttled::Pairing));
        }
        // The origin never paid for any of that, so a different pairing still reaches it.
        assert_eq!(limiter.admit("pairing-b", Some(O), now), Ok(()));
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
            assert_eq!(limiter.admit(P, None, start), Ok(()));
        }

        // Just under one token's worth of time: still refused.
        let nearly = start + Duration::from_millis(999);
        assert_eq!(
            limiter.admit(P, None, nearly),
            Err(Throttled::Pairing),
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
        assert_eq!(limiter.admit(P, None, earned), Ok(()));
        assert_eq!(
            limiter.admit(P, None, earned),
            Err(Throttled::Pairing),
            "more than one token was earned for one token's worth of waiting"
        );

        // An hour of idling earns the burst back and NOT more.
        let rested = earned + Duration::from_secs(3_600);
        for i in 0..PAIRING_BURST {
            assert_eq!(
                limiter.admit(P, None, rested),
                Ok(()),
                "frame {i} was refused after a full rest"
            );
        }
        assert_eq!(
            limiter.admit(P, None, rested),
            Err(Throttled::Pairing),
            "an idle bucket accumulated more than its burst"
        );
    }
}
