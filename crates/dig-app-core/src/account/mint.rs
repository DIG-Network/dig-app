//! Minting an on-chain DID, and WAITING for the chain to confirm it (dig_ecosystem#2341).
//!
//! # Why the wait is a state machine and not a spinner
//!
//! A DID mint is a real Chia spend. Confirmation takes blocks, not milliseconds, and it can end in
//! four genuinely different places: confirmed, rejected by the chain, unreachable because this
//! computer lost its connection, or still pending long after a person stopped wanting to watch. A
//! spinner expresses exactly one of those and cannot fail — which is the dead end dig_ecosystem#1800
//! removed from this app once already.
//!
//! So the wait lives here, as [`await_confirmation`]: a loop that polls a [`MintObserver`], reports
//! its progress to a [`WaitSurface`] the user can stop at any time, and ends in a
//! [`MintOutcome`] that names which of the four happened. The surface is a seam, so a live animated
//! window can replace a sequence of notices without this logic changing.
//!
//! # The rule the outcome carries
//!
//! [`MintOutcome::Confirmed`] is reachable ONLY from [`Sighting::Confirmed`], and it carries the
//! [`MintEvidence`] that sighting produced. A submission alone can never produce it. That is what stops
//! the wizard from writing a DID that the chain never accepted — see [`crate::account::did`].

use crate::account::did::MintEvidence;
use crate::account::second_factor::journey::Clock;

/// Submits the DID mint spend.
///
/// A seam because nothing in dig-app can mint today — and the reason is worth stating precisely,
/// because it is no longer the obvious one.
///
/// `dig-account` 0.5.0 **does** implement the mint: `ProfileMinter::begin_did_mint` builds, signs and
/// pushes a real spend, and `ProfileMinter::mint_status` turns a buried confirmation into evidence. The
/// gap is reachability. `ProfileMinter::new` takes an `Arc<UnlockedMasterSeed>`, and nothing in
/// dig-account's public API produces one: `UnlockedAccount` holds the seed privately and hands out an
/// identity signer, wallet ops, a DEK, a sealing key and the recovery phrase — but no minter.
/// dig_ecosystem#2371 adds the accessor.
///
/// The one workaround available to dig-app would be to re-unlock the master seed through `dig-session`
/// and hold a second `Arc<UnlockedMasterSeed>` outside dig-account. That copy would not observe the
/// account's [`Residency`](dig_account::Residency), so lock-now, the idle timeout and the OS screen
/// lock would all leave it live and able to spend. In a binary whose whole custody model is one
/// lockable seed home, that is the wrong trade, and it is not made here.
///
/// So the production implementation stays [`UnavailableMinter`], which refuses honestly. When the
/// accessor lands, the real minter implements this trait and the wizard is unchanged.
pub trait DidMinter {
    /// Build, authorize, sign and push the mint spend.
    ///
    /// The user's key never leaves this computer: the implementation signs locally and pushes the
    /// signed bundle, exactly as every other money path in dig-app does.
    fn submit(&self) -> Submission;
}

/// What submitting the mint did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submission {
    /// The spend reached the network. **This is not a success** — it is the start of the wait.
    Submitted {
        /// The spend to watch for, handed to [`MintObserver::look`].
        spend_id: String,
        /// The DID the spend creates, which becomes real only once the spend is confirmed.
        did: String,
    },
    /// The wallet does not hold enough XCH to pay for the spend.
    InsufficientFunds {
        /// What the mint costs, in whole XCH, already formatted for a human.
        needed: String,
    },
    /// The spend was refused before it left this computer — the user declined the consent window, or
    /// building it failed. `reason` is shown to the user verbatim.
    Refused {
        /// Why, in the user's words.
        reason: String,
    },
    /// No code path can mint on this build. Distinct from [`Submission::Refused`] because the user did
    /// nothing wrong and there is nothing they can do differently.
    NotAvailable,
}

/// The production [`DidMinter`] until `dig-account`'s minter is real.
///
/// It refuses honestly rather than pretending. Deliberately NOT a silent no-op: a minter that returned
/// a fabricated spend id would send the wizard into a wait for something that was never submitted.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableMinter;

impl DidMinter for UnavailableMinter {
    fn submit(&self) -> Submission {
        Submission::NotAvailable
    }
}

/// Watches the chain for a submitted mint.
pub trait MintObserver {
    /// Look for `spend_id` right now. Must not block for longer than one poll interval.
    fn look(&self, spend_id: &str) -> Sighting;
}

/// What one look at the chain saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sighting {
    /// Not confirmed yet, and nothing is wrong. Keep waiting.
    Pending,
    /// Confirmed in a block. The ONLY thing that can produce a [`MintOutcome::Confirmed`].
    Confirmed(MintEvidence),
    /// The chain rejected the spend. It will never confirm; waiting longer changes nothing.
    Rejected {
        /// Why, in the user's words.
        reason: String,
    },
    /// This computer could not reach the chain. The spend may well be fine — the WATCHER is what
    /// failed — so this is reported as a lost connection, never as a rejection.
    Unreachable,
}

/// How far the wait has got, handed to the [`WaitSurface`] so the user is told the truth about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitProgress {
    /// Seconds since the spend was submitted.
    pub elapsed_secs: u64,
    /// Seconds after which [`await_confirmation`] gives up and reports [`MintOutcome::StillPending`].
    pub give_up_after_secs: u64,
    /// How many consecutive looks failed to reach the chain. Zero on a healthy wait.
    pub unreachable_looks: u32,
}

impl WaitProgress {
    /// Whether the watcher is currently unable to reach the chain, so the surface can say so instead of
    /// showing a silent, indistinguishable "still waiting".
    pub fn connection_lost(&self) -> bool {
        self.unreachable_looks >= UNREACHABLE_LOOKS_BEFORE_SAYING_SO
    }
}

/// How many consecutive unreachable looks before the user is told the connection is the problem.
///
/// More than one, because a single failed look is ordinary on any network and telling a person their
/// connection is down for one dropped request would make the message meaningless. Small enough that a
/// genuinely offline machine is not left reading "still waiting" for minutes.
const UNREACHABLE_LOOKS_BEFORE_SAYING_SO: u32 = 3;

/// The user's answer to "this is still going — keep waiting?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepWaiting {
    /// Keep polling.
    Yes,
    /// Stop watching. The spend is NOT cancelled — it is on the chain and may still confirm — so the
    /// outcome is [`MintOutcome::StillPending`], never a failure.
    No,
}

/// Where the wait is drawn, and where the user's "stop watching" comes from.
///
/// A seam for the same reason [`DidMinter`] is one: the wait must be drivable by a test at a pinned
/// clock, and the surface that draws it is a platform concern. Today the shell implements it with the
/// app's existing OS-owned windows; a live-updating window implements the same two methods.
pub trait WaitSurface {
    /// The wait has been going for `progress.elapsed_secs`. Return whether to keep waiting.
    ///
    /// Called on [`CHECK_IN_EVERY_SECS`] boundaries, not on every poll — a person does not want a
    /// window every few seconds, and a surface that cannot be escaped is the thing this seam exists to
    /// avoid.
    fn checking_in(&self, progress: &WaitProgress) -> KeepWaiting;

    /// Sleep until the next poll. Injected so a test drives the loop without real time passing.
    fn wait_a_moment(&self);
}

/// How often the wait polls the chain.
///
/// A Chia block is about 52 seconds, so polling faster than this only adds load; polling slower makes
/// the reported elapsed time coarse enough to look stuck.
pub const POLL_EVERY_SECS: u64 = 10;

/// How long between check-ins with the user.
pub const CHECK_IN_EVERY_SECS: u64 = 120;

/// How long the wait runs before it reports [`MintOutcome::StillPending`] and hands control back.
///
/// Ten minutes is roughly a dozen blocks — far past the point where a healthy spend confirms, and
/// short enough that nobody is left watching a window all afternoon. It is a bound on the WATCH, never
/// on the spend: a mint that confirms at minute eleven is still a real DID, and the wizard says so.
pub const GIVE_UP_AFTER_SECS: u64 = 600;

/// Where a mint ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintOutcome {
    /// The chain confirmed it. Carries the evidence, which is the only thing that may be written to the
    /// [`DidLedger`](crate::account::did::DidLedger).
    Confirmed {
        /// The DID that now exists.
        did: String,
        /// How we know.
        evidence: MintEvidence,
    },
    /// The chain rejected the spend. It will not confirm.
    Rejected {
        /// Why, in the user's words.
        reason: String,
    },
    /// The watch ended without an answer — the user stopped watching, or the watch ran out of time.
    /// The spend may still confirm; nothing here says it failed.
    StillPending {
        /// The spend to look up later.
        spend_id: String,
        /// How long the wait ran, so the user can be told.
        waited_secs: u64,
    },
    /// The chain could not be reached for long enough that watching is pointless. Like
    /// [`MintOutcome::StillPending`], this says nothing about the spend itself.
    ConnectionLost {
        /// The spend to look up once the connection is back.
        spend_id: String,
    },
}

/// Watch `spend_id` until the chain answers, the user stops watching, or the watch runs out of time.
///
/// # What each ending means, and why none of them is a guess
///
/// * A [`Sighting::Confirmed`] — and nothing else — produces [`MintOutcome::Confirmed`], carrying the
///   evidence that sighting reported. There is no path from a submission to a success.
/// * A [`Sighting::Rejected`] ends the wait immediately: waiting longer cannot change a rejection, and
///   a person watching a spinner for a spend the chain already refused is being lied to.
/// * Repeated [`Sighting::Unreachable`] ends it as [`MintOutcome::ConnectionLost`], which is reported
///   as "we stopped being able to look", never as "it failed".
/// * Running past [`GIVE_UP_AFTER_SECS`], or a [`KeepWaiting::No`], ends it as
///   [`MintOutcome::StillPending`] with the spend id — a way forward, not a dead end.
pub fn await_confirmation(
    did: &str,
    spend_id: &str,
    observer: &dyn MintObserver,
    surface: &dyn WaitSurface,
    clock: &dyn Clock,
) -> MintOutcome {
    let started = clock.now_unix();
    let mut unreachable_looks = 0;
    let mut next_check_in = CHECK_IN_EVERY_SECS;

    loop {
        match observer.look(spend_id) {
            Sighting::Confirmed(evidence) => {
                return MintOutcome::Confirmed {
                    did: did.to_owned(),
                    evidence,
                }
            }
            Sighting::Rejected { reason } => return MintOutcome::Rejected { reason },
            Sighting::Unreachable => unreachable_looks += 1,
            // A healthy look clears the counter: an intermittent connection that keeps recovering is a
            // slow wait, not a lost one.
            Sighting::Pending => unreachable_looks = 0,
        }

        let elapsed = clock.now_unix().saturating_sub(started);
        let progress = WaitProgress {
            elapsed_secs: elapsed,
            give_up_after_secs: GIVE_UP_AFTER_SECS,
            unreachable_looks,
        };

        if unreachable_looks >= UNREACHABLE_LOOKS_BEFORE_GIVING_UP {
            return MintOutcome::ConnectionLost {
                spend_id: spend_id.to_owned(),
            };
        }
        if elapsed >= GIVE_UP_AFTER_SECS {
            return still_pending(spend_id, elapsed);
        }
        if elapsed >= next_check_in {
            next_check_in = elapsed + CHECK_IN_EVERY_SECS;
            if surface.checking_in(&progress) == KeepWaiting::No {
                return still_pending(spend_id, elapsed);
            }
        }

        surface.wait_a_moment();
    }
}

/// How many consecutive unreachable looks end the watch.
///
/// Comfortably more than [`UNREACHABLE_LOOKS_BEFORE_SAYING_SO`], so the user is TOLD the connection is
/// the problem while the watch is still trying, rather than the two happening at once.
const UNREACHABLE_LOOKS_BEFORE_GIVING_UP: u32 = 12;

/// The "no answer yet" ending, built in one place so the two ways of reaching it cannot drift.
fn still_pending(spend_id: &str, waited_secs: u64) -> MintOutcome {
    MintOutcome::StillPending {
        spend_id: spend_id.to_owned(),
        waited_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const DID: &str = "did:chia:1mintwaitfixture0000000000000000000000000000000000000000000";
    const SPEND: &str = "0xmintwaitfixturespendid";

    /// A clock a test advances deliberately.
    ///
    /// Pinned rather than wall-clock: a wait tested through `SystemTime::now` would report an elapsed
    /// time of zero on every iteration and could never reach its own timeout, so the timeout branches
    /// would be asserted about without ever being run.
    struct PinnedClock {
        now: Mutex<u64>,
    }

    impl PinnedClock {
        /// Start at a plausible present rather than zero, so nothing accidentally passes because the
        /// numbers are small.
        fn new() -> Self {
            Self {
                now: Mutex::new(1_770_000_000),
            }
        }
    }

    impl Clock for PinnedClock {
        fn now_unix(&self) -> u64 {
            *self.now.lock().unwrap()
        }
    }

    /// A surface that advances the pinned clock by one poll interval each time the loop waits, and
    /// answers check-ins from a script.
    struct ScriptedWait<'a> {
        clock: &'a PinnedClock,
        answers: Mutex<Vec<KeepWaiting>>,
        check_ins: Mutex<Vec<WaitProgress>>,
    }

    impl<'a> ScriptedWait<'a> {
        fn patient(clock: &'a PinnedClock) -> Self {
            Self {
                clock,
                answers: Mutex::new(Vec::new()),
                check_ins: Mutex::new(Vec::new()),
            }
        }

        fn giving_up_at_the_first_check_in(clock: &'a PinnedClock) -> Self {
            Self {
                clock,
                answers: Mutex::new(vec![KeepWaiting::No]),
                check_ins: Mutex::new(Vec::new()),
            }
        }

        fn check_ins(&self) -> Vec<WaitProgress> {
            self.check_ins.lock().unwrap().clone()
        }
    }

    impl WaitSurface for ScriptedWait<'_> {
        fn checking_in(&self, progress: &WaitProgress) -> KeepWaiting {
            self.check_ins.lock().unwrap().push(*progress);
            let mut answers = self.answers.lock().unwrap();
            match answers.is_empty() {
                true => KeepWaiting::Yes,
                false => answers.remove(0),
            }
        }

        fn wait_a_moment(&self) {
            *self.clock.now.lock().unwrap() += POLL_EVERY_SECS;
        }
    }

    /// An observer that reads a script of sightings, repeating the last one for ever.
    struct ScriptedChain {
        sightings: Mutex<Vec<Sighting>>,
        looks: Mutex<u32>,
    }

    impl ScriptedChain {
        fn seeing(sightings: Vec<Sighting>) -> Self {
            Self {
                sightings: Mutex::new(sightings),
                looks: Mutex::new(0),
            }
        }

        fn looks(&self) -> u32 {
            *self.looks.lock().unwrap()
        }
    }

    impl MintObserver for ScriptedChain {
        fn look(&self, _spend_id: &str) -> Sighting {
            *self.looks.lock().unwrap() += 1;
            let mut sightings = self.sightings.lock().unwrap();
            match sightings.len() {
                0 => Sighting::Pending,
                1 => sightings[0].clone(),
                _ => sightings.remove(0),
            }
        }
    }

    fn evidence() -> MintEvidence {
        MintEvidence::confirmed(SPEND, 5_412_009)
    }

    /// **A confirmation, and only a confirmation, produces a success — and it carries the evidence.**
    ///
    /// The fixture makes the chain report `Pending` twice first, so the assertion cannot be satisfied
    /// by an implementation that returns success before looking at all.
    #[test]
    fn only_a_confirmed_sighting_produces_a_confirmed_outcome() {
        let clock = PinnedClock::new();
        let surface = ScriptedWait::patient(&clock);
        let chain = ScriptedChain::seeing(vec![
            Sighting::Pending,
            Sighting::Pending,
            Sighting::Confirmed(evidence()),
        ]);

        let outcome = await_confirmation(DID, SPEND, &chain, &surface, &clock);

        assert_eq!(
            outcome,
            MintOutcome::Confirmed {
                did: DID.to_owned(),
                evidence: evidence(),
            }
        );
        assert_eq!(chain.looks(), 3, "the chain must actually have been polled");
    }

    /// A chain that never confirms and a user who never stops ends in a bounded, honest
    /// [`MintOutcome::StillPending`] — not an endless loop and not a failure.
    ///
    /// The reported wait is asserted at the bound from BOTH sides: it must be at least the give-up
    /// threshold (a loop that gave up early would report less) and within one poll of it (a loop that
    /// overshot would report more).
    #[test]
    fn a_wait_that_never_confirms_gives_up_at_its_bound_and_says_so() {
        let clock = PinnedClock::new();
        let surface = ScriptedWait::patient(&clock);
        let chain = ScriptedChain::seeing(vec![Sighting::Pending]);

        let outcome = await_confirmation(DID, SPEND, &chain, &surface, &clock);

        let MintOutcome::StillPending {
            spend_id,
            waited_secs,
        } = outcome
        else {
            panic!("a wait that never confirms must end as still-pending: {outcome:?}");
        };
        assert_eq!(spend_id, SPEND, "the user needs the spend to look up later");
        assert!(
            (GIVE_UP_AFTER_SECS..GIVE_UP_AFTER_SECS + POLL_EVERY_SECS).contains(&waited_secs),
            "the watch must run to its bound and no further: {waited_secs}"
        );
    }

    /// The user is checked in with while the wait runs, and the check-in carries the REAL elapsed time.
    ///
    /// The elapsed figure is the assertion, not the number of check-ins: a surface told "still waiting"
    /// with no duration is the spinner this module exists to replace.
    #[test]
    fn the_user_is_told_how_long_the_wait_has_been_going() {
        let clock = PinnedClock::new();
        let surface = ScriptedWait::patient(&clock);
        let chain = ScriptedChain::seeing(vec![Sighting::Pending]);

        await_confirmation(DID, SPEND, &chain, &surface, &clock);

        let check_ins = surface.check_ins();
        assert!(
            check_ins.len() > 1,
            "a ten-minute wait must check in more than once: {check_ins:?}"
        );
        assert!(
            check_ins[0].elapsed_secs >= CHECK_IN_EVERY_SECS,
            "the first check-in must report the real elapsed time: {:?}",
            check_ins[0]
        );
        assert!(
            check_ins
                .windows(2)
                .all(|pair| pair[1].elapsed_secs > pair[0].elapsed_secs),
            "each check-in must report a longer wait than the last: {check_ins:?}"
        );
    }

    /// Stopping the watch is a way out that does not lie: the spend is still on the chain, so the
    /// outcome is still-pending with its id — never a failure and never a success.
    #[test]
    fn a_user_who_stops_watching_is_not_told_the_mint_failed() {
        let clock = PinnedClock::new();
        let surface = ScriptedWait::giving_up_at_the_first_check_in(&clock);
        let chain = ScriptedChain::seeing(vec![Sighting::Pending]);

        let outcome = await_confirmation(DID, SPEND, &chain, &surface, &clock);

        let MintOutcome::StillPending { waited_secs, .. } = outcome else {
            panic!("stopping the watch must not be reported as a failure: {outcome:?}");
        };
        assert!(
            waited_secs < GIVE_UP_AFTER_SECS,
            "stopping early must be recorded as stopping early: {waited_secs}"
        );
    }

    /// A rejection ends the wait at once. Asserted through the poll COUNT, because an implementation
    /// that kept polling until its timeout and reported the rejection at the end would return the same
    /// outcome while leaving a person watching a spend the chain had already refused.
    #[test]
    fn a_rejected_spend_stops_the_wait_immediately() {
        let clock = PinnedClock::new();
        let surface = ScriptedWait::patient(&clock);
        let chain = ScriptedChain::seeing(vec![
            Sighting::Pending,
            Sighting::Rejected {
                reason: "the coin was already spent".to_owned(),
            },
        ]);

        let outcome = await_confirmation(DID, SPEND, &chain, &surface, &clock);

        assert_eq!(
            outcome,
            MintOutcome::Rejected {
                reason: "the coin was already spent".to_owned()
            }
        );
        assert_eq!(chain.looks(), 2, "a rejection must not be waited out");
    }

    /// **A lost connection is reported as a lost connection, never as a rejection.**
    ///
    /// The distinction is the whole point: the spend is probably fine and the WATCHER is what broke, so
    /// the user must not be told their mint failed.
    #[test]
    fn a_chain_that_cannot_be_reached_is_not_reported_as_a_rejection() {
        let clock = PinnedClock::new();
        let surface = ScriptedWait::patient(&clock);
        let chain = ScriptedChain::seeing(vec![Sighting::Unreachable]);

        let outcome = await_confirmation(DID, SPEND, &chain, &surface, &clock);

        assert_eq!(
            outcome,
            MintOutcome::ConnectionLost {
                spend_id: SPEND.to_owned()
            }
        );
    }

    /// A connection that drops and recovers is a slow wait, not a lost one.
    ///
    /// The fixture varies ONE actor — the chain's reachability — and keeps an honest recovery in the
    /// script, so an implementation that never cleared its failure counter would end in
    /// `ConnectionLost` here and fail. An all-unreachable fixture could not see that bug at all.
    #[test]
    fn an_intermittent_connection_does_not_end_the_wait() {
        let clock = PinnedClock::new();
        let surface = ScriptedWait::patient(&clock);
        let mut script = Vec::new();
        // More drops in total than the give-up threshold, but never that many CONSECUTIVELY.
        for _ in 0..UNREACHABLE_LOOKS_BEFORE_GIVING_UP + 2 {
            script.push(Sighting::Unreachable);
            script.push(Sighting::Pending);
        }
        script.push(Sighting::Confirmed(evidence()));
        let chain = ScriptedChain::seeing(script);

        let outcome = await_confirmation(DID, SPEND, &chain, &surface, &clock);

        assert!(
            matches!(outcome, MintOutcome::Confirmed { .. }),
            "an intermittent connection must not end the wait: {outcome:?}"
        );
    }

    /// The user is TOLD the connection is the problem while the watch is still trying — the two
    /// thresholds are ordered, not simultaneous.
    #[test]
    fn the_connection_is_reported_as_lost_before_the_watch_gives_up() {
        // A compile-time assertion, so an edit that reordered the two thresholds fails the BUILD
        // rather than one test — the ordering is what makes the "connection lost" message arrive
        // while the watch is still trying.
        const _: () =
            assert!(UNREACHABLE_LOOKS_BEFORE_SAYING_SO < UNREACHABLE_LOOKS_BEFORE_GIVING_UP);
        let healthy = WaitProgress {
            elapsed_secs: 60,
            give_up_after_secs: GIVE_UP_AFTER_SECS,
            unreachable_looks: 0,
        };
        assert!(!healthy.connection_lost());
        assert!(WaitProgress {
            unreachable_looks: UNREACHABLE_LOOKS_BEFORE_SAYING_SO,
            ..healthy
        }
        .connection_lost());
    }

    /// The stubbed production minter refuses honestly rather than fabricating a spend to wait on.
    #[test]
    fn the_stub_minter_reports_that_minting_is_unavailable() {
        assert_eq!(UnavailableMinter.submit(), Submission::NotAvailable);
    }
}
