//! The channel a card's submit handler hands a create job to, and the worker that runs it.
//!
//! # Why a second worker, sharing the tray's own exclusion flag
//!
//! Signing and pushing a reward-distributor CREATE is a custody-adjacent spend exactly like the
//! tray's own menu actions (see `dig-app`'s `tray_worker` module doc for the class of freeze this
//! avoids, and dig_ecosystem#1926 for the one that shipped). It must never run inline on a paint
//! thread, and it must never overlap a tray action that is *also* moving this account's funds --
//! a create racing a destroy, or two creates racing each other, is exactly the double-flow the
//! tray's single worker exists to make unreachable. Rather than invent a second exclusion
//! mechanism, this worker RESERVES THE SAME `Arc<AtomicBool>` the tray's `ActionWorker` reserves
//! (`dig-app`'s `tray_worker::ActionWorker::shared_busy`), so the two contend for one flag exactly
//! as a tray click and a window row already do through `Submitter`.
//!
//! # Refuse, never queue
//!
//! [`RewardCreateSink::submit`] never blocks and never queues: if the shared flag is already held,
//! the job -- including its non-`Clone` `Launchable` -- is DROPPED and [`Refused::Busy`] is
//! returned. A queued second submission would run after the first with no card on screen watching
//! it, which is the shape of defect this crate withdrew a whole PR over (see [`super::mint`]'s
//! module doc).
//!
//! # I/O-free by construction
//!
//! This module knows nothing about a chain, a residency or a publisher -- `run_job` is supplied by
//! the caller (`dig-app.rs`'s bin, which owns the live session and node endpoint) and performs the
//! actual mint. That keeps the same split [`super::create_card`]'s own module doc describes: paint
//! stays I/O-free, and so does the plumbing that carries a job to the thread that isn't.
//!
//! # No card paint here (dig_ecosystem#3253)
//!
//! Nothing in this module is reachable from a click yet -- [`install`]/[`get`] exist so a later
//! lane's submit-button handler has somewhere to reach the sink from; wiring a control that calls
//! [`RewardCreateSink::submit`] is that lane's job, not this one's.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, OnceLock};
use std::thread;

use super::create::Launchable;
use super::mint::DistributorMintTerms;

/// One create submission: the typed, ladder-witnessed pair plus which store it is for.
///
/// `store_id` travels with the job rather than being closed over by the caller, because the
/// worker (not the card) is what records the outcome against a store id -- see
/// [`super::create_card::record_submission`] and
/// [`super::create_card::record_submit_error`].
pub struct RewardCreateJob {
    /// Which store's pending-mint slot the outcome is recorded against.
    pub store_id: String,
    /// The ladder's terminal value -- consumed by [`super::mint::DistributorMintDoor::begin`]
    /// and nowhere else in production; see [`super::create_card::submit`].
    pub launchable: Launchable,
    /// The money and timing terms the ladder does not carry.
    pub terms: DistributorMintTerms,
}

/// Why a submitted job did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The shared exclusion flag was already held -- by a tray action, a window row, or another
    /// create submission. The job was dropped, never queued; see this module's doc comment.
    Busy,
}

/// Submits create jobs to a dedicated worker thread that shares its exclusion flag with the
/// tray's own `ActionWorker` (`dig-app`'s `tray_worker` module -- this crate does not depend on
/// `dig-app`, so that is a name, not a link) -- see this module's doc comment for why.
pub struct RewardCreateSink {
    submit: SyncSender<RewardCreateJob>,
    busy: Arc<AtomicBool>,
}

impl RewardCreateSink {
    /// Starts the worker thread and returns a sink that submits to it.
    ///
    /// `shared_busy` must be the SAME `Arc` the tray's `ActionWorker` reserves -- a clone of the
    /// `Arc`, never a fresh `AtomicBool`, or the two workers would no longer contend for anything.
    ///
    /// `run_job` performs the actual mint; it is supplied by the caller because this crate keeps
    /// I/O out of `rewards::create_sink` and `rewards::create_card` alike (see both modules' doc
    /// comments). A panicking `run_job` costs the app one refused submission, never a dead worker
    /// -- mirrors `tray_worker::ActionWorker::spawn`'s own `catch_unwind`.
    pub fn spawn<H>(shared_busy: Arc<AtomicBool>, mut run_job: H) -> Self
    where
        H: FnMut(RewardCreateJob) + Send + 'static,
    {
        let (submit, jobs) = sync_channel::<RewardCreateJob>(1);
        let worker_busy = Arc::clone(&shared_busy);
        thread::Builder::new()
            .name("dig-reward-create".to_string())
            .spawn(move || {
                for job in jobs {
                    if catch_unwind(AssertUnwindSafe(|| run_job(job))).is_err() {
                        tracing::error!(
                            "a reward-distributor create job panicked; the app stays live and the submission is lost"
                        );
                    }
                    worker_busy.store(false, Ordering::SeqCst);
                }
            })
            .expect("the reward-create worker thread could not be started");

        Self {
            submit,
            busy: shared_busy,
        }
    }

    /// Hand `job` to the worker. Never blocks, never queues: [`Refused::Busy`] means the shared
    /// flag was already held and `job` -- including its `Launchable` -- was dropped.
    pub fn submit(&self, job: RewardCreateJob) -> Result<(), Refused> {
        if self
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(Refused::Busy);
        }
        if self.submit.try_send(job).is_err() {
            // The worker is gone. Release the reservation so the shared flag stays honest for the
            // tray side too, and report the job as not taken.
            self.busy.store(false, Ordering::SeqCst);
            return Err(Refused::Busy);
        }
        Ok(())
    }
}

/// The process-wide reward-create sink, installed once at app startup.
///
/// A `OnceLock` for the same reason `super::create_card`'s own process-global slot is one: the sink is
/// built once, beside the tray's own worker, and every later reader (today: only this module's
/// own tests; eventually the submit button a later lane paints) reaches the SAME worker thread and
/// the SAME shared flag rather than a copy of either.
fn sink_slot() -> &'static OnceLock<RewardCreateSink> {
    static SINK: OnceLock<RewardCreateSink> = OnceLock::new();
    &SINK
}

/// Installs the process's one [`RewardCreateSink`]. Called once, from `dig-app.rs`'s startup,
/// beside where the tray's `ActionWorker` is spawned. A second call is a build error, not a
/// runtime one: `dig-app.rs` has exactly one startup path, so two installs would mean a second
/// worker thread nothing ever reaches.
pub fn install(sink: RewardCreateSink) {
    if sink_slot().set(sink).is_err() {
        tracing::error!("the reward-create sink was installed twice; the second sink is unused");
    }
}

/// The installed sink, or `None` before [`install`] has run (headless builds, and any test that
/// never calls it).
pub fn get() -> Option<&'static RewardCreateSink> {
    sink_slot().get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewards::create_card;
    use crate::rewards::mint::tests::{
        fixture_launchable, fixture_minter, fixture_terms, AcceptingPublisher,
    };
    use crate::rewards::mint::DistributorMint;
    use chia_wallet_sdk::prelude::MAINNET_CONSTANTS;
    use dig_account::mint::MintNetwork;
    use std::sync::mpsc::channel;
    use std::time::{Duration, Instant};

    /// Wait for `condition`, up to a second -- long enough that a loaded CI machine is not flaky,
    /// short enough that a genuine failure is a failure rather than a hang. Mirrors
    /// `tray_worker::tests::eventually`.
    fn eventually(condition: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            thread::sleep(Duration::from_millis(5));
        }
        condition()
    }

    /// A job submitted while the shared flag is held is refused, and `run_job` -- which is where a
    /// real `.begin(` call would live -- never runs at all.
    #[test]
    fn a_job_is_refused_and_never_run_while_the_shared_flag_is_held() {
        let busy = Arc::new(AtomicBool::new(true));
        let (ran, runs) = channel::<()>();
        let sink = RewardCreateSink::spawn(Arc::clone(&busy), move |_job: RewardCreateJob| {
            ran.send(()).expect("test is listening");
        });

        let (_residency, minter) = fixture_minter();
        let now = 2_000_000_000;
        let (terms, _chain) = fixture_terms(&minter, now);
        let manager_key = minter.public_key().expect("a fresh residency is unlocked");

        let job = RewardCreateJob {
            store_id: "busy-store".to_string(),
            launchable: fixture_launchable(manager_key),
            terms,
        };

        assert_eq!(sink.submit(job), Err(Refused::Busy));
        assert!(
            runs.recv_timeout(Duration::from_millis(200)).is_err(),
            "the refused job ran anyway"
        );
    }

    /// A job submitted while the shared flag is free runs, and the fixture door's `begin` -- the
    /// same door production builds -- leaves `has_pending` true for the job's store id.
    #[test]
    fn a_job_runs_when_the_shared_flag_is_free_and_the_pending_mint_is_recorded() {
        let busy = Arc::new(AtomicBool::new(false));
        let (_residency, minter) = fixture_minter();
        let now = 2_000_000_000;
        let (terms, chain) = fixture_terms(&minter, now);
        let publisher = AcceptingPublisher::default();
        let manager_key = minter.public_key().expect("a fresh residency is unlocked");
        let store_id = "free-store-sink";

        let sink = RewardCreateSink::spawn(Arc::clone(&busy), move |job: RewardCreateJob| {
            let door = DistributorMint::new(
                &minter,
                MintNetwork::mainnet(),
                &MAINNET_CONSTANTS,
                &chain,
                &publisher,
            );
            match create_card::submit(door, job.launchable, job.terms) {
                Ok(pending) => create_card::record_submission(&job.store_id, pending),
                Err(message) => create_card::record_submit_error(&job.store_id, message),
            }
        });

        let job = RewardCreateJob {
            store_id: store_id.to_string(),
            launchable: fixture_launchable(manager_key),
            terms,
        };

        assert_eq!(sink.submit(job), Ok(()));
        assert!(
            eventually(|| create_card::has_pending(store_id)),
            "the job never ran, or never recorded the pending mint"
        );
        assert!(!busy.load(Ordering::SeqCst), "the flag was never released");
    }
}
