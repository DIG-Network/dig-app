//! The call site: read the beacon's record on a slow cadence, offer what is new to the gate.
//!
//! Modelled on [`crate::collateral::watch`], which is the first caller of the activity gate, and
//! sharing its two-throttle split:
//!
//! - [`WATCH_INTERVAL`] is how often the BEACON is asked. Asking means spawning a process, and the
//!   answer changes at most once a pass — which is daily.
//! - The activity gate ([`crate::notify::shared`]) owns how often a person is TOLD, and it is the
//!   only thing that decides when. **This module never consults a clock about a person.**
//!
//! # Why the reader is injected rather than built here
//!
//! Asking the beacon means spawning `dig-updater status --json`, and on Windows a GUI-subsystem
//! process must suppress the console window the child would otherwise paint. That suppression lives
//! in the binary shell, so the binary supplies the reader. It also means a test drives the whole
//! decide-record-offer path against its own bytes instead of needing a beacon installed.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::store;
use crate::notify::gate::HoldKey;
use crate::notify::Notification;

/// How long between reads of the beacon's status mirror.
///
/// Slow on purpose. The beacon installs at most once a pass, so a reading fifteen minutes old is not
/// meaningfully less true than one taken this instant — and the gate may hold the result for hours
/// anyway, so a faster cadence would spend process spawns to change nothing a person sees.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Watches what the beacon has installed and offers the resulting announcement to the gate.
pub struct UpdateWatch {
    state: Arc<Mutex<WatchState>>,
    refresh: Duration,
    /// Where the announced-version ledger is persisted.
    record: PathBuf,
    /// Reads `dig-updater status --json`, returning its stdout. `None` when the beacon could not be
    /// asked at all — not installed, would not start, or exited non-zero. See the module docs for
    /// why this is injected.
    read: fn() -> Option<Vec<u8>>,
    /// Offers a notification to the gate, returning whether it was taken. Injected so a test can see
    /// WHAT was offered rather than only that nothing crashed.
    offer: fn(HoldKey, Notification) -> bool,
}

#[derive(Default)]
struct WatchState {
    last_read: Option<Instant>,
    in_flight: bool,
}

impl UpdateWatch {
    /// A watch over the ledger at `record`, with its cadence and both seams stated.
    #[must_use]
    pub fn new(
        record: PathBuf,
        refresh: Duration,
        read: fn() -> Option<Vec<u8>>,
        offer: fn(HoldKey, Notification) -> bool,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(WatchState::default())),
            refresh,
            record,
            read,
            offer,
        }
    }

    /// The production watch: the real ledger path, the real cadence, the real gate.
    #[must_use]
    pub fn over(record: PathBuf, read: fn() -> Option<Vec<u8>>) -> Self {
        Self::new(record, WATCH_INTERVAL, read, crate::notify::shared::hold)
    }

    /// Ask the beacon — at most every [`WATCH_INTERVAL`] — what it has installed, and offer the
    /// announcement if anything moved. **Never blocks**: the read and the file I/O run on a worker.
    pub fn observe(&self) {
        {
            let mut state = self.lock();
            if state.in_flight {
                return;
            }
            if state
                .last_read
                .is_some_and(|last| last.elapsed() < self.refresh)
            {
                return;
            }
            state.in_flight = true;
        }

        let shared = Arc::clone(&self.state);
        let record = self.record.clone();
        let (read, offer) = (self.read, self.offer);
        std::thread::spawn(move || {
            sweep(&record, read, offer);
            let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
            state.last_read = Some(Instant::now());
            state.in_flight = false;
        });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WatchState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One pass: read the beacon, fold it into the ledger, persist, offer what is new.
///
/// Separated from the threading so the decision is testable as a pure-ish step — bytes and a path in,
/// at most one offer out.
///
/// **Neither a failed read nor a read naming no installed build is an OBSERVATION**, and both are
/// handled by the one guard below rather than by two, because they have the same consequence and a
/// second branch that cannot change the outcome is a branch no test can hold.
///
/// An unasked question has no answer, and a dry check reports components with no `installed` object
/// at all. Recording either as "nothing is installed" would adopt an empty ledger, and the next
/// successful read would then announce every component on the machine.
fn sweep(
    record: &std::path::Path,
    read: fn() -> Option<Vec<u8>>,
    offer: fn(HoldKey, Notification) -> bool,
) {
    let observed = read()
        .map(|json| super::read_components(&json))
        .unwrap_or_default();
    if observed.is_empty() {
        return;
    }

    let mut ledger = store::load(record);
    let outcome = ledger.announce(&observed);
    if outcome.changed {
        if let Err(e) = store::save(record, &ledger) {
            // The record could not be written, so the same install will be announced again next
            // time. Say so rather than swallowing it — a repeating toast with no explanation is how
            // this looks from the outside.
            tracing::warn!(error = %e, "the announced-update record could not be saved");
        }
    }
    if let Some(notification) = outcome.notification {
        offer(HoldKey::Installed, notification);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Every offer any test in this module makes, keyed by nothing — the gate is a singleton and this
    /// double stands in for it, so the assertions can read what was offered.
    static OFFERED: Mutex<Vec<(HoldKey, Notification)>> = Mutex::new(Vec::new());
    static READS: AtomicUsize = AtomicUsize::new(0);

    fn record_offer(key: HoldKey, notification: Notification) -> bool {
        OFFERED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((key, notification));
        true
    }

    fn taken() -> Vec<(HoldKey, Notification)> {
        std::mem::take(&mut *OFFERED.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// These cases share the two statics above, so they run one at a time.
    fn exclusively() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        taken();
        READS.store(0, Ordering::SeqCst);
        guard
    }

    fn mirror(version: &str, activation: &str) -> Vec<u8> {
        format!(
            r#"{{"paused":false,"components":[{{"component":"dig-node","action":"update",
               "result":"installed","detail":"","installed":{{"version":"{version}",
               "activation":"{activation}"}}}}]}}"#
        )
        .into_bytes()
    }

    fn read_0_154() -> Option<Vec<u8>> {
        READS.fetch_add(1, Ordering::SeqCst);
        Some(mirror("0.154.0", "active"))
    }
    fn read_0_155() -> Option<Vec<u8>> {
        READS.fetch_add(1, Ordering::SeqCst);
        Some(mirror("0.155.0", "pending_restart"))
    }
    fn read_nothing() -> Option<Vec<u8>> {
        READS.fetch_add(1, Ordering::SeqCst);
        None
    }

    /// **The whole path works: adopt in silence, then announce the change exactly once.**
    ///
    /// Drives the real ledger through the real file, so it also proves the sweep persists what it
    /// announced — the defect a purely in-memory test could not see, because a sweep that forgot to
    /// save would still be silent on its second call within one process.
    #[test]
    fn a_changed_version_is_announced_once_through_the_persisted_ledger() {
        let _exclusive = exclusively();
        let dir = tempfile::tempdir().unwrap();
        let record = store::path_in(dir.path());

        sweep(&record, read_0_154, record_offer);
        assert!(taken().is_empty(), "the first sight is adopted in silence");

        sweep(&record, read_0_155, record_offer);
        let offered = taken();
        assert_eq!(offered.len(), 1, "the update was announced");
        assert_eq!(offered[0].0, HoldKey::Installed);
        assert!(offered[0].1.body.contains("0.155.0"), "{:?}", offered[0].1);

        // A fresh sweep reading the SAME record from disk stays quiet.
        sweep(&record, read_0_155, record_offer);
        assert!(taken().is_empty(), "announced twice");
    }

    /// **A beacon that cannot be asked changes nothing — and specifically does not adopt.**
    ///
    /// The load-bearing half is the third sweep. If a failed read had been recorded as an
    /// observation, the ledger would have adopted `unread -> {}` and the real install that follows
    /// would be swallowed. So this asserts the install IS still announced afterwards, rather than
    /// merely that the failed read was quiet.
    #[test]
    fn a_beacon_that_cannot_be_asked_neither_announces_nor_adopts() {
        let _exclusive = exclusively();
        let dir = tempfile::tempdir().unwrap();
        let record = store::path_in(dir.path());

        sweep(&record, read_nothing, record_offer);
        assert!(taken().is_empty());
        assert!(
            !record.exists(),
            "an unasked question was written down as an answer"
        );

        sweep(&record, read_0_154, record_offer);
        assert!(taken().is_empty(), "that first real read adopts");
        sweep(&record, read_0_155, record_offer);
        assert_eq!(taken().len(), 1, "the later install still reaches the gate");
    }

    /// **The cadence is respected: a second `observe` inside the interval does not ask again.**
    ///
    /// The counter is the assertion, and the third call after a zero interval is the control — it
    /// proves the watch can ask more than once, so the throttle is what stopped the second one.
    #[test]
    fn the_beacon_is_not_asked_again_inside_the_interval() {
        let _exclusive = exclusively();
        let dir = tempfile::tempdir().unwrap();

        let watch = UpdateWatch::new(
            store::path_in(dir.path()),
            Duration::from_secs(3600),
            read_0_154,
            record_offer,
        );
        watch.observe();
        join(&watch);
        watch.observe();
        join(&watch);
        assert_eq!(
            READS.load(Ordering::SeqCst),
            1,
            "asked twice in one interval"
        );

        let eager = UpdateWatch::new(
            store::path_in(dir.path()),
            Duration::ZERO,
            read_0_154,
            record_offer,
        );
        eager.observe();
        join(&eager);
        eager.observe();
        join(&eager);
        assert_eq!(
            READS.load(Ordering::SeqCst),
            3,
            "with no throttle it asks every time, so the assertion above is about the interval"
        );
    }

    /// Wait for the watch's worker to finish. The work happens on a thread the watch owns and does
    /// not hand back, so the test waits on the observable state instead: `in_flight` clearing.
    fn join(watch: &UpdateWatch) {
        for _ in 0..1_000 {
            if !watch.lock().in_flight {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("the watch worker did not finish");
    }
}
