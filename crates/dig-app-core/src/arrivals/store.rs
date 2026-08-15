//! Where the record of what has been announced lives between runs.
//!
//! The whole promise of this module is that a restart does not re-announce yesterday's payments, and
//! that promise is only as durable as the file below. So it is deliberately small and deliberately
//! fail-closed: every way of failing to READ the record produces an UNREAD one, which the next page
//! ADOPTS in silence. The cost is one missed toast; the cost of the opposite — treating an
//! unreadable file as "nothing has been announced yet, start from the beginning" — is toasting the
//! node's whole ledger the first time the file is corrupted.
//!
//! The cursor and the announced-coin record live in ONE file for the same reason. A cursor that
//! survived a lost coin record would page past arrivals the record could no longer recognise, so
//! they fail together or not at all.

use std::path::{Path, PathBuf};

use super::ArrivalAnnouncer;

/// The record's file name under the brand data directory, beside `agent.json`.
///
/// Named for what it now holds. Each earlier name held something this one is a superset of — a whole
/// coin ledger as `arrivals.json` before dig-app consumed `control.wallet.arrivals`, then a bare
/// cursor as `arrival-cursor.json` before #2959 — and every one of them loads as UNREAD here, which
/// adopts silently. That is the correct outcome for an upgrade, and the reason no migration is
/// needed at any of these steps.
const RECORD_FILE: &str = "arrival-record.json";

/// The record path under a resolved brand data directory.
pub fn path_in(brand_dir: &Path) -> PathBuf {
    brand_dir.join(RECORD_FILE)
}

/// Read the record at `path`.
///
/// A missing file is the ordinary first-run case. A file that cannot be read or parsed is treated
/// the same way, with a warning: see the module docs for why an unreadable record must not become an
/// announcing one.
pub fn load(path: &Path) -> ArrivalAnnouncer {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ArrivalAnnouncer::unread(),
        Err(e) => {
            tracing::warn!(error = %e, "the arrival record could not be read; starting unread");
            return ArrivalAnnouncer::unread();
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(record) => record,
        Err(e) => {
            tracing::warn!(error = %e, "the arrival record is not valid JSON; starting unread");
            ArrivalAnnouncer::unread()
        }
    }
}

/// Write `record` to `path`, creating the parent directory if needed.
///
/// Written through a temporary file and renamed into place: a process killed mid-write would
/// otherwise leave a truncated file, which loads as unread and re-adopts — losing the record of what
/// has already been announced. A rename is the cheapest thing that makes the file always whole.
pub fn save(path: &Path, record: &ArrivalAnnouncer) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, json)?;
    std::fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrivals::{Arrival, ArrivalPage};

    fn page(seqs: &[u64], after_seq: u64, latest: u64) -> ArrivalPage {
        let arrivals: Vec<Arrival> = seqs
            .iter()
            .map(|seq| Arrival {
                seq: *seq,
                coin_id: format!("{seq:064x}"),
                asset_id: None,
                amount: 1,
                confirmed_height: 5_412_000 + *seq as u32,
            })
            .collect();
        let cursor = arrivals.last().map_or(after_seq, |a| a.seq);
        ArrivalPage {
            arrivals,
            cursor,
            latest,
        }
    }

    /// **A missing record is a first run, not an error.**
    #[test]
    fn a_missing_record_is_an_unread_one() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(&path_in(dir.path())), ArrivalAnnouncer::unread());
    }

    /// One arrival naming its coin independently of its `seq`, which the helper above cannot do.
    ///
    /// The helper derives the coin id FROM the seq, so it cannot express the same coin returning at a
    /// different position — which is the only shape that can see the coin set through a file.
    fn arrival_of(seq: u64, coin: u64, height: u32) -> Arrival {
        Arrival {
            seq,
            coin_id: format!("{coin:064x}"),
            asset_id: None,
            amount: 1,
            confirmed_height: height,
        }
    }

    /// **The record of what has been announced survives the process that announced it — coin set
    /// included.**
    ///
    /// This is the only test that crosses [`save`]/[`load`], so it is the only place a coin set that
    /// silently failed to serialize can be caught, and its fixture has to be able to SEE the set. A
    /// coin replayed at or below the persisted cursor proves nothing: `ArrivalCursor`'s floor discards
    /// that row before `AnnouncedCoins::admit` is ever consulted, so the assertion is answered by the
    /// cursor alone and a `#[serde(skip)]` on the coin set would leave it green while every restart
    /// re-announced the ledger. The coin therefore returns ABOVE the cursor — the same correction the
    /// in-memory tests in [`super::super::announcer`] already carry.
    ///
    /// The second coin is the control: without it, "suppressed" is equally satisfied by a reloaded
    /// record that announces nothing at all.
    #[test]
    fn what_was_announced_is_still_known_after_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(&dir.path().join("DigNetwork"));

        let mut first = ArrivalAnnouncer::unread();
        first.advance(&page(&[], 0, 4));
        assert_eq!(
            first.advance(&page(&[5], 4, 5)).len(),
            1,
            "the fixture must announce something"
        );
        save(&path, &first).expect("saved");

        // The node's table is rebuilt and replays coin 5 at a far higher seq, with a genuinely new
        // coin behind it.
        let mut second = load(&path);
        let announced = second.advance(&ArrivalPage {
            arrivals: vec![
                arrival_of(300, 5, 5_412_005),
                arrival_of(301, 0xbbb, 5_412_600),
            ],
            cursor: 301,
            latest: 301,
        });
        assert_eq!(
            announced
                .iter()
                .map(|a| a.coin_id.clone())
                .collect::<Vec<_>>(),
            vec![arrival_of(0, 0xbbb, 0).coin_id],
            "the reloaded record re-announced a payment it had already announced, \
             or suppressed a genuinely new coin"
        );
    }

    /// **A record whose coin set is missing still suppresses, even with a readable cursor.**
    ///
    /// This is the asymmetry #2959 turns on, and the cursor cannot stand in for it: the position
    /// below is perfectly readable and sits at 5, so the cursor alone would hand rows 6..=8 straight
    /// to the toast. An absent coin set means ALREADY ANNOUNCED, not "nothing announced yet", so the
    /// page is adopted in silence. The tail is the control — an arrival above the adopted horizon
    /// must still be announced, or this test would pass against a record that never says anything.
    #[test]
    fn a_record_with_a_readable_cursor_and_no_coin_set_adopts_in_silence() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(dir.path());
        std::fs::write(&path, br#"{"cursor":{"position":5}}"#).unwrap();

        let mut record = load(&path);
        assert_eq!(record.position(), Some(5), "the fixture must have a cursor");
        assert!(
            record.advance(&page(&[6, 7, 8], 5, 8)).is_empty(),
            "a record with no coin set announced arrivals its cursor had not seen"
        );
        assert_eq!(
            record.advance(&page(&[9], 8, 9)).len(),
            1,
            "the adopted horizon suppressed everything after it, not just the adopted page"
        );
    }

    /// **A record that cannot be PARSED starts unread and therefore SILENT.**
    ///
    /// The fixture is truncated JSON, which is what a process killed mid-write leaves behind, and it
    /// is deliberately not merely *unexpected* JSON: every field of the record is
    /// `#[serde(default)]` and unknown keys are ignored, so a fixture like an older file's
    /// `{"baseline_height":100}` PARSES cleanly and never reaches the parse-failure branch this test
    /// exists to cover. Right outcome, wrong reason — and the branch left uncovered.
    #[test]
    fn an_unparseable_record_adopts_silently_rather_than_announcing_the_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(dir.path());
        std::fs::write(&path, br#"{"cursor":{"position":5},"announced":"#).unwrap();

        let mut record = load(&path);
        assert_eq!(
            record.position(),
            None,
            "the fixture must have failed to parse"
        );
        assert!(
            record.advance(&page(&[1, 2, 3], 0, 3)).is_empty(),
            "an unparseable record announced the node's whole ledger"
        );
    }

    /// **A record that PARSES but carries nothing is the same fail-closed state.**
    ///
    /// This is the real upgrade path and a distinct branch from the one above: the pre-#2548-fix file
    /// at the oldest name held a coin ledger and the pre-#2959 one held a bare cursor, and both parse
    /// here — every field defaults and unknown keys are ignored — leaving an ADOPT state rather than
    /// a parse failure. It must still adopt in silence rather than replay.
    #[test]
    fn a_record_that_parses_to_nothing_adopts_silently() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(dir.path());
        std::fs::write(&path, br#"{"baseline_height":100,"seen":{"a":1}}"#).unwrap();

        let mut record = load(&path);
        assert_eq!(
            record.position(),
            None,
            "the fixture must parse to an empty record"
        );
        assert!(
            record.advance(&page(&[1, 2, 3], 0, 3)).is_empty(),
            "a record carrying nothing announced the node's whole ledger"
        );
    }

    /// **A save leaves no half-written file behind for the next load to read.**
    #[test]
    fn saving_leaves_only_the_finished_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(dir.path());
        let mut record = ArrivalAnnouncer::unread();
        record.advance(&page(&[], 0, 7));
        save(&path, &record).expect("saved");

        assert!(path.exists());
        assert!(
            !path.with_extension("json.tmp").exists(),
            "the temporary file was left behind"
        );
        assert_eq!(load(&path), record);
    }
}
