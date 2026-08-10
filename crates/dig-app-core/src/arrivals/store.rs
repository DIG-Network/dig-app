//! Where the arrival cursor lives between runs.
//!
//! The whole promise of this module is that a restart does not re-announce yesterday's payments, and
//! that promise is only as durable as the file below. So it is deliberately small and deliberately
//! fail-closed: every way of failing to READ the cursor produces an UNREAD one, which the next page
//! ADOPTS in silence. The cost is one missed toast; the cost of the opposite — treating an
//! unreadable file as "nothing has been announced yet, start from the beginning" — is toasting the
//! node's whole ledger the first time the file is corrupted.

use std::path::{Path, PathBuf};

use super::ArrivalCursor;

/// The cursor file name under the brand data directory, beside `agent.json`.
///
/// Named for what it now holds. The file that lived here before dig-app started consuming
/// `control.wallet.arrivals` held a whole coin ledger under the name `arrivals.json`; loading one of
/// those as a cursor would fail to parse and be read as UNREAD, which adopts silently — the correct
/// outcome for an upgrade, and the reason no migration is needed.
const CURSOR_FILE: &str = "arrival-cursor.json";

/// The cursor path under a resolved brand data directory.
pub fn path_in(brand_dir: &Path) -> PathBuf {
    brand_dir.join(CURSOR_FILE)
}

/// Read the cursor at `path`.
///
/// A missing file is the ordinary first-run case. A file that cannot be read or parsed is treated
/// the same way, with a warning: see the module docs for why an unreadable cursor must not become an
/// announcing one.
pub fn load(path: &Path) -> ArrivalCursor {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ArrivalCursor::unread(),
        Err(e) => {
            tracing::warn!(error = %e, "the arrival cursor could not be read; starting unread");
            return ArrivalCursor::unread();
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(cursor) => cursor,
        Err(e) => {
            tracing::warn!(error = %e, "the arrival cursor is not valid JSON; starting unread");
            ArrivalCursor::unread()
        }
    }
}

/// Write `cursor` to `path`, creating the parent directory if needed.
///
/// Written through a temporary file and renamed into place: a process killed mid-write would
/// otherwise leave a truncated file, which loads as unread and re-adopts — losing the record of what
/// has already been announced. A rename is the cheapest thing that makes the file always whole.
pub fn save(path: &Path, cursor: &ArrivalCursor) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec(cursor).map_err(std::io::Error::other)?;
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
                confirmed_height: 5_412_000,
            })
            .collect();
        let cursor = arrivals.last().map_or(after_seq, |a| a.seq);
        ArrivalPage {
            arrivals,
            cursor,
            latest,
        }
    }

    /// **A missing cursor is a first run, not an error.**
    #[test]
    fn a_missing_cursor_is_an_unread_one() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(&path_in(dir.path())), ArrivalCursor::unread());
    }

    /// **The record of what has been announced survives the process that announced it.**
    #[test]
    fn what_was_announced_is_still_known_after_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(&dir.path().join("DigNetwork"));

        let mut first = ArrivalCursor::unread();
        first.advance(&page(&[], 0, 4));
        assert_eq!(
            first.advance(&page(&[5], 4, 5)).len(),
            1,
            "the fixture must announce something"
        );
        save(&path, &first).expect("saved");

        let mut second = load(&path);
        assert!(
            second.advance(&page(&[5], 4, 5)).is_empty(),
            "the reloaded cursor re-announced a payment it had already announced"
        );
    }

    /// **A corrupt cursor starts unread and therefore SILENT, never announcing a whole ledger.**
    ///
    /// This is also the upgrade path: the pre-#2548-fix file at the old name held a coin ledger, and
    /// any leftover unreadable content must adopt rather than replay.
    #[test]
    fn a_corrupt_cursor_adopts_silently_rather_than_announcing_the_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(dir.path());
        std::fs::write(&path, br#"{"baseline_height":100,"seen":{"a":1}}"#).unwrap();

        let mut cursor = load(&path);
        assert_eq!(cursor.position(), None);
        assert!(
            cursor.advance(&page(&[1, 2, 3], 0, 3)).is_empty(),
            "an unreadable cursor announced the node's whole ledger"
        );
    }

    /// **A save leaves no half-written file behind for the next load to read.**
    #[test]
    fn saving_leaves_only_the_finished_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(dir.path());
        let mut cursor = ArrivalCursor::unread();
        cursor.advance(&page(&[], 0, 7));
        save(&path, &cursor).expect("saved");

        assert!(path.exists());
        assert!(
            !path.with_extension("json.tmp").exists(),
            "the temporary file was left behind"
        );
        assert_eq!(load(&path), cursor);
    }
}
