//! Where the arrival ledger lives between runs.
//!
//! The dedup that stops a restart re-announcing yesterday's payments is only as durable as the file
//! it is written to, so this module is deliberately small and deliberately fail-closed: every way of
//! failing to read the ledger produces an EMPTY ledger, which the next observation ADOPTS silently.
//! The cost of that is one missed toast; the cost of the opposite — treating an unreadable file as
//! "nothing has been announced yet, and here is a baseline" — is announcing a wallet's whole history
//! the first time the file is corrupted.

use std::path::{Path, PathBuf};

use super::ArrivalLedger;

/// The ledger file name under the brand data directory, beside `agent.json`.
const LEDGER_FILE: &str = "arrivals.json";

/// The ledger path under a resolved brand data directory.
pub fn path_in(brand_dir: &Path) -> PathBuf {
    brand_dir.join(LEDGER_FILE)
}

/// Read the ledger at `path`.
///
/// A missing file is the ordinary first-run case. A file that cannot be read or parsed is treated
/// the same way, with a warning: see the module docs for why an unreadable ledger must not become an
/// announcing one.
pub fn load(path: &Path) -> ArrivalLedger {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ArrivalLedger::empty(),
        Err(e) => {
            tracing::warn!(error = %e, "the arrival ledger could not be read; starting a fresh one");
            return ArrivalLedger::empty();
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(ledger) => ledger,
        Err(e) => {
            tracing::warn!(error = %e, "the arrival ledger is not valid JSON; starting a fresh one");
            ArrivalLedger::empty()
        }
    }
}

/// Write `ledger` to `path`, creating the parent directory if needed.
///
/// Written through a temporary file and renamed into place: a process killed mid-write would
/// otherwise leave a truncated ledger, which loads as empty and re-adopts — losing the record of
/// what has already been announced. A rename is the cheapest thing that makes the file always whole.
pub fn save(path: &Path, ledger: &ArrivalLedger) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec(ledger).map_err(std::io::Error::other)?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, json)?;
    std::fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrivals::{ChainView, ConfirmedCoin};
    use crate::wallet::state::Asset;

    fn coin(id: &str, parent: &str, height: u32) -> ConfirmedCoin {
        ConfirmedCoin {
            coin_id: id.to_string(),
            parent_coin_id: parent.to_string(),
            asset: Asset::Xch,
            amount: 1,
            confirmed_height: height,
        }
    }

    fn view(peak: u32, coins: Vec<ConfirmedCoin>) -> ChainView {
        ChainView::of_read(true, Some(peak), coins).expect("synced with a peak")
    }

    /// **A missing ledger is a first run, not an error.**
    #[test]
    fn a_missing_ledger_is_an_empty_one() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = load(&path_in(dir.path()));
        assert_eq!(ledger, ArrivalLedger::empty());
        assert_eq!(ledger.baseline_height(), None);
    }

    /// **The record of what has been announced survives the process that announced it.**
    ///
    /// The end-to-end shape of trap 2: a run adopts and announces, the file is written, and a fresh
    /// load re-presented with the SAME coin announces nothing.
    #[test]
    fn what_was_announced_is_still_known_after_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(&dir.path().join("DigNetwork"));

        let mut first = ArrivalLedger::empty();
        first.observe(&view(100, vec![coin("old", "stranger", 50)]));
        let announced = first.observe(&view(200, vec![coin("paid", "stranger", 150)]));
        assert_eq!(announced.len(), 1, "the fixture must announce something");
        save(&path, &first).expect("saved");

        let mut second = load(&path);
        let again = second.observe(&view(210, vec![coin("paid", "stranger", 150)]));
        assert!(
            again.is_empty(),
            "the reloaded ledger re-announced a payment it had already announced"
        );
    }

    /// **A corrupt ledger starts fresh and therefore SILENT, never announcing a whole history.**
    #[test]
    fn a_corrupt_ledger_adopts_silently_rather_than_announcing_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(dir.path());
        std::fs::write(&path, b"{ not json").unwrap();

        let mut ledger = load(&path);
        assert_eq!(ledger.baseline_height(), None);
        let announced = ledger.observe(&view(
            500,
            vec![coin("a", "s", 10), coin("b", "s", 20), coin("c", "s", 30)],
        ));
        assert!(
            announced.is_empty(),
            "a corrupt ledger announced {} historical coins",
            announced.len()
        );
    }

    /// **A save leaves no half-written file behind for the next load to read.**
    #[test]
    fn saving_leaves_only_the_finished_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(dir.path());
        let mut ledger = ArrivalLedger::empty();
        ledger.observe(&view(10, vec![coin("a", "s", 1)]));
        save(&path, &ledger).expect("saved");

        assert!(path.exists());
        assert!(
            !path.with_extension("json.tmp").exists(),
            "the temporary file was left behind"
        );
        assert_eq!(load(&path), ledger);
    }
}
