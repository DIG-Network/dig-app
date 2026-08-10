//! Where the send cursor lives between runs.
//!
//! Its OWN file beside the arrival cursor, not a second field inside it. The node keeps two
//! independent `AUTOINCREMENT` sequences, so the two positions are unrelated numbers; storing them
//! in one document would mean a corrupt or partially-written file taking BOTH ledgers back to unread
//! at once, and would make a future field added to one of them a parse risk for the other.
//!
//! Reading and writing are [`crate::arrivals::store`]'s, unchanged — same fail-closed-to-unread rule
//! and same write-temp-then-rename. The whole of this module is the file NAME, which is the only
//! thing that actually differs.

use std::path::{Path, PathBuf};

use crate::arrivals::store::{load as load_cursor, save as save_cursor};
use crate::arrivals::ArrivalCursor;

/// The send-cursor file name under the brand data directory, beside `arrival-cursor.json`.
const CURSOR_FILE: &str = "send-cursor.json";

/// The send-cursor path under a resolved brand data directory.
pub fn path_in(brand_dir: &Path) -> PathBuf {
    brand_dir.join(CURSOR_FILE)
}

/// Read the send cursor at `path`. Every failure yields an UNREAD cursor, which the next page
/// ADOPTS in silence — see [`crate::arrivals::store`] for why that direction is the only safe one.
pub fn load(path: &Path) -> ArrivalCursor {
    load_cursor(path)
}

/// Write the send cursor to `path`, atomically.
pub fn save(path: &Path, cursor: &ArrivalCursor) -> std::io::Result<()> {
    save_cursor(path, cursor)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The two cursors are separate files.** One document holding both would let a corrupt write
    /// re-adopt a ledger that was fine, and re-announcing is the failure this whole feature avoids.
    #[test]
    fn the_send_cursor_does_not_share_a_file_with_the_arrival_cursor() {
        let dir = std::path::Path::new("/tmp/brand");
        assert_ne!(path_in(dir), crate::arrivals::store::path_in(dir));
        assert!(path_in(dir).ends_with("send-cursor.json"));
    }

    /// **A saved position survives a reload**, which is the whole promise of the file.
    #[test]
    fn a_saved_send_position_round_trips() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = path_in(dir.path());
        assert_eq!(load(&path), ArrivalCursor::unread());

        let mut cursor = ArrivalCursor::unread();
        cursor.advance_rows::<crate::sends::SentPayment>(&[], 0, 41);
        save(&path, &cursor).expect("the cursor saves");

        assert_eq!(load(&path).position(), Some(41));
    }
}
