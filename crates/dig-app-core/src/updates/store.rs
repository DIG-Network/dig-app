//! Where the record of what has already been announced lives between runs.
//!
//! Deliberately the same shape as [`crate::arrivals::store`], for the same reason and with the same
//! failure direction: **every way of failing to read the record produces an UNREAD one**, which the
//! next observation adopts in silence. The cost is one missed toast. The cost of the opposite —
//! reading an unreadable file as "nothing has ever been announced" — is announcing every installed
//! component on a machine where nothing was installed at all.
//!
//! This is also what makes dig-app's own update announceable. When the component installed is
//! dig-app, the process that would have noticed is the one being replaced; there is nothing alive to
//! observe the moment. It notices on the NEXT start instead, by comparing the beacon's record against
//! this file — which is why the comparison is against a persisted version rather than against
//! anything held in memory.

use std::path::{Path, PathBuf};

use super::AnnouncedVersions;

/// The record's file name under the brand data directory, beside `agent.json`.
const RECORD_FILE: &str = "announced-updates.json";

/// The record path under a resolved brand data directory.
#[must_use]
pub fn path_in(brand_dir: &Path) -> PathBuf {
    brand_dir.join(RECORD_FILE)
}

/// Read the record at `path`.
///
/// A missing file is the ordinary first-run case. A file that cannot be read or parsed is treated the
/// same way, with a warning: see the module docs for why an unreadable record must not become an
/// announcing one.
#[must_use]
pub fn load(path: &Path) -> AnnouncedVersions {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return AnnouncedVersions::unread(),
        Err(e) => {
            tracing::warn!(error = %e, "the announced-update record could not be read; starting unread");
            return AnnouncedVersions::unread();
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(record) => record,
        Err(e) => {
            tracing::warn!(error = %e, "the announced-update record is not valid JSON; starting unread");
            AnnouncedVersions::unread()
        }
    }
}

/// Write `record` to `path`, creating the parent directory if needed.
///
/// Written through a temporary file and renamed into place: a process killed mid-write would
/// otherwise leave a truncated file, which loads as unread and re-adopts — losing the record of what
/// has already been announced. A rename is the cheapest thing that makes the file always whole.
pub fn save(path: &Path, record: &AnnouncedVersions) -> std::io::Result<()> {
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
    use crate::updates::{Activation, InstalledComponent};

    fn component(name: &str, version: &str) -> InstalledComponent {
        InstalledComponent {
            name: name.to_string(),
            version: version.to_string(),
            activation: Activation::Active,
        }
    }

    /// **A record survives the round trip, so a restart does not re-announce yesterday's install.**
    ///
    /// The reload is driven through `announce` rather than compared as a struct: what has to survive
    /// is the DECISION, and a record that deserialized into a structurally-equal value while
    /// announcing again would pass an equality assertion.
    #[test]
    fn an_announced_version_stays_announced_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(dir.path());

        let mut record = AnnouncedVersions::unread();
        record.announce(&[component("dig-node", "0.154.0")]);
        record.announce(&[component("dig-node", "0.155.0")]);
        save(&path, &record).unwrap();

        let mut reloaded = load(&path);
        assert!(!reloaded.is_unread(), "the record was read back");
        let outcome = reloaded.announce(&[component("dig-node", "0.155.0")]);
        assert_eq!(
            outcome.notification, None,
            "the install was announced a second time after a restart"
        );
    }

    /// **A missing record is unread, and adopts rather than announcing.**
    ///
    /// This is first run on a machine with components already installed by the installer.
    #[test]
    fn a_missing_record_adopts_in_silence() {
        let dir = tempfile::tempdir().unwrap();
        let mut record = load(&path_in(dir.path()));
        assert!(record.is_unread());
        assert_eq!(
            record.announce(&[component("dig-node", "0.154.0")]).notification,
            None
        );
    }

    /// **A corrupt record adopts too — it does NOT announce every component on disk.**
    ///
    /// The fixture is a truncated JSON object, which is what a process killed mid-write leaves
    /// behind, and the whole reason `save` renames rather than writes in place.
    ///
    /// The control is the second half: the same bytes replaced with a VALID record announce
    /// normally, so this proves the corruption is what produced the silence rather than a loader
    /// that is silent about everything.
    #[test]
    fn a_corrupt_record_adopts_rather_than_announcing_everything() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(dir.path());
        std::fs::write(&path, br#"{"announced":{"dig-node":"0.15"#).unwrap();

        let mut corrupt = load(&path);
        assert!(corrupt.is_unread());
        assert_eq!(
            corrupt.announce(&[component("dig-node", "0.155.0")]).notification,
            None,
            "a corrupt record announced an install nothing observed"
        );

        let mut valid = AnnouncedVersions::unread();
        valid.announce(&[component("dig-node", "0.154.0")]);
        save(&path, &valid).unwrap();
        assert!(
            load(&path)
                .announce(&[component("dig-node", "0.155.0")])
                .notification
                .is_some(),
            "with an intact record the same observation IS news, so the assertion above is about \
             the corruption and not about a loader that never announces"
        );
    }

    /// **A record written before this feature existed loads as unread.**
    ///
    /// `{}` is the shape a forward-compatible reader must tolerate, and it must land on ADOPT — an
    /// empty map would mean "nothing has been announced", which announces everything.
    #[test]
    fn a_record_with_no_announced_field_is_unread() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(dir.path());
        std::fs::write(&path, b"{}").unwrap();
        assert!(load(&path).is_unread());
    }

    /// **Saving creates the directory and leaves no temporary file behind.**
    #[test]
    fn saving_creates_the_directory_and_leaves_nothing_temporary() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_in(&dir.path().join("nested"));
        save(&path, &AnnouncedVersions::unread()).unwrap();
        assert!(path.exists());
        assert!(!path.with_extension("json.tmp").exists());
    }
}
