//! The **Apps** group — other DIG apps this install can open from the tray (dig_ecosystem#2101).
//!
//! # Why this is a registry, not a hard-coded "Chat" button
//!
//! The user asked for an Apps menu with Chat in it. Chat is the only entry today, but §5.4 already
//! names the siblings that follow it (dig-email, dig-video-chat), so the surface is built so a SECOND
//! app is a [`DigApp`] row appended to [`APPS`] — never new menu code, a new
//! [`TrayAction`](crate::tray_menu::TrayAction), or a new
//! launch path. The tray builder, the launch seam and the not-installed notice all read the same
//! registry fields.
//!
//! # Why the launch decision is a pure function
//!
//! Spawning a process and drawing a window cannot be exercised from a unit test, and "did clicking
//! Chat do the right thing" is exactly the rule worth pinning. So the decision — launch this binary,
//! or show that notice — is [`plan_launch`], which takes an [`AppLocator`] and returns a [`LaunchPlan`]
//! WITHOUT touching the process table or the screen. The shell does the two impure things the plan
//! names; the choice between them is tested here.
//!
//! # Discovery: a sibling of dig-app
//!
//! Every DIG component installs as a SIBLING of the running beacon in one bin dir (the canonical
//! install root — dig-app itself lands there as `dig-app`), so a dig-chat binary, once packaged and
//! shipped, is `dig-chat` (`.exe` on Windows) in that same directory. Presence is therefore a single
//! `is_file` check against that path ([`InstalledApps`]). dig-chat is not packaged or carried by the
//! installer yet, so on every machine today that check returns absent — the notice path is the only
//! one currently reachable, and it is written to be honest about that rather than to promise an install
//! step that does not exist.

use std::path::PathBuf;

/// A stable identifier for one app in the [`APPS`] registry.
///
/// Carried by [`crate::tray_menu::TrayAction::LaunchApp`] so the shell learns WHICH app a click meant
/// without the menu holding one action variant per app — adding an app never touches
/// [`TrayAction`](crate::tray_menu::TrayAction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppId {
    /// DIG Chat — end-to-end-encrypted messaging (its on-wire envelope is [`crate::digchat`]).
    Chat,
}

/// One row of the Apps registry: a DIG app the tray can offer to open.
///
/// A second app (dig-email, dig-video-chat — §5.4) is a new value in [`APPS`]; every field the menu
/// and the launcher need lives here, so nothing else changes.
#[derive(Debug, Clone, Copy)]
pub struct DigApp {
    /// The registry key, echoed by the menu action so a click resolves back to this row.
    pub id: AppId,
    /// The name shown in the menu — plain product language, no `dig-` prefix.
    pub display_name: &'static str,
    /// One line saying what the app IS, for a surface with room for more than a name.
    ///
    /// The window's Apps tab draws a card per entry and a card needs a sentence; the tray, which has
    /// room for a name and nothing else, ignores this. It is registry DATA for the same reason
    /// [`display_name`](Self::display_name) is — a second app is a row here, never new menu or pane
    /// code — and it describes the app rather than the click, so no surface can mistake it for a
    /// verb: what a click DOES is still decided once, by [`crate::tray_menu`].
    pub tagline: &'static str,
    /// The installed binary's file STEM (no extension). Because DIG components install as siblings in
    /// one bin dir, presence is this stem in dig-app's own directory (see the module docs).
    pub binary_stem: &'static str,
}

/// The apps offered under the tray's **Apps** group, in menu order. Chat is the only one today.
pub const APPS: [DigApp; 1] = [DigApp {
    id: AppId::Chat,
    display_name: "Chat",
    tagline: "Private messages between DIG accounts, end-to-end encrypted so only the person you \
              are writing to can read them.",
    binary_stem: "dig-chat",
}];

/// The registry entry for `id`.
///
/// Total by construction — every [`AppId`] variant has a row in [`APPS`], which the
/// `every_app_id_has_a_registry_row` test pins so a future variant cannot be added without one.
pub fn app(id: AppId) -> &'static DigApp {
    APPS.iter()
        .find(|entry| entry.id == id)
        .expect("every AppId has a row in APPS")
}

/// Finds an installed DIG app binary, so the launch decision can be tested without a filesystem.
pub trait AppLocator {
    /// The path to `binary_stem`'s executable if it is installed on this machine, else `None`.
    fn locate(&self, binary_stem: &str) -> Option<PathBuf>;
}

/// What the shell should do when the user clicks an Apps row — decided PURELY, so both outcomes are
/// tested without spawning a process or drawing a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchPlan {
    /// The app is installed at this path. Spawn it DETACHED and with NO arguments: the child outlives
    /// the click (never run on the single-threaded prompt thread, dig_ecosystem#78), and no
    /// identity/pairing material is ever placed on its argv — pairing is the app's own job (§5.4).
    Launch(PathBuf),
    /// The app is not installed. Show [`not_available_notice`] rather than doing nothing (§6.1 never a
    /// silent no-op). This is the only reachable outcome today (dig-chat is not yet packaged).
    NotInstalled(AppId),
}

/// Decide what clicking `app`'s row does, given a way to find installed binaries.
pub fn plan_launch(app: &DigApp, locator: &dyn AppLocator) -> LaunchPlan {
    match locator.locate(app.binary_stem) {
        Some(path) => LaunchPlan::Launch(path),
        None => LaunchPlan::NotInstalled(app.id),
    }
}

/// The production locator: DIG apps install as siblings of dig-app in one bin dir (the canonical
/// install root), so an app is present iff `<bin_dir>/<stem><exe suffix>` is a file.
pub struct InstalledApps {
    bin_dir: PathBuf,
}

impl InstalledApps {
    /// Look beside the running executable — dig-app's own install directory, where every sibling
    /// component lands. `None` when the running exe's path or parent cannot be determined, which the
    /// shell treats as "nothing installed" (the notice path), never as a launch.
    pub fn beside_this_exe() -> Option<Self> {
        let exe = std::env::current_exe().ok()?;
        exe.parent().map(|dir| Self {
            bin_dir: dir.to_path_buf(),
        })
    }

    /// A locator rooted at an explicit bin dir — used by tests to point discovery at a temp directory.
    pub fn in_dir(bin_dir: impl Into<PathBuf>) -> Self {
        Self {
            bin_dir: bin_dir.into(),
        }
    }

    /// The path an installed `stem` would occupy in this bin dir, with the platform executable suffix
    /// (`.exe` on Windows, empty elsewhere).
    fn candidate(&self, stem: &str) -> PathBuf {
        self.bin_dir
            .join(format!("{stem}{}", std::env::consts::EXE_SUFFIX))
    }
}

impl AppLocator for InstalledApps {
    fn locate(&self, binary_stem: &str) -> Option<PathBuf> {
        let path = self.candidate(binary_stem);
        path.is_file().then_some(path)
    }
}

/// A plain informational message for the shell to draw. Owned strings because the heading and body are
/// composed from the app's name; the title is a constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppNotice {
    /// The window title.
    pub title: &'static str,
    /// The one-line heading.
    pub heading: String,
    /// The full explanation.
    pub body: String,
}

/// The honest notice shown when an Apps entry is clicked but the app is not installed (§6.1: never a
/// silent no-op; §6.0: honest copy).
///
/// It deliberately does NOT invent an install step. dig-chat is not yet packaged or carried by the
/// installer, so there is nothing for the user to run — naming a "run installer X" step that cannot
/// work would be exactly the dead end the tray was rebuilt to remove (#1800). Instead it states the
/// truth: the app is coming, it will appear here on its own once it ships, and no action is needed.
pub fn not_available_notice(id: AppId) -> AppNotice {
    let name = app(id).display_name;
    AppNotice {
        title: "DIG — Apps",
        heading: format!("DIG {name} isn't available on this computer yet."),
        body: format!(
            "DIG {name} is coming to the DIG Network, but it is not part of this install yet, so \
             there is nothing to open right now. It will appear in this menu automatically once it \
             ships — you don't need to install or set up anything."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A locator that reports a fixed answer for one stem, so both branches of [`plan_launch`] are
    /// exercised without a real binary on disk. It varies ONE actor — the presence of the requested
    /// stem — and answers `None` for anything else, so a test that asked for the wrong stem fails
    /// rather than silently passing.
    struct FakeLocator {
        stem: &'static str,
        at: Option<PathBuf>,
    }

    impl AppLocator for FakeLocator {
        fn locate(&self, binary_stem: &str) -> Option<PathBuf> {
            if binary_stem == self.stem {
                self.at.clone()
            } else {
                None
            }
        }
    }

    #[test]
    fn every_app_id_has_a_registry_row() {
        // `app` panics if an id has no row; calling it for every registry id proves the lookup is total
        // and, with the exhaustive match below, that no variant can be added without a row.
        for entry in APPS {
            assert_eq!(app(entry.id).binary_stem, entry.binary_stem);
        }
        // An exhaustive match so a new AppId variant fails to compile until it is added to APPS.
        match AppId::Chat {
            AppId::Chat => {}
        }
    }

    /// **Every registry row carries a tagline that says something the name does not.**
    ///
    /// The window draws a card per app, and a card whose sentence is its own title back again is a
    /// placeholder wearing a description. Both halves are asserted over the WHOLE registry rather
    /// than over Chat, so the next app cannot be added with an empty or echoing one — which is the
    /// only moment this can go wrong, since the field is a constant.
    #[test]
    fn every_app_describes_itself_in_words_its_name_does_not_already_say() {
        for entry in APPS {
            let tagline = entry.tagline.trim();
            assert!(
                tagline.len() > entry.display_name.len(),
                "{}'s tagline ({tagline:?}) is no longer than its name, so the card would say the \
                 same thing twice",
                entry.display_name
            );
            assert!(
                tagline.ends_with('.'),
                "{}'s tagline is not a sentence: {tagline:?}",
                entry.display_name
            );
        }
    }

    #[test]
    fn chat_is_the_first_app_and_names_the_dig_chat_binary() {
        assert_eq!(APPS[0].id, AppId::Chat);
        assert_eq!(APPS[0].display_name, "Chat");
        // The launch path depends on this stem matching what the installer will ship dig-chat as — a
        // sibling `dig-chat` in the shared bin dir (canonical install root).
        assert_eq!(APPS[0].binary_stem, "dig-chat");
    }

    #[test]
    fn a_present_app_plans_to_launch_its_exact_path_without_spawning() {
        let installed = PathBuf::from("/opt/dig/bin/dig-chat");
        let locator = FakeLocator {
            stem: "dig-chat",
            at: Some(installed.clone()),
        };
        // `plan_launch` returns the launch target; no process is spawned by building the plan — the
        // whole point of the seam. The shell is the only thing that spawns, from this path.
        assert_eq!(
            plan_launch(app(AppId::Chat), &locator),
            LaunchPlan::Launch(installed)
        );
    }

    #[test]
    fn an_absent_app_plans_the_notice_path_not_a_silent_no_op() {
        // The reachable state today: nothing is installed, so the plan is the notice — never a launch,
        // never nothing.
        let locator = FakeLocator {
            stem: "dig-chat",
            at: None,
        };
        assert_eq!(
            plan_launch(app(AppId::Chat), &locator),
            LaunchPlan::NotInstalled(AppId::Chat)
        );
    }

    #[test]
    fn the_not_available_notice_is_honest_and_names_no_fake_install_step() {
        let notice = not_available_notice(AppId::Chat);
        assert!(notice.heading.contains("Chat"));
        // It must promise nothing the user cannot do. Guard against the copy drifting back into a
        // fabricated "run the installer" instruction that would be a dead end (#1800).
        let text = format!("{} {}", notice.heading, notice.body).to_lowercase();
        assert!(
            !text.contains("run the installer") && !text.contains("reinstall"),
            "the notice must not invent an install step dig-chat has no way to satisfy"
        );
        assert!(
            text.contains("once it ships") || text.contains("automatically"),
            "the notice must say it will appear on its own once dig-chat ships"
        );
    }

    #[test]
    fn installed_apps_finds_a_binary_that_exists_and_misses_one_that_does_not() {
        let dir = std::env::temp_dir().join(format!("dig-apps-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let stem = "dig-chat";
        let path = dir.join(format!("{stem}{}", std::env::consts::EXE_SUFFIX));

        let locator = InstalledApps::in_dir(&dir);
        assert_eq!(locator.locate(stem), None, "absent before the file exists");

        std::fs::write(&path, b"not a real binary").unwrap();
        assert_eq!(
            locator.locate(stem),
            Some(path),
            "present once the sibling binary exists in the bin dir"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
