//! The `dig-app` argv surface — `--version`, `--help`, and "just run" (dig_ecosystem#1749).
//!
//! # Why a tray app needs a command line at all
//!
//! `dig-app` is a desktop shell with no verbs, so for three releases it ignored argv entirely. That
//! turned out to break something invisible: the **update beacon health-gates every component by
//! spawning `<binary> --version`** and reading stdout
//! (`dig_release_resolver::detect_installed_version`). A binary that ignores `--version` does not
//! fail loudly — it *launches the whole app* and prints nothing to stdout, so the beacon reads an
//! empty string, cannot parse a version, and concludes the install is broken **forever**.
//!
//! So the contract this module upholds is narrow and externally imposed:
//!
//! 1. `--version` writes to **stdout** and exits **0** — the probe rejects a non-zero exit and never
//!    looks at stderr.
//! 2. The **last whitespace-separated token of the first line** must be a bare `MAJOR.MINOR.PATCH`.
//!    That is precisely what the beacon's parser accepts, and it is why [`version_line`] must never
//!    grow a trailing suffix like `(tray build)` — see the test that pins it.
//! 3. The version is read from the crate metadata, never written out as a literal, so a release bump
//!    cannot leave this reporting a stale number.
//!
//! # The second, later contract: the `dig-app:` activation URI
//!
//! The installer registers `dig-app` as an OS URL scheme, so a launch may carry a
//! `dig-app:<route>` argument naming a view to open (dig-app#296). Which routes exist — and, far
//! more importantly, which do NOT — is decided by
//! [`dig_app_core::activation`], not here: this module only lifts the
//! route out of argv. A URI that names no known route is left in `unrecognized`, so it is reported
//! on the one path that already reports arguments this shell did not understand, and the app opens
//! normally.
//!
//! Parsing lives here, in the library, so it is unit-tested; the binary only performs the effects.

use dig_app_core::Os;

/// What the process was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// Print the version and exit 0. The update beacon's health probe.
    Version,
    /// Print the usage text and exit 0.
    Help,
    /// Start the agent normally.
    ///
    /// `unrecognized` carries any argument this shell did not understand. It is deliberately NOT an
    /// error: a service manager or desktop launcher may pass flags of its own, and refusing to start
    /// the user's agent over an unknown token would trade a working app for a pedantic one. The
    /// binary warns about them and continues (§6.1 — never dead-end the user).
    Run {
        /// Arguments that were not understood, in the order they were given.
        ///
        /// A `dig-app:` URI naming no known route lands here too — it genuinely was not understood,
        /// and routing it to the same warning keeps one report rather than two.
        unrecognized: Vec<String>,
        /// The view this launch asks to open, if it named one this app allows.
        activation: Option<Activation>,
    },
}

/// Parse the process arguments (**excluding** `argv[0]`).
///
/// `--version`/`-V` and `--help`/`-h` win over anything else in the list, because a request for
/// information about the binary should be answerable even when the rest of the line is nonsense.
/// Version is checked first so `--help --version` reports a version rather than usage — the beacon's
/// probe is the caller that must never be surprised.
pub fn parse<S: AsRef<str>>(args: &[S]) -> Invocation {
    let args = args.iter().map(AsRef::as_ref);

    let mut unrecognized = Vec::new();
    let mut activation = None;
    let mut wants_help = false;
    for arg in args {
        match arg {
            "--version" | "-V" => return Invocation::Version,
            "--help" | "-h" => wants_help = true,
            // The first known route wins, so a launcher appending its own arguments cannot
            // displace the one the OS handed over.
            other
                if activation.is_none() && dig_app_core::activation::route_of(other).is_some() =>
            {
                activation = dig_app_core::activation::route_of(other);
            }
            other => unrecognized.push(other.to_string()),
        }
    }
    if wants_help {
        return Invocation::Help;
    }
    Invocation::Run {
        unrecognized,
        activation,
    }
}

/// The view a launch asks to open — [`dig_app_core::activation::Route`], re-exported so callers of
/// this module need only one import for everything argv can produce.
pub type Activation = dig_app_core::activation::Route;

/// This build's version, straight from the crate metadata (which the workspace sets from the single
/// `[workspace.package].version` the release pipeline bumps).
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The single line `--version` prints.
///
/// The shape is `"dig-app <semver>"` — the same `"<name> <version>"` clap emits for every other DIG
/// binary, so the beacon's one parser reads them all. **The bare semver must stay the final token**;
/// appending anything after it silently breaks the update health-gate.
pub fn version_line() -> String {
    format!("dig-app {}", version())
}

/// What this build does on a host with no desktop — a PURE function of the target OS and whether the
/// tray is compiled in, so every arm is reachable from a test on any platform.
///
/// # Why a function and not three `#[cfg]` constants
///
/// The `cfg` version compiled exactly one arm per build, so proving an arm required a CI job on that
/// platform with that feature — and two of the three arms had no such job. The headless arm had none
/// anywhere: `Headless build` runs clippy only, and `--all-features` never turns `tray` OFF. A test
/// that cannot run is not a guard, and this note has now been wrong twice.
///
/// # The three answers, and why they differ
///
/// - **Linux + tray.** The sentence this replaces — *"on a machine with no desktop it runs
///   headless"* — is FALSE here. The default Linux artifact hard-links the GTK stack and is killed
///   by the dynamic loader with exit 127 before `main()` runs (measured on Ubuntu Server 24.04,
///   dig-app#303). Headless is chosen at BUILD time by selecting the `-headless` artifact, never at
///   run time by detecting a display, so the help must name that artifact.
/// - **macOS / Windows + tray.** A `-headless` artifact is published for `linux-x64` and
///   `linux-arm64` and for NO other platform, so sending these readers to one names a download they
///   cannot obtain. Their tray builds link no X11/Wayland stack and DO degrade at run time when the
///   tray cannot mount, so the original promise is both true and the useful thing to print.
/// - **No tray.** This build IS the no-desktop build; it points at no other artifact.
fn headless_note(os: Os, tray: bool) -> &'static str {
    match (tray, os) {
        (false, _) => {
            "
This is the headless build: there is no tray menu, and it runs as an agent on a host
with no desktop."
        }
        (true, Os::Linux) => {
            "
On a Linux server with no desktop, use the `-headless` build instead — this one needs
the desktop libraries and will not start without them."
        }
        (true, _) => {
            "
With no desktop session available it runs headless, without the menu."
        }
    }
}

/// The OS this binary was built for. `headless_note` takes it as an argument so the other arms stay
/// testable; only this one line is compile-time.
const fn target_os() -> Os {
    if cfg!(target_os = "windows") {
        Os::Windows
    } else if cfg!(target_os = "macos") {
        Os::MacOs
    } else {
        Os::Linux
    }
}

/// Whether the tray shell is compiled into THIS binary.
const fn has_tray() -> bool {
    cfg!(feature = "tray")
}

/// What running the binary with no arguments DOES — a pure function of whether the tray is compiled
/// in, for the same reason [`headless_note`] is one: the arm that does not match this build must
/// still be reachable from a test.
///
/// A build with no tray draws no menu, so an opening sentence promising one describes a capability
/// this binary does not have (dig-app#316). `--help` is the ONLY interface an operator has on a
/// display-less host, which makes that the wrong first sentence for exactly its intended reader.
fn opening_line(tray: bool) -> &'static str {
    if tray {
        "The DIG user identity agent. Running it with no arguments starts the agent and puts
the DIG menu in your system tray (menu bar on macOS)."
    } else {
        "The DIG user identity agent. Running it with no arguments starts the agent in the
background. It draws no menu."
    }
}

/// Where a person manages their account — the closing sentence, per arm for the same reason as
/// [`opening_line`]. `diga` is named by BOTH arms: it is the terminal interface either way, and on
/// the headless build it is the only one.
///
/// # `diga` is DESCRIBED, never INSTRUCTED, until the beacon installs it (dig-app#327)
///
/// Both arms used to say *"use `diga`"*. `diga` is built and published for every platform with each
/// dig-app release, but it is **not one of the updater manifest's components** — measured against
/// the live stable manifest, which carries `dig-node`, `digstore`, `dig-updater`, `dig-dns`,
/// `dig-app` and `dig-chat` and no seventh. So the beacon has nothing to install, and a
/// fully-updated machine has no `diga` on `PATH`.
///
/// A person following that instruction got `command not found` with no way to tell whether they
/// mis-typed it, missed an install step, or were on an unsupported platform — worse than the CLI
/// not being mentioned, because the product itself vouched for the command. Until `diga` joins the
/// manifest each arm states where it comes from instead of telling anyone to run it, and the
/// unqualified instruction is guarded against below. The headless arm matters most: `diga` is the
/// ONLY route it has, so a bare instruction there strands its reader completely.
fn where_things_live(tray: bool) -> &'static str {
    if tray {
        "Your account, profiles, wallet and node live in the tray menu. The `diga` CLI does the
same from a terminal. It ships with every dig-app release but is not yet installed by the
DIG updater, so it is on your PATH only if you put it there."
    } else {
        "Your account, profiles, wallet and node are managed from a terminal, with the `diga`
CLI. It ships with every dig-app release but is not yet installed by the DIG updater, so it
is on your PATH only if you put it there."
    }
}

/// The usage text for an arbitrary (os, tray) pair. `help_text` renders THIS build; taking both as
/// arguments is what lets one test read the whole screen an operator on another platform sees.
fn help_text_for(os: Os, tray: bool) -> String {
    format!(
        "{}
{}
{}

Usage: dig-app [OPTIONS]

Options:
  -V, --version  Print the version and exit
  -h, --help     Print this help and exit

{}",
        version_line(),
        opening_line(tray),
        headless_note(os, tray),
        where_things_live(tray)
    )
}

/// The usage text. Short on purpose: this binary genuinely has no verbs, and its job here is to point
/// at the places that DO — the tray menu for a person where there is one, `diga` for a terminal.
pub fn help_text() -> String {
    help_text_for(target_os(), has_tray())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> Invocation {
        Invocation::Run {
            unrecognized: vec![],
            activation: None,
        }
    }

    #[test]
    fn no_arguments_starts_the_agent() {
        assert_eq!(parse::<&str>(&[]), run());
    }

    #[test]
    fn both_version_spellings_are_recognized() {
        assert_eq!(parse(&["--version"]), Invocation::Version);
        assert_eq!(parse(&["-V"]), Invocation::Version);
    }

    /// Every arm of the no-desktop note, exercised on EVERY platform.
    ///
    /// These ran under `#[cfg]` before, so each arm was provable only by a CI job on that exact
    /// (os, feature) pair — and two of the three had none. `headless_note` being a pure function is
    /// what makes one ubuntu job prove all three.
    ///
    /// **A Linux tray build must not promise a runtime degrade it cannot reach**: the default Linux
    /// artifact hard-links GTK and exits 127 before `main()` on a display-less host (dig-app#303).
    /// Asserting only the ABSENCE of that promise would pass if the sentence were simply deleted,
    /// losing the operator the pointer they need, so the `-headless` pointer is asserted too.
    #[test]
    fn a_linux_tray_build_sends_a_server_to_the_headless_build() {
        let note = headless_note(Os::Linux, true);
        assert!(note.contains("-headless"), "{note}");
        assert!(note.contains("will not start"), "{note}");
        assert!(!note.contains("it runs headless"), "{note}");
    }

    /// **macOS and Windows MUST NOT be sent to a `-headless` artifact**: none is published for them,
    /// so the advice would name a download that does not exist. Their run-time degrade is real, so
    /// the no-desktop promise is the honest thing to print.
    ///
    /// The ABSENCE assertion is what distinguishes the per-OS split from the single constant that
    /// preceded it — without it, printing the Linux sentence everywhere passes.
    #[test]
    fn a_non_linux_tray_build_never_names_an_artifact_it_does_not_publish() {
        for os in [Os::MacOs, Os::Windows] {
            let note = headless_note(os, true);
            assert!(!note.contains("-headless"), "{os:?}: {note}");
            assert!(!note.contains("will not start"), "{os:?}: {note}");
            assert!(note.contains("runs headless"), "{os:?}: {note}");
        }
    }

    /// The headless build is the one where a no-desktop claim is unconditionally true, and it must
    /// not send the reader looking for a different artifact they already have.
    ///
    /// This arm had NO CI job at all before: `Headless build` runs clippy only, and `--all-features`
    /// never turns `tray` off.
    #[test]
    fn a_headless_build_says_so_without_pointing_elsewhere() {
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            let note = headless_note(os, false);
            assert!(note.contains("headless build"), "{os:?}: {note}");
            assert!(!note.contains("-headless"), "{os:?}: {note}");
            assert!(!note.contains("will not start"), "{os:?}: {note}");
        }
    }

    /// The three arms are genuinely DIFFERENT strings. Without this, a refactor collapsing them to
    /// one constant keeps every assertion above green: each arm's assertions are satisfiable by a
    /// single sentence that happens to contain "headless build" and no "-headless".
    #[test]
    fn the_three_arms_are_distinct() {
        let linux = headless_note(Os::Linux, true);
        let other = headless_note(Os::MacOs, true);
        let none = headless_note(Os::Linux, false);
        assert_ne!(linux, other);
        assert_ne!(linux, none);
        assert_ne!(other, none);
    }

    /// `help_text` actually EMBEDS the note for this build. The arm tests above prove the strings
    /// are right; without this one they would all pass while `help_text` ignored the function.
    #[test]
    fn help_text_embeds_this_builds_note() {
        assert!(help_text().contains(headless_note(target_os(), has_tray())));
    }

    #[test]
    fn both_help_spellings_are_recognized() {
        assert_eq!(parse(&["--help"]), Invocation::Help);
        assert_eq!(parse(&["-h"]), Invocation::Help);
    }

    /// The beacon's probe is the caller that must never be surprised, so a version request wins even
    /// when it is buried among other arguments.
    #[test]
    fn version_wins_over_help_and_over_junk() {
        assert_eq!(parse(&["--help", "--version"]), Invocation::Version);
        assert_eq!(parse(&["--nonsense", "-V", "--more"]), Invocation::Version);
    }

    /// An unknown argument must NOT stop the agent starting — it is reported, and the app runs.
    #[test]
    fn an_unknown_argument_still_starts_the_agent_and_is_reported() {
        assert_eq!(
            parse(&["--service", "-x"]),
            Invocation::Run {
                unrecognized: vec!["--service".to_string(), "-x".to_string()],
                activation: None,
            }
        );
    }

    // -- the activation URI (dig-app#296) ------------------------------------------------------

    /// The launch a notification click produces, spelled exactly as the toast's `launch` attribute
    /// and therefore exactly as the OS hands it to `%1`.
    #[test]
    fn a_notification_click_asks_for_the_deposit_view() {
        assert_eq!(
            parse(&["dig-app:deposit"]),
            Invocation::Run {
                unrecognized: vec![],
                activation: Some(Activation::Deposit),
            }
        );
    }

    /// An activation URI naming no known route must NOT open a guessed view, must not be an error,
    /// and must still be reported — so it lands where every other unrecognized argument does.
    ///
    /// The inputs are the two wrong implementations this is aimed at: one that strips a query
    /// string off a known route, and one that treats any `dig-app:` argument as an activation.
    #[test]
    fn an_unknown_route_opens_the_default_view_and_is_reported() {
        for uri in [
            "dig-app:deposit?amount=100&to=xch1attacker",
            "dig-app:send",
            "dig-app:",
        ] {
            assert_eq!(
                parse(&[uri]),
                Invocation::Run {
                    unrecognized: vec![uri.to_string()],
                    activation: None,
                },
                "{uri:?} names no route, so it is reported and the app opens normally"
            );
        }
    }

    /// A version probe is still answered when an activation URI is also present — the beacon's
    /// caller must never be surprised, and this is the one ordering the whole module is built on.
    #[test]
    fn version_still_wins_over_an_activation() {
        assert_eq!(
            parse(&["dig-app:deposit", "--version"]),
            Invocation::Version
        );
    }

    // -- the externally-imposed contract with the update beacon -------------------------------

    /// The regression that #1749 exists for, expressed as the CONSUMER's algorithm rather than as
    /// our own output.
    ///
    /// `dig-release-resolver` takes the **last whitespace token of the first line** and requires it
    /// to be exactly three numeric dot-segments. Reproducing that here (rather than asserting
    /// `version_line() == "dig-app x.y.z"`) is what makes this test load-bearing: the nearest wrong
    /// implementation is a well-meaning `"dig-app 3.4.0 (tray build)"`, which an equality assertion
    /// on our own format string would be rewritten to accept, and which this test rejects.
    #[test]
    fn the_beacon_can_parse_the_version_line() {
        let line = version_line();

        let first_line = line.lines().next().expect("a first line");
        let token = first_line
            .split_whitespace()
            .last()
            .expect("a final token to parse");
        let token = token.strip_prefix('v').unwrap_or(token);

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "the beacon rejects anything but MAJOR.MINOR.PATCH; got {token:?} from {line:?}"
        );
        for part in parts {
            assert!(
                part.parse::<u64>().is_ok(),
                "every segment must be numeric; got {part:?} from {line:?}"
            );
        }
    }

    /// The version must track the crate metadata, so a release bump cannot leave a stale literal
    /// behind. Comparing against the same `env!` the release pipeline drives is the only assertion
    /// that stays true across bumps.
    #[test]
    fn the_version_comes_from_the_crate_metadata() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert!(version_line().ends_with(env!("CARGO_PKG_VERSION")));
    }

    /// **Help must not INSTRUCT a person to run a command nothing installs (dig-app#327).**
    ///
    /// `diga` is absent from the updater manifest, so a fully-updated machine has no `diga` on
    /// `PATH`. Naming it is still useful — it is a real binary in every release — but naming it and
    /// telling someone to run it are different acts, and only the second one lies.
    ///
    /// The assertion is on the QUALIFICATION rather than on the absence of the word, because the
    /// nearest wrong fix is deleting the sentence: that stops the lie and also removes the only
    /// pointer to the non-GUI route. So both must hold — `diga` is named, AND the text says it is
    /// not installed. A test asserting only `contains("diga")` passes against the false version.
    /// Asserted over EVERY (os, tray) arm rather than this build's. `where_things_live` gained a
    /// second arm when the help screen became per-build, and the headless arm is the one where the
    /// instruction does the most damage: `diga` is the only route that build has. A test reading
    /// only `help_text()` cannot see the arm it is not compiled for.
    #[test]
    fn help_names_diga_without_instructing_anyone_to_run_it() {
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            for tray in [true, false] {
                let help = help_text_for(os, tray);
                assert!(help.contains("diga"), "{os:?}/{tray}: must still name diga: {help}");
                assert!(
                    help.contains("not yet installed"),
                    "{os:?}/{tray}: must say diga is not installed, or it instructs a                      command nothing delivers: {help}"
                );
                assert!(
                    !help.contains("use `diga`"),
                    "{os:?}/{tray}: the unqualified instruction is what dig-app#327 is: {help}"
                );
            }
        }
    }

    /// Help must name every way in that THIS build has, so a person who runs the binary in a
    /// terminal and sees no window is not left guessing. Asserting on the specific escape routes,
    /// not on length.
    ///
    /// The tray assertion is per-arm: a build without the tray feature has no tray to name, and
    /// asserting one unconditionally is what kept the old contradiction (dig-app#316) invisible.
    ///
    /// It is asserted over the help MINUS the no-desktop note, because the note legitimately says
    /// the words "no tray menu" on a headless build. Reading the raw screen for "tray" cannot tell
    /// a promise apart from its denial — measured: this test failed on the headless build for
    /// exactly that reason before the subtraction was added.
    #[test]
    fn help_points_at_the_ways_in_that_this_build_has() {
        let help = help_text();
        let claims = help.replace(headless_note(target_os(), has_tray()), "");
        assert_eq!(claims.contains("tray"), has_tray(), "{help}");
        assert!(help.contains("diga"), "help must mention diga: {help}");
        assert!(
            help.contains("--version"),
            "help must document --version: {help}"
        );
    }

    /// **A headless build's `--help` must not describe a tray anywhere on the screen.**
    ///
    /// The whole screen is the unit under test, not one sentence: dig-app#316 was three sentences
    /// where the middle one correctly said there is no tray while the first and last described the
    /// menu it draws. Any assertion scoped to a single line passes on that output.
    ///
    /// `diga` MUST still be offered — it is the only interface this build has — so the absence
    /// assertion cannot be satisfied by emitting nothing.
    #[test]
    fn a_headless_builds_whole_help_screen_describes_no_tray() {
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            let help = help_text_for(os, false);
            // The note is the ONE sentence allowed to say "tray", because it says there ISN'T one.
            // Subtracting it first is what keeps this a whole-screen assertion instead of a
            // per-line one -- the same shape `storage::tests` uses to stop `contains("HOME")`
            // being satisfied by `XDG_DATA_HOME`. If the renderer ever dropped the note, the
            // subtraction becomes a no-op and this assertion gets STRICTER, never weaker.
            let claims = help.replace(headless_note(os, false), "");
            assert!(!claims.contains("tray"), "{os:?}: {help}");
            assert!(!claims.contains("menu bar"), "{os:?}: {help}");
            assert!(help.contains("diga"), "{os:?}: {help}");
            assert!(help.contains("draws no menu"), "{os:?}: {help}");
        }
    }

    /// The control for the test above: a TRAY build still describes its tray, in the opening AND the
    /// closing sentence. Without this, deleting both sentences — losing the reader the pointer they
    /// need — passes the absence assertions.
    #[test]
    fn a_tray_builds_help_still_describes_its_tray_at_both_ends() {
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            let help = help_text_for(os, true);
            assert!(help.contains("in your system tray"), "{os:?}: {help}");
            assert!(help.contains("live in the tray menu"), "{os:?}: {help}");
            assert!(help.contains("diga"), "{os:?}: {help}");
        }
    }

    /// `help_text_for` EMBEDS all three per-arm strings rather than re-spelling them.
    ///
    /// Without this the arm tests above would stay green while the renderer ignored one of the
    /// functions and printed a constant — the same shape as `help_text_embeds_this_builds_note`,
    /// extended to the two sentences that wrap the note.
    #[test]
    fn help_text_embeds_every_per_arm_string() {
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            for tray in [true, false] {
                let help = help_text_for(os, tray);
                assert!(help.contains(opening_line(tray)), "{os:?}/{tray}: {help}");
                assert!(
                    help.contains(headless_note(os, tray)),
                    "{os:?}/{tray}: {help}"
                );
                assert!(
                    help.contains(where_things_live(tray)),
                    "{os:?}/{tray}: {help}"
                );
            }
        }
        // And `help_text` renders THIS build through the same renderer.
        assert_eq!(help_text(), help_text_for(target_os(), has_tray()));
    }

    /// Both arms of each wrapping sentence are genuinely different strings — the same guard
    /// `the_three_arms_are_distinct` gives the note, so a collapse back to one constant cannot pass.
    #[test]
    fn the_wrapping_sentences_have_two_distinct_arms() {
        assert_ne!(opening_line(true), opening_line(false));
        assert_ne!(where_things_live(true), where_things_live(false));
    }
}
