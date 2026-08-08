//! The **auto-update** settings group — what channel DIG follows, and whether it updates at all
//! (dig_ecosystem#2293).
//!
//! # The beacon is the authority, and this module never pretends otherwise
//!
//! Auto-update is not performed by dig-app. It is performed by `dig-updater` — the *beacon* — running
//! as a scheduled task (`\DIG\dig-updater` on Windows, a `dig-updater` systemd unit on Linux),
//! trust-rooted on a pinned signing key. The beacon keeps its own `config.json` in an Admin/SYSTEM-only
//! state directory, consults it before every pass, and returns without touching the network when it
//! says paused. That is a REAL refusal, not a quiet skip, and it is why this surface is worth having.
//!
//! So this module owns no policy of its own. It reads the beacon's unprivileged status mirror
//! (`dig-updater status --json`) for what IS true, and it builds the argv that asks the beacon to
//! change (`pause` / `resume` / `channel set <token>`). Nothing here writes the beacon's config,
//! reimplements its defaults, or infers its state from anything but its own answer.
//!
//! # Two values, and why that is not two sources of truth
//!
//! [`AutoUpdate`] is the user's PREFERENCE, remembered in dig-app's own `agent.json`
//! ([`crate::config::AgentConfig`]). [`BeaconStatus`] is the OBSERVED state, read from the beacon.
//! They are different facts and the surface shows the observed one whenever it exists: an
//! administrator who paused the beacon out of band, or a user who dismissed the elevation prompt, must
//! see what is actually happening rather than what dig-app last asked for. The preference exists so
//! that a machine whose beacon cannot be read still shows a meaningful, persisted setting instead of a
//! blank, and so the intended default — auto-update ON — is recorded rather than merely hoped for.
//!
//! # Why every mutation costs an elevation prompt, and why that is the right trade
//!
//! The beacon's `config.json` sits in the same locked-down directory as its trust state, so `pause`,
//! `resume` and `channel set` all require Administrator/root. The alternative — dig-app disabling the
//! scheduled task itself — needs the same elevation AND leaves the beacon's own config claiming it is
//! still enabled, so the two would disagree the moment anything re-armed the schedule. Machine-wide
//! update policy is an administrator's decision on every operating system DIG ships on; the honest
//! response is to say so in the row's own label rather than to route around it. Reading never needs
//! elevation, so the tab always renders the truth even for a user who declines every prompt.

use std::path::{Path, PathBuf};
use std::sync::PoisonError;

use serde::{Deserialize, Serialize};

use crate::apps::AppLocator;

/// The beacon binary's file stem. Every DIG component installs as a sibling in one bin dir (see
/// [`crate::apps`]), so this is all that is needed to find it.
pub const BEACON_STEM: &str = "dig-updater";

/// Which signed feed DIG follows.
///
/// The tokens are the beacon's own (`/v1/<token>/manifest.json`, and the `channel` field of both its
/// `config.json` and its status mirror), so a value round-trips through the CLI unchanged. The legacy
/// pre-channel token `alpha` aliases to [`Nightly`](Self::Nightly), matching the beacon, so an old
/// mirror still parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateChannel {
    /// Tested `vX.Y.Z` releases only. The default, for the reason it is the beacon's default: a
    /// machine nobody has made a choice about should be running releases that were tested.
    #[default]
    Stable,
    /// Nightly builds from `main`, cut every night. Newer, and less tested.
    #[serde(alias = "alpha")]
    Nightly,
}

impl UpdateChannel {
    /// Every channel, in the order they are offered. Callers that must present ALL channels read this
    /// rather than hardcoding the pair, so a third channel is a value and not a new branch.
    pub const ALL: [Self; 2] = [Self::Stable, Self::Nightly];

    /// The beacon's wire/CLI token (`"stable"`, `"nightly"`).
    pub fn token(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Nightly => "nightly",
        }
    }

    /// The name a person reads.
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Stable => "Stable",
            Self::Nightly => "Nightly",
        }
    }

    /// What choosing this channel means, in one clause and no jargon.
    pub fn description(self) -> &'static str {
        match self {
            Self::Stable => "tested releases only",
            Self::Nightly => "the newest builds, tested less",
        }
    }
}

/// The user's remembered auto-update preference, persisted in `agent.json`.
///
/// `enabled` defaults to **true**: a person who has never opened this tab is on auto-update, which is
/// the whole point of shipping a beacon. That default has to survive a config file written before this
/// field existed, which a bare `#[serde(default)]` on a `bool` would NOT do — it would yield `false`
/// and silently opt every existing install OUT. Hence the explicit `default_enabled` seed, and the
/// test that pins it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoUpdate {
    /// Whether DIG should keep itself up to date.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Which feed to follow.
    #[serde(default)]
    pub channel: UpdateChannel,
}

fn default_enabled() -> bool {
    true
}

impl Default for AutoUpdate {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            channel: UpdateChannel::default(),
        }
    }
}

/// What the beacon says about itself right now — the two facts this surface shows.
///
/// Deliberately a two-field subset of the beacon's much larger status mirror. Carrying the whole
/// snapshot would couple dig-app to a schema it neither owns nor needs, and every extra field would be
/// one more thing to keep in step across two repos for no user-visible gain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconStatus {
    /// Whether updates are PAUSED. The beacon reports the EFFECTIVE value — a timed pause that has
    /// lapsed already reads as not paused.
    pub paused: bool,
    /// Whether the daily schedule was DELIBERATELY removed (`dig-updater schedule uninstall`), which
    /// the beacon records as a privileged-owned sentinel beside its config.
    ///
    /// A separate fact from [`paused`](Self::paused), and not a redundant one: an opted-out beacon is
    /// not paused, it simply never wakes. Reading only `paused` on such a host reports "auto-update —
    /// on" about a machine that will never update itself, and — worse — makes `resume` look like the
    /// remedy when it clears a pause that was never set (dig_ecosystem#2324).
    ///
    /// Absent from an older beacon's status mirror, and absence means `false`: the sentinel is what
    /// makes this true, so a mirror that does not mention it is describing a host that has none.
    pub schedule_opted_out: bool,
    /// The channel the beacon is configured to follow.
    pub channel: UpdateChannel,
}

impl BeaconStatus {
    /// Whether this machine will actually update itself.
    ///
    /// Both facts, because either one alone stops updates happening, and the surface's whole claim is
    /// this single sentence. Every heading, row label and pane note derives from this rather than from
    /// [`paused`](Self::paused) — reading the pause flag directly is how a host that had opted out came
    /// to be told it was up to date.
    pub fn updates_are_live(self) -> bool {
        !self.paused && !self.schedule_opted_out
    }

    /// What has to change for [`updates_are_live`](Self::updates_are_live) to become true, if
    /// anything.
    ///
    /// The schedule comes FIRST when both are wrong, because it is the blocker a resume cannot clear:
    /// re-arming leaves a still-paused beacon reporting a pause the user can then lift, whereas
    /// resuming first leaves them looking at "on" on a machine that never wakes.
    pub fn blocking_updates(self) -> Option<Change> {
        match (self.schedule_opted_out, self.paused) {
            (true, _) => Some(Change::RearmSchedule),
            (false, true) => Some(Change::Enable(true)),
            (false, false) => None,
        }
    }
}

/// Read the beacon's `status --json` output.
///
/// `None` for anything that is not a beacon status object: a non-zero exit's error JSON, an empty body
/// from a binary that is not there, or a future/foreign shape. A `None` is shown as "the updater could
/// not be asked", which is honest; guessing a default here would draw a confident switch position for
/// a beacon nobody has heard from.
///
/// Only `paused` and `channel` are read, and an absent `channel` falls back to the same default the
/// beacon itself uses. `paused` is required: a status mirror that does not say whether updates are
/// running has not answered the question.
pub fn read_status(json: &[u8]) -> Option<BeaconStatus> {
    let value: serde_json::Value = serde_json::from_slice(json).ok()?;
    let paused = value.get("paused")?.as_bool()?;
    let channel = match value.get("channel") {
        Some(raw) => serde_json::from_value(raw.clone()).ok()?,
        None => UpdateChannel::default(),
    };
    Some(BeaconStatus {
        paused,
        // Optional, unlike `paused`: a beacon predating the opt-out sentinel cannot have one, so its
        // silence is a real `false` rather than an unanswered question.
        schedule_opted_out: value
            .get("schedule_opted_out")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        channel,
    })
}

/// A change the user asked for, before it has been shown to be possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Turn auto-update on or off — `resume` or `pause`.
    Enable(bool),
    /// Put the daily schedule back — `schedule install`, which also clears the opt-out sentinel.
    ///
    /// Distinct from `Enable(true)` because it fixes a different thing, and using `resume` here is
    /// precisely the defect: on an opted-out host `resume` exits ZERO having cleared a pause that was
    /// never set, so DIG would report the setting saved while the machine still never wakes to update
    /// (dig_ecosystem#2324).
    RearmSchedule,
    /// Follow a different feed. Carries the channel being LEFT as well as the one being adopted,
    /// because the caution the user is owed depends on the direction (see [`switch_caution`]).
    Channel {
        /// The channel in force before the click.
        from: UpdateChannel,
        /// The channel the user picked.
        to: UpdateChannel,
    },
}

impl Change {
    /// The beacon argv this change asks for.
    pub fn argv(self) -> Vec<String> {
        let words: Vec<&str> = match self {
            Self::Enable(true) => vec!["resume"],
            Self::Enable(false) => vec!["pause"],
            Self::RearmSchedule => vec!["schedule", "install"],
            Self::Channel { to, .. } => vec!["channel", "set", to.token()],
        };
        words.into_iter().map(str::to_string).collect()
    }
}

/// What to do about a click on an auto-update row, decided without touching the process table.
///
/// Same shape and same reasoning as [`crate::apps::LaunchPlan`]: spawning an elevated process cannot
/// be exercised from a unit test, but "which of the two things should happen, and what is the user
/// told first" is exactly the rule worth pinning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangePlan {
    /// Run the beacon. The shell asks for elevation, because every one of these argvs writes the
    /// beacon's Admin-only config.
    Run {
        /// The located beacon binary.
        program: PathBuf,
        /// Its arguments.
        args: Vec<String>,
        /// What the user must be told and agree to BEFORE this runs, if anything.
        caution: Option<String>,
    },
    /// The beacon is not installed, so there is nothing to configure. Carries the sentence the shell
    /// shows — a notice, never a silent no-op.
    NotInstalled {
        /// The notice body.
        body: String,
    },
}

/// Decide what a click on an auto-update row does.
pub fn plan_change(locator: &dyn AppLocator, change: Change) -> ChangePlan {
    let Some(program) = locator.locate(BEACON_STEM) else {
        return ChangePlan::NotInstalled {
            body: NOT_INSTALLED_BODY.to_string(),
        };
    };
    ChangePlan::Run {
        program,
        args: change.argv(),
        caution: match change {
            // Nothing to warn about: both restore the state a person expects DIG to be in, and
            // re-arming the schedule is what the user just asked for in so many words.
            Change::Enable(_) | Change::RearmSchedule => None,
            Change::Channel { from, to } => switch_caution(from, to).map(str::to_string),
        },
    }
}

/// Shown when the beacon is absent. It names what is missing and what having it would do, rather than
/// reporting a failure the user can do nothing with.
const NOT_INSTALLED_BODY: &str =
    "The DIG updater is not installed on this computer, so DIG cannot \
     keep itself up to date and there is nothing to turn on or off here. Install DIG with the DIG \
     installer and auto-update will be set up with it.";

/// What the user must be told before a channel switch takes effect, or `None` when the switch is a
/// no-op.
///
/// # Nightly to stable is a DOWNGRADE, and saying nothing about that would be a lie by omission
///
/// The two channels are independent trust contexts: each has its own feed and its own monotonic
/// rollback floor, so switching cannot rewind the floor of the channel being left. What it CAN do is
/// leave the machine running a nightly build that is newer than anything stable has released, and the
/// next pass will then move those components BACK to the stable release. That is the correct behaviour
/// — the user asked to follow stable — but it is a version going down, which no one expects from an
/// updater unless they are told.
pub fn switch_caution(from: UpdateChannel, to: UpdateChannel) -> Option<&'static str> {
    match (from, to) {
        (UpdateChannel::Stable, UpdateChannel::Stable)
        | (UpdateChannel::Nightly, UpdateChannel::Nightly) => None,
        (UpdateChannel::Nightly, UpdateChannel::Stable) => Some(
            "Following the stable channel can move DIG back to an earlier version. Nightly builds \
             are usually ahead of the newest tested release, so the next update may install an \
             older, tested version over the newer one you have now. Nothing you have saved is \
             removed, and you can switch back to nightly whenever you like.",
        ),
        (UpdateChannel::Stable, UpdateChannel::Nightly) => Some(
            "Nightly builds are cut every night from the newest code and get far less testing than a \
             release. Expect the occasional broken build. You can switch back to stable whenever you \
             like.",
        ),
    }
}

/// A privileged run of the beacon, ready to hand to [`std::process::Command`].
///
/// The `env` entries are not optional decoration — on Windows they carry the only values that vary,
/// and dropping them yields a command that runs nothing. See [`elevated_command`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elevation {
    /// The elevator to spawn (`powershell`, `pkexec`).
    pub program: String,
    /// Its argv.
    pub args: Vec<String>,
    /// Variables to add to the elevator's environment block, as `(name, value)`.
    pub env: Vec<(String, String)>,
}

/// The environment variable carrying the beacon's path into the Windows elevation command.
pub const BEACON_PATH_VAR: &str = "DIG_ELEVATE_PROGRAM";

/// Prefix of the per-argument environment variables, suffixed with the argument's index.
pub const BEACON_ARG_VAR_PREFIX: &str = "DIG_ELEVATE_ARG";

/// How to run `program args…` with the privileges the beacon's config directory demands, on `os`.
///
/// `os` is [`std::env::consts::OS`] — a runtime string, deliberately not a `cfg!`. Every branch is
/// then exercised by `cargo test` on every runner, where a `cfg!` would leave two of the three
/// unfalsifiable on whichever platform CI happens to be.
///
/// `None` means this operating system has no way for a desktop app to ask for elevation that DIG is
/// willing to use, so the change must be refused with an explanation rather than attempted and failed.
/// macOS is that case today: it also has no window host, so this surface is the tray's, and prompting
/// for an admin password from a menu bar item is not a pattern the platform offers honestly.
///
/// # Quoting is AVOIDED here, not solved
///
/// The Windows route is the only one that hands a STRING to a language parser, and that is the whole
/// hazard: `-Command` is PowerShell source, so any run-time value spliced into it is being offered to
/// a tokenizer. The previous shape spliced the install path in as a single-quoted literal with `'`
/// doubled, on the stated reasoning that a quote is the only character able to end such a literal.
/// **That reasoning is false.** PowerShell's `CharTraits.IsSingleQuote` admits FIVE codepoints —
/// U+0027 and the curly quotes U+2018, U+2019, U+201A, U+201B — and `ScanStringLiteral` terminates on
/// any of them regardless of which one opened the string. All four exotic ones are legal in NTFS and
/// arrive from ordinary autocorrect, so a path containing one closed the literal early and the tail
/// became COMMAND on a line the user was being asked to run as Administrator (dig_ecosystem#2325).
///
/// Widening the escape to five codepoints would leave a denylist one Unicode revision from being
/// wrong again, and a second copy of the tokenizer's rule to keep in step with it. So the values are
/// taken OUT of the parser instead: the path and every argument travel in the elevator's environment
/// block, and the command string refers to them as `$env:` variables whose NAMES this function
/// generates from an index. Nothing in the command string derives from a run-time value, so no input
/// can become tokens — there is nothing to escape and no rule to keep in sync. `$env:X` in argument
/// position binds the variable's value as one argument; PowerShell does not re-tokenize or word-split
/// it, which is exactly the property the literal was trying and failing to buy.
///
/// The arguments are separately safe by construction ([`Change::argv`] builds them from a closed enum
/// of `&'static str`, pinned by `no_change_can_produce_an_argument_needing_quoting`), but they take
/// the same route: one string-building rule for the whole command is a rule that cannot be applied
/// inconsistently, and a future change carrying a user-chosen token would otherwise reopen this.
pub fn elevated_command(os: &str, program: &Path, args: &[String]) -> Option<Elevation> {
    match os {
        "windows" => {
            let mut env = vec![(BEACON_PATH_VAR.to_string(), program.display().to_string())];
            let mut refs = Vec::with_capacity(args.len());
            for (index, arg) in args.iter().enumerate() {
                let name = format!("{BEACON_ARG_VAR_PREFIX}{index}");
                refs.push(format!("$env:{name}"));
                env.push((name, arg.clone()));
            }
            // `-ArgumentList` demands at least one value, so a no-argument run omits the parameter
            // rather than emitting an empty list PowerShell would refuse to parse.
            let argument_list = match refs.is_empty() {
                true => String::new(),
                false => format!(" -ArgumentList {}", refs.join(",")),
            };
            Some(Elevation {
                program: "powershell".to_string(),
                args: vec![
                    "-NoProfile".to_string(),
                    "-Command".to_string(),
                    format!(
                        "Start-Process -FilePath $env:{BEACON_PATH_VAR}{argument_list} \
                         -Verb RunAs -Wait"
                    ),
                ],
                env,
            })
        }
        // The freedesktop polkit agent: it draws the system's own authentication dialog, so the user
        // is authorising DIG through their desktop rather than typing a password into DIG. There is no
        // parser in this path — argv reaches `execve` as separate strings — so the values travel as
        // arguments and no environment indirection is needed.
        "linux" => {
            let mut argv = vec![program.display().to_string()];
            argv.extend(args.iter().cloned());
            Some(Elevation {
                program: "pkexec".to_string(),
                args: argv,
                env: Vec::new(),
            })
        }
        _ => None,
    }
}

/// Shown when the platform offers no elevation route ([`elevated_command`] returned `None`), naming
/// the command that does the same thing so the setting is still reachable.
pub fn no_elevation_route_body(program: &Path, args: &[String]) -> String {
    format!(
        "DIG cannot ask this computer for administrator rights from here, and changing how the whole \
         computer updates itself needs them.\n\nYou can make the same change from a terminal:\n\n    \
         sudo {} {}",
        program.display(),
        args.join(" ")
    )
}

/// The explainer behind the group's "About auto-update" row.
pub fn explainer_body() -> String {
    format!(
        "DIG keeps itself up to date with a small background updater. It checks once a day, and it \
         only installs updates that carry a valid DIG signature — an update that does not verify is \
         refused, not installed.\n\n\
         {stable} {stable_desc}. {nightly} {nightly_desc}. Most people should stay on {stable}.\n\n\
         Turning auto-update off, or changing the channel, changes a setting for the whole computer, \
         so Windows or Linux will ask you to confirm as an administrator. Reading this page never \
         does.",
        stable = UpdateChannel::Stable.display_name(),
        stable_desc = UpdateChannel::Stable.description(),
        nightly = UpdateChannel::Nightly.display_name(),
        nightly_desc = UpdateChannel::Nightly.description(),
    )
}

/// How long a beacon reading is reused before the beacon is asked again.
///
/// Chosen against what the reading is FOR rather than by taste. It has one deadline: after an
/// elevation prompt is accepted, the switch must be seen to move. That path does not wait for this
/// interval — it refreshes the cache itself — so what remains is the slow case of a change made
/// outside DIG entirely (`dig-updater channel set` in a terminal), where five seconds is far below
/// noticing. It is also two orders of magnitude below the repaint rate, which is the number that
/// matters: the surface repaints about twice a second.
pub const BEACON_REFRESH: std::time::Duration = std::time::Duration::from_secs(5);

/// A beacon reading, reused across repaints (dig_ecosystem#2311).
///
/// # Why this type exists at all
///
/// Asking the beacon means SPAWNING IT — `dig-updater status --json` is a subprocess. The surface
/// that shows the answer rebuilds its whole view on every repaint, about twice a second, so reading
/// the beacon inside that rebuild spawns, executes and reaps a process roughly 120 times a minute on
/// an idle machine. On Windows it was also visible: a console child of a GUI-subsystem parent flashes
/// a window, which is how this was found.
///
/// The fix is not "read it less often" written in a comment — it is a value that HOLDS the reading, so
/// the frequency is a property of this type instead of a property of every call site. Same shape and
/// same reasoning as `dig-app`'s process-wide balance poller.
///
/// # Why the clock is a parameter
///
/// [`read`](Self::read) takes `now` rather than calling [`Instant::now`](std::time::Instant::now)
/// itself, so a test states the passage of time instead of sleeping through it.
#[derive(Debug, Default)]
pub struct BeaconCache {
    /// The last reading and when it was taken. `None` until the first read; the inner `Option` is the
    /// reading itself, and a `None` reading is cached exactly like a `Some` one — "nobody answered"
    /// is an answer, and re-spawning a missing binary twice a second is the same defect.
    held: std::sync::Mutex<Option<(std::time::Instant, Option<BeaconStatus>)>>,
}

impl BeaconCache {
    /// The current reading, asking `fetch` only if what is held has aged past [`BEACON_REFRESH`].
    ///
    /// `fetch` is a closure rather than a fixed call so the spawn stays at the call site that owns it
    /// — this module decides WHEN, not HOW.
    pub fn read(
        &self,
        now: std::time::Instant,
        fetch: impl FnOnce() -> Option<BeaconStatus>,
    ) -> Option<BeaconStatus> {
        // A panic in another thread must not turn this into a permanent refusal to read the beacon:
        // what the lock guards is a CACHE, so the worst a poisoned one can hold is a stale reading,
        // and taking it is strictly better than propagating that panic into every repaint.
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((taken, reading)) = *held {
            if now.duration_since(taken) < BEACON_REFRESH {
                return reading;
            }
        }
        let reading = fetch();
        *held = Some((now, reading));
        reading
    }

    /// Take a reading now, whatever is held, and hold it.
    ///
    /// For the moment a change has just been applied: the held reading is known to be stale the
    /// instant the beacon accepts, and waiting out [`BEACON_REFRESH`] would show the user the switch
    /// they just moved sitting in its old position.
    pub fn refresh(
        &self,
        now: std::time::Instant,
        fetch: impl FnOnce() -> Option<BeaconStatus>,
    ) -> Option<BeaconStatus> {
        let reading = fetch();
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        *held = Some((now, reading));
        reading
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// A locator that reports the beacon present at a fixed path, and nothing else installed.
    struct BeaconAt(&'static str);
    impl AppLocator for BeaconAt {
        fn locate(&self, stem: &str) -> Option<PathBuf> {
            (stem == BEACON_STEM).then(|| PathBuf::from(self.0))
        }
    }

    /// A locator on a machine with no DIG binaries at all.
    struct NothingInstalled;
    impl AppLocator for NothingInstalled {
        fn locate(&self, _stem: &str) -> Option<PathBuf> {
            None
        }
    }

    /// **The default that the whole feature turns on.** A config file written before this field
    /// existed must load as auto-update ON.
    ///
    /// This is the case a naive implementation gets backwards: `#[serde(default)]` on a `bool` yields
    /// `false`, which would opt every existing install OUT of updates on the version that added the
    /// setting. Pinned from both sides — an absent field is on, and an explicit `false` is off, so the
    /// test cannot be satisfied by a field that ignores its input.
    #[test]
    fn an_absent_enabled_field_loads_as_on() {
        let absent: AutoUpdate = serde_json::from_str("{}").unwrap();
        assert!(
            absent.enabled,
            "an absent field must mean auto-update is ON"
        );
        assert_eq!(absent.channel, UpdateChannel::Stable);

        let explicit: AutoUpdate = serde_json::from_str(r#"{"enabled":false}"#).unwrap();
        assert!(
            !explicit.enabled,
            "an explicit false must still mean OFF, or the default is just a constant"
        );
    }

    #[test]
    fn the_default_preference_is_on_and_stable() {
        assert_eq!(
            AutoUpdate::default(),
            AutoUpdate {
                enabled: true,
                channel: UpdateChannel::Stable
            }
        );
    }

    /// The channel tokens are the beacon's, so a value written here is a value it accepts.
    #[test]
    fn a_channel_round_trips_through_the_beacons_own_tokens() {
        for channel in UpdateChannel::ALL {
            let json = serde_json::to_string(&channel).unwrap();
            assert_eq!(json, format!("\"{}\"", channel.token()));
            assert_eq!(
                serde_json::from_str::<UpdateChannel>(&json).unwrap(),
                channel
            );
        }
        // The beacon still accepts the pre-channel token, so a mirror written by an old beacon must
        // not read as "could not be asked".
        assert_eq!(
            serde_json::from_str::<UpdateChannel>("\"alpha\"").unwrap(),
            UpdateChannel::Nightly
        );
    }

    /// The status mirror is read for exactly two facts, and `paused` is INVERTED on the way in.
    ///
    /// The fixture is the beacon's real shape, extra fields and all, because a parser tested only
    /// against a two-key object proves nothing about the object it will actually be handed.
    #[test]
    fn a_real_status_mirror_reads_as_the_two_facts_the_tab_shows() {
        let running = br#"{
            "schema": 1, "version": "0.27.0", "channel": "nightly", "paused": false,
            "paused_until": null, "last_check": 1754000000, "last_outcome": "applied",
            "components": [], "trust_state": {}, "refused_components": []
        }"#;
        assert_eq!(
            read_status(running),
            Some(BeaconStatus {
                paused: false,
                schedule_opted_out: false,
                channel: UpdateChannel::Nightly
            })
        );

        let paused = br#"{"schema":1,"version":"0.27.0","channel":"stable","paused":true}"#;
        assert_eq!(
            read_status(paused),
            Some(BeaconStatus {
                paused: true,
                schedule_opted_out: false,
                channel: UpdateChannel::Stable
            })
        );
    }

    /// A body that is not a beacon status is `None`, not a confident default.
    ///
    /// The middle case is the one that matters: the CLI's own error object is well-formed JSON, so a
    /// parser that only guarded against malformed input would read a FAILED status call as a running
    /// beacon on the stable channel and draw a switch position nobody reported.
    #[test]
    fn a_non_status_body_is_unknown_rather_than_a_guess() {
        assert_eq!(read_status(b""), None);
        assert_eq!(read_status(b"not json"), None);
        assert_eq!(
            read_status(br#"{"status":"error","detail":"state dir unreadable"}"#),
            None,
            "the CLI's error object must not read as a running beacon"
        );
        assert_eq!(read_status(br#"{"paused":"no"}"#), None);
        assert_eq!(
            read_status(br#"{"paused":false,"channel":"experimental"}"#),
            None,
            "a channel this build does not know is not silently stable"
        );
    }

    /// A status mirror written before the channel field existed still answers the pause question.
    #[test]
    fn a_channel_less_mirror_falls_back_to_the_beacons_own_default() {
        assert_eq!(
            read_status(br#"{"schema":1,"paused":false}"#),
            Some(BeaconStatus {
                paused: false,
                schedule_opted_out: false,
                channel: UpdateChannel::Stable
            })
        );
    }

    /// Each change maps to the beacon subcommand that performs it, and no two changes share an argv.
    #[test]
    fn every_change_is_a_distinct_beacon_subcommand() {
        assert_eq!(Change::Enable(true).argv(), ["resume"]);
        assert_eq!(Change::Enable(false).argv(), ["pause"]);
        assert_eq!(
            Change::Channel {
                from: UpdateChannel::Stable,
                to: UpdateChannel::Nightly
            }
            .argv(),
            ["channel", "set", "nightly"]
        );
        assert_eq!(
            Change::Channel {
                from: UpdateChannel::Nightly,
                to: UpdateChannel::Stable
            }
            .argv(),
            ["channel", "set", "stable"]
        );

        let argvs: BTreeSet<Vec<String>> = [
            Change::Enable(true),
            Change::Enable(false),
            Change::Channel {
                from: UpdateChannel::Stable,
                to: UpdateChannel::Nightly,
            },
            Change::Channel {
                from: UpdateChannel::Nightly,
                to: UpdateChannel::Stable,
            },
        ]
        .into_iter()
        .map(Change::argv)
        .collect();
        assert_eq!(argvs.len(), 4, "two different clicks ran the same command");
    }

    /// The argv names the channel being ADOPTED, never the one being left — a switch that sent the old
    /// token would silently do nothing while reporting success.
    #[test]
    fn a_switch_sets_the_channel_the_user_picked() {
        for from in UpdateChannel::ALL {
            for to in UpdateChannel::ALL {
                let argv = Change::Channel { from, to }.argv();
                assert_eq!(argv[2], to.token(), "switching {from:?} -> {to:?}");
            }
        }
    }

    #[test]
    fn a_click_runs_the_installed_beacon() {
        let plan = plan_change(&BeaconAt("/opt/dig/bin/dig-updater"), Change::Enable(false));
        assert_eq!(
            plan,
            ChangePlan::Run {
                program: PathBuf::from("/opt/dig/bin/dig-updater"),
                args: vec!["pause".to_string()],
                caution: None,
            }
        );
    }

    /// With no beacon there is nothing to configure, and the user is TOLD so — never a click that
    /// appears to work and changes nothing.
    #[test]
    fn a_click_with_no_beacon_installed_explains_itself() {
        let ChangePlan::NotInstalled { body } =
            plan_change(&NothingInstalled, Change::Enable(false))
        else {
            panic!("a missing beacon must not produce a command to run");
        };
        assert!(body.contains("not installed"));
        assert!(
            body.contains("DIG installer"),
            "the notice must name the way to get one"
        );
    }

    /// **The downgrade the user is owed a warning about.** Nightly to stable can move a version
    /// backwards, so that switch carries a caution and the click cannot be planned without one.
    ///
    /// Asserted from both directions and on the no-op, because a function that returned the same
    /// sentence for every pair would pass a test that only checked one.
    #[test]
    fn leaving_nightly_warns_that_the_version_can_go_backwards() {
        let caution = switch_caution(UpdateChannel::Nightly, UpdateChannel::Stable)
            .expect("leaving nightly must be explained");
        assert!(
            caution.contains("earlier version") && caution.contains("older"),
            "the caution must say the version can go DOWN: {caution}"
        );

        let joining = switch_caution(UpdateChannel::Stable, UpdateChannel::Nightly)
            .expect("joining nightly must be explained");
        assert_ne!(
            joining, caution,
            "the two directions are different facts and cannot share one sentence"
        );
        assert!(joining.contains("less testing"));

        for channel in UpdateChannel::ALL {
            assert_eq!(
                switch_caution(channel, channel),
                None,
                "re-picking the channel already in force changes nothing to warn about"
            );
        }
    }

    /// A planned switch carries its caution, so the shell cannot apply one without having shown it.
    #[test]
    fn a_planned_switch_carries_the_caution_the_user_must_see_first() {
        let ChangePlan::Run { caution, .. } = plan_change(
            &BeaconAt("/opt/dig/bin/dig-updater"),
            Change::Channel {
                from: UpdateChannel::Nightly,
                to: UpdateChannel::Stable,
            },
        ) else {
            panic!("an installed beacon must be runnable");
        };
        assert_eq!(
            caution.as_deref(),
            switch_caution(UpdateChannel::Nightly, UpdateChannel::Stable)
        );
    }

    /// Every platform's elevation route runs the SAME beacon subcommand, and the one platform with no
    /// route says so rather than silently doing nothing.
    ///
    /// Driven off [`Change::argv`] rather than a hand-typed argv, so a change to what `pause` is called
    /// cannot leave this test asserting a command the app no longer issues.
    #[test]
    fn each_platform_elevates_the_same_beacon_subcommand() {
        let beacon = PathBuf::from("/opt/dig/bin/dig-updater");
        let args = Change::Channel {
            from: UpdateChannel::Stable,
            to: UpdateChannel::Nightly,
        }
        .argv();

        let windows = elevated_command("windows", &beacon, &args).expect("windows elevates");
        assert_eq!(windows.program, "powershell");
        let script = windows.args.last().unwrap();
        assert!(script.contains("-Verb RunAs"), "{script}");
        // The beacon and its argv are named by variable, and the variables carry the real values —
        // asserted on the ENV, because that is now where the subcommand lives.
        assert!(
            script.contains("-FilePath $env:DIG_ELEVATE_PROGRAM"),
            "{script}"
        );
        assert!(
            script.contains(
                "-ArgumentList $env:DIG_ELEVATE_ARG0,$env:DIG_ELEVATE_ARG1,$env:DIG_ELEVATE_ARG2"
            ),
            "{script}"
        );
        assert_eq!(
            windows.env,
            vec![
                (
                    "DIG_ELEVATE_PROGRAM".to_string(),
                    beacon.display().to_string()
                ),
                ("DIG_ELEVATE_ARG0".to_string(), "channel".to_string()),
                ("DIG_ELEVATE_ARG1".to_string(), "set".to_string()),
                ("DIG_ELEVATE_ARG2".to_string(), "nightly".to_string()),
            ]
        );

        let linux = elevated_command("linux", &beacon, &args).expect("linux elevates");
        assert_eq!(linux.program, "pkexec");
        assert_eq!(
            linux.args,
            vec!["/opt/dig/bin/dig-updater", "channel", "set", "nightly"]
        );
        assert!(
            linux.env.is_empty(),
            "there is no parser in the pkexec path, so nothing needs an environment detour"
        );

        assert_eq!(
            elevated_command("macos", &beacon, &args),
            None,
            "a platform with no route must be refused, not attempted"
        );
        let body = no_elevation_route_body(&beacon, &args);
        assert!(
            body.contains("sudo /opt/dig/bin/dig-updater channel set nightly"),
            "the refusal must name the command that works: {body}"
        );
    }

    /// **No change can produce an argument that needs quoting.** Defence in depth rather than the
    /// load-bearing guarantee it once was: since [`elevated_command`] routes every argument through
    /// the environment too, no argument is offered to a parser either. This keeps the argv boring
    /// anyway, so a future channel token that carried a space or a quote is caught at its source
    /// rather than relying on the transport to absorb it.
    ///
    /// The channel tokens are checked too, not only the subcommand words: a future channel whose token
    /// carried a space or a quote would slip through a test that only looked at `pause`/`resume`.
    #[test]
    fn no_change_can_produce_an_argument_needing_quoting() {
        let mut changes = vec![
            Change::Enable(true),
            Change::Enable(false),
            Change::RearmSchedule,
        ];
        for from in UpdateChannel::ALL {
            for to in UpdateChannel::ALL {
                changes.push(Change::Channel { from, to });
            }
        }
        for change in changes {
            for arg in change.argv() {
                assert!(
                    !arg.is_empty()
                        && arg
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                    "{arg:?} is not a bare lowercase token, so embedding it in a shell string is \
                     no longer provably safe"
                );
            }
        }
    }

    /// **A host that opted out of the daily schedule is not "on", and `resume` is not its remedy.**
    ///
    /// The state that makes this worth a test: `paused` is FALSE and updates still never happen. Every
    /// reading of the pause flag alone calls that host up to date, and offers it a `resume` that exits
    /// zero having changed nothing — so DIG reports a saved setting for a machine that will not update
    /// itself (dig_ecosystem#2324). Both halves are asserted, because fixing only the label would leave
    /// the honest text sitting above the useless button.
    #[test]
    fn an_opted_out_schedule_stops_updates_and_asks_for_a_re_arm_not_a_resume() {
        let opted_out = BeaconStatus {
            paused: false,
            schedule_opted_out: true,
            channel: UpdateChannel::Stable,
        };
        assert!(
            !opted_out.updates_are_live(),
            "a removed daily check means the machine does not update itself, whatever `paused` says"
        );
        assert_eq!(opted_out.blocking_updates(), Some(Change::RearmSchedule));
        assert_eq!(
            Change::RearmSchedule.argv(),
            vec!["schedule".to_string(), "install".to_string()],
            "`schedule install` is the command that re-arms the check and clears the opt-out marker"
        );
        assert_ne!(
            Change::RearmSchedule.argv(),
            Change::Enable(true).argv(),
            "a re-arm that ran `resume` would be the defect, not the fix"
        );
    }

    /// The three ways updates can be stopped resolve to three different remedies, in a fixed order.
    ///
    /// A truthful control at each corner: the running host must ask for nothing, or a `blocking_updates`
    /// that always answered would look correct on the two broken cases.
    #[test]
    fn each_reason_updates_are_stopped_has_its_own_remedy() {
        let status = |paused, schedule_opted_out| BeaconStatus {
            paused,
            schedule_opted_out,
            channel: UpdateChannel::Stable,
        };

        assert_eq!(status(false, false).blocking_updates(), None);
        assert_eq!(
            status(true, false).blocking_updates(),
            Some(Change::Enable(true))
        );
        assert_eq!(
            status(false, true).blocking_updates(),
            Some(Change::RearmSchedule)
        );
        // Both wrong: the schedule first, because resuming would leave "on" showing on a machine that
        // never wakes, whereas re-arming leaves a pause the user can then see and lift.
        assert_eq!(
            status(true, true).blocking_updates(),
            Some(Change::RearmSchedule)
        );
        assert!(status(false, false).updates_are_live());
        for broken in [status(true, false), status(false, true), status(true, true)] {
            assert!(
                !broken.updates_are_live(),
                "{broken:?} does not update itself"
            );
        }
    }

    /// The opt-out flag is read from the beacon's real mirror, and its absence is a real `false`.
    #[test]
    fn the_status_mirror_carries_the_opt_out_flag_and_its_absence_means_no() {
        let opted_out =
            br#"{"schema":1,"channel":"stable","paused":false,"schedule_opted_out":true}"#;
        assert_eq!(
            read_status(opted_out),
            Some(BeaconStatus {
                paused: false,
                schedule_opted_out: true,
                channel: UpdateChannel::Stable
            })
        );

        // An older beacon has no opt-out sentinel to report, so silence is `false` — not "unknown",
        // which would make every pre-sentinel host look broken.
        let older = br#"{"schema":1,"channel":"stable","paused":false}"#;
        assert_eq!(
            read_status(older).map(|status| status.schedule_opted_out),
            Some(false)
        );
    }

    /// Paths Windows genuinely allows, each one a way the previous escape was wrong or could become
    /// wrong. Shared by the two tests below so neither can be strengthened without the other seeing it.
    ///
    /// The first five carry PowerShell's FIVE single-quote codepoints (`CharTraits.IsSingleQuote`:
    /// U+0027, U+2018, U+2019, U+201A, U+201B), each followed by a payload that would run. The escape
    /// this replaced doubled only U+0027, so the four curly ones truncated the `-FilePath` and executed
    /// the tail with no UAC prompt at all — `Start-Process` had failed on the truncated path, so
    /// `-Verb RunAs` never ran (dig_ecosystem#2325). The rest are NEGATIVE CONTROLS: characters that do
    /// NOT end a literal, and a look-alike quote (U+201C is a DOUBLE quote, U+00B4 an acute accent,
    /// U+02BC a modifier letter). They belong here because a fix that over-escapes them mangles the
    /// path into one that no longer names the beacon, which is a broken elevation of its own.
    const HOSTILE_PATHS: [&str; 10] = [
        "C:\\Users\\O'Brien\\DIG\\bin\\dig-updater.exe",
        "C:\\dig\u{27};Write-Output PWNED;exit 42;#\\dig-updater.exe",
        "C:\\dig\u{2018};Write-Output PWNED;exit 42;#\\dig-updater.exe",
        "C:\\dig\u{2019};Write-Output PWNED;exit 42;#\\dig-updater.exe",
        "C:\\dig\u{201A};Write-Output PWNED;exit 42;#\\dig-updater.exe",
        "C:\\dig\u{201B};Write-Output PWNED;exit 42;#\\dig-updater.exe",
        "C:\\dig\u{201C}\u{00B4}\u{02BC}\\dig-updater.exe",
        "C:\\Program Files\\DIG & Co\\dig-updater.exe",
        "C:\\dig$env:PATH`n;rm\\dig-updater.exe",
        "C:\\dig;rm\\dig-updater.exe",
    ];

    /// **No install path reaches the elevation command as text at all.**
    ///
    /// This is the property the fix buys, and it is asserted as an ABSENCE deliberately. The escape it
    /// replaced was audited by a helper that re-implemented PowerShell's string scanner — and that
    /// helper modelled only ASCII `'`, the very blind spot of the function it was auditing, so adding a
    /// U+2019 fixture to it left the test PASSING on a command that executes attacker text. An
    /// instrument that models the parser can be wrong about the parser. An instrument that asks
    /// "does the value appear in the string?" cannot be, because it models nothing: whatever
    /// PowerShell's quoting rules are or become, a substring that is not present cannot be tokenized.
    ///
    /// The negative controls are carried in [`HOSTILE_PATHS`] for the same reason — this test would
    /// pass just as happily if the path were dropped on the floor, so the companion test below pins
    /// that the beacon still arrives, exactly, by the other route.
    #[test]
    fn no_install_path_can_become_powershell_tokens() {
        for path in HOSTILE_PATHS {
            let elevation = elevated_command(
                "windows",
                Path::new(path),
                &Change::argv(Change::Enable(true)),
            )
            .expect("windows has an elevation route");
            let command = elevation.args.last().expect("the -Command string");

            // Not merely "the whole path is absent": any run of it long enough to carry a payload is
            // absent too, so a partial splice cannot pass. The `C:\dig` prefix these share is what the
            // truncated command received, and it is the one fragment allowed to be checked loosely.
            for fragment in [path, path.trim_start_matches("C:\\dig")] {
                assert!(
                    fragment.is_empty() || !command.contains(fragment),
                    "{fragment:?} of the install path is spliced into a command PowerShell will \
                     parse, so it is being offered to a tokenizer: {command}"
                );
            }
            assert!(
                !command.contains('\''),
                "the command quotes something, which means it is escaping a value again: {command}"
            );
        }
    }

    /// **…and the beacon still arrives, byte for byte, by the environment.**
    ///
    /// The companion to the absence assertion above, and not optional: "the path is not in the command
    /// string" is satisfied perfectly by a function that forgets the path entirely. This pins the
    /// value's actual delivery, unmodified — no escaping applied, so the negative controls in
    /// [`HOSTILE_PATHS`] cannot have been mangled into a path that names nothing.
    #[test]
    fn the_beacon_reaches_the_elevator_unmodified_through_the_environment() {
        for path in HOSTILE_PATHS {
            let elevation = elevated_command(
                "windows",
                Path::new(path),
                &Change::argv(Change::Enable(true)),
            )
            .expect("windows has an elevation route");

            let delivered = elevation
                .env
                .iter()
                .find(|(name, _)| name == BEACON_PATH_VAR)
                .map(|(_, value)| value.as_str());
            assert_eq!(
                delivered,
                Some(path),
                "the beacon must reach the elevator exactly as located, neither escaped nor lost"
            );
            assert!(
                elevation
                    .args
                    .last()
                    .expect("the -Command string")
                    .contains(&format!("$env:{BEACON_PATH_VAR}")),
                "the command must still refer to it, or the elevator runs nothing"
            );
        }
    }

    /// A reading, distinguishable from the next one so a stale answer cannot pass for a fresh one.
    fn reading(channel: UpdateChannel) -> Option<BeaconStatus> {
        Some(BeaconStatus {
            paused: false,
            schedule_opted_out: false,
            channel,
        })
    }

    /// **A minute of repaints asks the beacon about once every [`BEACON_REFRESH`], not once a
    /// repaint.**
    ///
    /// The defect this pins is not a wrong answer, it is a FREQUENCY: reading the beacon inside the
    /// per-repaint view rebuild spawned `dig-updater` about 120 times a minute and, on Windows,
    /// flashed a console window every time (dig_ecosystem#2311). Every value the function returned
    /// was correct throughout, which is why no assertion on its output could have caught it — the
    /// count is the property.
    ///
    /// Sixty seconds of a real repaint rate, not a token few: the expected number has to be big
    /// enough that "cached forever" and "correct cadence" are different answers. A cache that never
    /// refreshed would give 1, and per-repaint reading gives 120.
    #[test]
    fn a_minute_of_repaints_spawns_the_beacon_on_the_refresh_cadence() {
        const REPAINTS_PER_SECOND: u32 = 2;
        const SECONDS: u32 = 60;

        let cache = BeaconCache::default();
        let start = std::time::Instant::now();
        let mut fetches = 0_u32;

        for repaint in 0..(REPAINTS_PER_SECOND * SECONDS) {
            let now = start
                + std::time::Duration::from_millis(
                    u64::from(repaint) * 1000 / u64::from(REPAINTS_PER_SECOND),
                );
            cache.read(now, || {
                fetches += 1;
                reading(UpdateChannel::Stable)
            });
        }

        let expected = SECONDS / u32::try_from(BEACON_REFRESH.as_secs()).unwrap();
        assert_eq!(
            fetches,
            expected,
            "{SECONDS}s of repainting {REPAINTS_PER_SECOND}x a second asked the beacon {fetches} \
             times; on a {}s cadence it should be {expected}",
            BEACON_REFRESH.as_secs()
        );
        assert!(
            fetches < REPAINTS_PER_SECOND * SECONDS,
            "the reader still runs once per repaint, which is the defect itself"
        );
    }

    /// The refresh interval pinned from BOTH sides: one instant under it reuses, at it re-reads.
    ///
    /// A bound checked only from below is satisfied by a cache that never expires at all, which is
    /// its own defect — a switch moved outside DIG would never be seen to move.
    #[test]
    fn a_reading_is_reused_up_to_the_refresh_interval_and_not_past_it() {
        let cache = BeaconCache::default();
        let start = std::time::Instant::now();
        // A `Cell` shared by reference, not a `u32` captured into each closure: a `move` closure would
        // copy the counter and lose every increment, and a lost increment reads as "nothing was ever
        // fetched" — a zero that looks like the property holding perfectly.
        let fetches = std::cell::Cell::new(0);
        let fetch = |channel| {
            let fetches = &fetches;
            move || {
                fetches.set(fetches.get() + 1);
                reading(channel)
            }
        };

        cache.read(start, fetch(UpdateChannel::Stable));

        let just_under = start + BEACON_REFRESH - std::time::Duration::from_millis(1);
        assert_eq!(
            cache.read(just_under, fetch(UpdateChannel::Nightly)),
            reading(UpdateChannel::Stable),
            "a read one millisecond inside the interval must reuse the held reading"
        );

        assert_eq!(
            cache.read(start + BEACON_REFRESH, fetch(UpdateChannel::Nightly)),
            reading(UpdateChannel::Nightly),
            "a read AT the interval must ask the beacon again"
        );
        assert_eq!(
            fetches.get(),
            2,
            "exactly the first read and the expiring one"
        );
    }

    /// "Nobody answered" is cached too.
    ///
    /// The tempting shape — hold only `Some` readings — spawns the beacon on every single repaint for
    /// the one user who has no beacon installed, which is the exact population the console flash was
    /// worst for.
    #[test]
    fn an_unanswered_read_is_held_like_any_other() {
        let cache = BeaconCache::default();
        let start = std::time::Instant::now();
        let mut fetches = 0;

        for tick in 0..10 {
            let answer = cache.read(start + std::time::Duration::from_millis(tick * 100), || {
                fetches += 1;
                None
            });
            assert_eq!(answer, None);
        }
        assert_eq!(fetches, 1, "a `None` reading must be held, not re-asked");
    }

    /// An applied change does not wait out the interval.
    #[test]
    fn a_refresh_reads_immediately_and_becomes_what_later_repaints_see() {
        let cache = BeaconCache::default();
        let start = std::time::Instant::now();

        cache.read(start, || reading(UpdateChannel::Stable));
        assert_eq!(
            cache.refresh(start, || reading(UpdateChannel::Nightly)),
            reading(UpdateChannel::Nightly),
            "a refresh must ask even though the held reading is fresh"
        );
        assert_eq!(
            cache.read(start + std::time::Duration::from_millis(500), || panic!(
                "the refreshed reading should have been reused"
            )),
            reading(UpdateChannel::Nightly),
            "the next repaint must see what the refresh read"
        );
    }

    /// The explainer says the three things a person needs: how often, what is refused, and why a
    /// change asks for administrator.
    #[test]
    fn the_explainer_answers_the_questions_the_group_raises() {
        let body = explainer_body();
        assert!(body.contains("once a day"));
        assert!(body.contains("signature"));
        assert!(body.contains("administrator"));
        for channel in UpdateChannel::ALL {
            assert!(body.contains(channel.display_name()));
            assert!(body.contains(channel.description()));
        }
    }
}
