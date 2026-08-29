//! Announce what the beacon installed — truthfully about whether it is RUNNING (dig-app#305).
//!
//! # What this module is, and the four things it deliberately is not
//!
//! `dig-updater` — the beacon — installs silently in the background and keeps the record. It runs as
//! a service (`\DIG\dig-updater`, or a systemd unit), and a service in session 0 **cannot draw a
//! toast for a logged-in user**. So the shape is the one the rest of this ecosystem already uses: the
//! headless service owns the record, a user-session surface reads it and notifies. This module is the
//! reader.
//!
//! It is **not** an update policy: dig_ecosystem#3180 decided the enterprise-normal pattern — silent
//! staged install, restart when convenient — so nothing here asks whether an install may happen, and
//! the *"would you like to install it now?"* offer and its modal were dropped with it. This is the
//! only routine user-facing update surface that survives.
//!
//! It is **not** a timing mechanism. [`crate::notify::gate`] owns when a person is told, how several
//! conditions coalesce, how long a notification may wait, and how the copy states its own age. A
//! second clock here would be a second answer to a question that already has one.
//!
//! It is **not** an installer, and it holds no opinion about `available`. The beacon's status mirror
//! reports what the feed OFFERS as well as what is installed; under the decided policy the offer will
//! be taken by the next pass regardless, so naming it to a person would be an interruption that
//! changes nothing.
//!
//! # The one rule the whole module exists to hold
//!
//! **"Installed" must not stand for "running".** `install.rs` replaces a *running* binary by renaming
//! the old image aside, so the new bytes sit at the destination while the old process keeps serving
//! until something restarts it. A toast reading *"dig-node 0.155.0 was installed"* while
//! `dign --version` still answers `0.154.0` states a falsehood about the machine.
//!
//! The beacon answers that question itself, in [`Activation`], and this module **renders that answer
//! and never infers one**. In particular [`Activation::Unknown`] gets its own sentence. It is the
//! default on the wire precisely so a record written by an older beacon degrades to *"I do not
//! know"*, and turning it into a confident *"and is now running"* here would re-create in the UI a
//! defect that took dig-updater three gate rounds to remove from its source.
//!
//! # Once per component per version, and never on first sight
//!
//! [`AnnouncedVersions`] is the ledger, and it fails closed exactly as [`crate::arrivals`] does: an
//! absent or unreadable record is an **adopt** state, not an empty one. A fresh machine has every
//! component new, and announcing six installs at first launch is how a person learns to dismiss these
//! without reading. So the first observation is recorded in silence and only a CHANGE speaks.
//!
//! # A version is announced once, describing what was true when it was seen
//!
//! The ledger is keyed on the version alone, so a component whose activation later moves from
//! `pending_restart` to `active` does **not** produce a second toast. The first one said what was
//! true when it was observed and said when it was observed; a follow-up would be the same news twice.

/// Reading and writing the announced-version ledger.
pub mod store;

/// The throttled reader that offers the announcement to the shared gate.
pub mod watch;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::notify::Notification;

/// The most components one status mirror may contribute to the ledger.
///
/// The beacon ships five (plus itself), so this is slack rather than a limit anybody meets. It is
/// here because the ledger is persisted and grows by union: without a bound, one garbled or hostile
/// `status.json` would write an arbitrarily large file that every later run must read.
const MAX_COMPONENTS: usize = 32;

/// The longest component name and version this surface will render.
///
/// Both reach a toast, and both come from a file on disk rather than from a constant in this binary.
/// They are capped and neutralised for the same reason every other caller-chosen string in this crate
/// is (see [`crate::confirm`]): a notification is a place where added lines and reordering controls
/// forge chrome.
const NAME_LIMIT: usize = 40;
/// The version cap. See [`NAME_LIMIT`].
const VERSION_LIMIT: usize = 32;

/// Whether a build that is on disk is the build that is actually RUNNING.
///
/// The three values are the beacon's own (`dig-updater-broker`'s `Activation`, serialised
/// `snake_case`), read here as a byte-identical wire contract rather than shared as a type — dig-app
/// does not depend on the beacon's crates, and reads its status mirror as JSON.
///
/// **[`Unknown`](Self::Unknown) is the default and every unrecognised token maps to it.** A value
/// this build has never heard of is a build it cannot make a claim about, and the only safe direction
/// to fail is towards saying less.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Activation {
    /// The newly installed build was confirmed to be the one now running.
    Active,
    /// The new build is on disk, but an older one is still running — a restart will pick it up.
    PendingRestart,
    /// Which build is running could not be established. NOT a synonym for either other value.
    #[default]
    Unknown,
}

impl Activation {
    /// Read the beacon's token. Anything else — a future value, a typo, a missing field — is
    /// [`Unknown`](Self::Unknown); see the type's docs for why that direction is the safe one.
    #[must_use]
    pub fn from_token(token: &str) -> Self {
        match token {
            "active" => Self::Active,
            "pending_restart" => Self::PendingRestart,
            _ => Self::Unknown,
        }
    }

    /// The clause that completes *"`<name>` `<version>` was installed"*, for one component.
    ///
    /// Each value gets its own sentence. None of them may be reachable from another's phrasing,
    /// which is what stops an unknown activation borrowing the confident wording of a measured one.
    #[must_use]
    pub fn sentence(self) -> &'static str {
        match self {
            Self::Active => "It is running now.",
            Self::PendingRestart => "It starts running the next time that component restarts.",
            Self::Unknown => "Whether it is running yet could not be determined.",
        }
    }

    /// The same fact as a short suffix, for the roll-up line of a multi-component announcement.
    #[must_use]
    pub fn short(self) -> &'static str {
        match self {
            Self::Active => "running now",
            Self::PendingRestart => "restart pending",
            Self::Unknown => "running build unknown",
        }
    }
}

/// One component's installed build, as the beacon reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledComponent {
    /// The component name (`dig-node`, `digstore`, …), neutralised and capped.
    pub name: String,
    /// The version on disk at that component's destination, neutralised and capped.
    pub version: String,
    /// Whether that version is the one actually running.
    pub activation: Activation,
}

/// Read the installed builds out of `dig-updater status --json`.
///
/// Total and forgiving in one direction only: anything unparseable yields an EMPTY list, which
/// announces nothing. A component with no `installed` object is skipped — the beacon writes that for
/// a pass that established no installed version (a dry check, or a component it deliberately did not
/// probe), and an absent version is not a version to announce.
///
/// `available` is read by nothing here; see the module docs.
#[must_use]
pub fn read_components(json: &[u8]) -> Vec<InstalledComponent> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(components) = value.get("components").and_then(|c| c.as_array()) else {
        return Vec::new();
    };
    components
        .iter()
        .filter_map(read_component)
        .take(MAX_COMPONENTS)
        .collect()
}

/// One entry of the `components` array, or `None` when it names no installed build.
fn read_component(entry: &serde_json::Value) -> Option<InstalledComponent> {
    let name = entry.get("component")?.as_str()?;
    let installed = entry.get("installed")?;
    let version = installed.get("version")?.as_str()?;
    // Absent activation is `unknown` — the beacon's own default, and the safe direction.
    let activation = installed
        .get("activation")
        .and_then(|a| a.as_str())
        .map_or(Activation::Unknown, Activation::from_token);
    Some(InstalledComponent {
        // Neutralised HERE, at the boundary, so nothing downstream holds a raw one. The fallbacks
        // are visible words rather than an empty string: a toast with a hole in it reads as a
        // rendering bug, and people dismiss rendering bugs.
        name: crate::confirm::neutralize_or(name, NAME_LIMIT, "an unnamed component"),
        version: crate::confirm::neutralize_or(version, VERSION_LIMIT, "an unnamed version"),
        activation,
    })
}

/// What one call to [`AnnouncedVersions::announce`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    /// The notification to offer the gate, or `None` when there is nothing new to say.
    pub notification: Option<Notification>,
    /// Whether the ledger moved and must be written back.
    ///
    /// Separate from `notification.is_some()` because **adoption changes the ledger while saying
    /// nothing**, and a run that forgot to persist an adoption would announce every component the
    /// next time it looked.
    pub changed: bool,
}

/// The record of which version of each component has already been announced on this machine.
///
/// `None` is the ADOPT state and is not the same as an empty map — see the module docs. It is what a
/// first run, a missing file and an unreadable file all produce.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnouncedVersions {
    #[serde(default)]
    announced: Option<BTreeMap<String, String>>,
}

impl AnnouncedVersions {
    /// The state that adopts the next observation in silence.
    #[must_use]
    pub fn unread() -> Self {
        Self { announced: None }
    }

    /// Whether this record has adopted an observation yet. For the tests and the store's logging.
    #[must_use]
    pub fn is_unread(&self) -> bool {
        self.announced.is_none()
    }

    /// Fold an observation in, and say what should be announced because of it.
    ///
    /// An unread record ADOPTS: every observed version is recorded and nothing is said. Afterwards a
    /// component speaks only when its version differs from the one last recorded for it — including
    /// when it moves DOWN, because a channel switch back to stable really does install an earlier
    /// build and a person who is not told will think DIG has broken.
    pub fn announce(&mut self, observed: &[InstalledComponent]) -> Announcement {
        let Some(announced) = self.announced.as_mut() else {
            self.announced = Some(
                observed
                    .iter()
                    .map(|c| (c.name.clone(), c.version.clone()))
                    .collect(),
            );
            return Announcement {
                notification: None,
                changed: true,
            };
        };

        let news: Vec<&InstalledComponent> = observed
            .iter()
            .filter(|c| announced.get(&c.name) != Some(&c.version))
            .collect();
        if news.is_empty() {
            return Announcement {
                notification: None,
                changed: false,
            };
        }
        let notification = summarize(&news);
        for component in news {
            announced.insert(component.name.clone(), component.version.clone());
        }
        // The union is bounded by the same cap the reader applies, so one hostile status mirror
        // cannot grow the persisted file past what a legitimate one could.
        while announced.len() > MAX_COMPONENTS {
            let Some(oldest) = announced.keys().next().cloned() else {
                break;
            };
            announced.remove(&oldest);
        }
        Announcement {
            notification: Some(notification),
            changed: true,
        }
    }
}

/// Render one or more newly-installed components as a single notification.
///
/// One component reads as a sentence; several roll up into one toast that names each, because six
/// toasts the instant somebody touches the mouse is the behaviour the gate exists to prevent, and the
/// gate can only coalesce ACROSS conditions — every install shares one [`crate::notify::HoldKey`], so
/// coalescing WITHIN this one is this function's job.
///
/// The copy never says when the install happened, only what it was: this process observed the
/// beacon's record, and the record carries no per-component install time. The gate supplies the
/// honest half of that sentence — *"detected N ago"*, measured from when this observation was made —
/// and inventing an install time to go beside it would be asserting something nothing measured.
fn summarize(news: &[&InstalledComponent]) -> Notification {
    if let [only] = news {
        return Notification {
            title: format!("DIG — {} was updated", only.name),
            body: format!(
                "{} {} was installed. {}",
                only.name,
                only.version,
                only.activation.sentence()
            ),
            // No route: there is nothing in dig-app to open about this. Where a restart is wanted it
            // is a restart of the component named, not of a screen here, and sending somebody to an
            // arbitrary tab is worse than sending them nowhere (see `notify::Route`).
            route: None,
        };
    }
    let lines = news
        .iter()
        .map(|c| format!("• {} {} — {}", c.name, c.version, c.activation.short()))
        .collect::<Vec<_>>()
        .join("\n");
    Notification {
        title: format!("DIG — {} components were updated", news.len()),
        body: lines,
        route: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(name: &str, version: &str, activation: Activation) -> InstalledComponent {
        InstalledComponent {
            name: name.to_string(),
            version: version.to_string(),
            activation,
        }
    }

    /// A status mirror in the beacon's real shape, with `installed`/`available` as separate fields.
    fn mirror(components: &str) -> Vec<u8> {
        format!(r#"{{"paused":false,"channel":"stable","components":[{components}]}}"#).into_bytes()
    }

    // ----------------------------------------------------------------------------------------
    // Reading the beacon's record
    // ----------------------------------------------------------------------------------------

    /// **Each of the three activation tokens survives the wire as its own value.**
    ///
    /// One case per token rather than one token asserted, because the defect this whole module
    /// guards against is two values collapsing into one — which a single-token test cannot see.
    #[test]
    fn every_activation_token_is_read_as_itself() {
        let json = mirror(
            r#"{"component":"a","action":"update","result":"installed","detail":"",
                "installed":{"version":"1.0.0","activation":"active"}},
               {"component":"b","action":"update","result":"installed","detail":"",
                "installed":{"version":"2.0.0","activation":"pending_restart"}},
               {"component":"c","action":"update","result":"installed","detail":"",
                "installed":{"version":"3.0.0","activation":"unknown"}}"#,
        );
        let read = read_components(&json);
        assert_eq!(
            read,
            vec![
                component("a", "1.0.0", Activation::Active),
                component("b", "2.0.0", Activation::PendingRestart),
                component("c", "3.0.0", Activation::Unknown),
            ]
        );
    }

    /// **An activation this build does not recognise is `unknown`, never `active`.**
    ///
    /// The two inputs are the two real ways it happens: a beacon older than the field (which omits
    /// it) and a beacon newer than this build (which sends a value invented after this build shipped).
    /// Both must land on the value that claims least. The `active` control is what makes the
    /// assertion load-bearing — without it a `from_token` that returned `Unknown` for EVERYTHING
    /// would pass, and that implementation announces every install as unknown forever.
    #[test]
    fn an_unrecognised_activation_is_unknown_and_never_active() {
        let older = mirror(
            r#"{"component":"a","action":"u","result":"i","detail":"",
                "installed":{"version":"1.0.0"}}"#,
        );
        assert_eq!(read_components(&older)[0].activation, Activation::Unknown);

        let newer = mirror(
            r#"{"component":"a","action":"u","result":"i","detail":"",
                "installed":{"version":"1.0.0","activation":"restarting_soon"}}"#,
        );
        assert_eq!(read_components(&newer)[0].activation, Activation::Unknown);

        // The control: a token this build DOES know still reads as itself, so the two assertions
        // above are about the unknown tokens and not about a reader that answers `Unknown` always.
        let known = mirror(
            r#"{"component":"a","action":"u","result":"i","detail":"",
                "installed":{"version":"1.0.0","activation":"active"}}"#,
        );
        assert_eq!(read_components(&known)[0].activation, Activation::Active);
    }

    /// **A component with no installed build is skipped, and the ones beside it are not.**
    ///
    /// A dry check reports a component without an `installed` object. Dropping the whole read on one
    /// such entry would silence a real install standing next to it, so the second component is the
    /// assertion that matters here.
    #[test]
    fn a_component_with_no_installed_build_is_skipped_without_losing_its_neighbour() {
        let json = mirror(
            r#"{"component":"dry","action":"would_fetch","result":"staged","detail":""},
               {"component":"real","action":"update","result":"installed","detail":"",
                "installed":{"version":"9.9.9","activation":"active"}}"#,
        );
        let read = read_components(&json);
        assert_eq!(read, vec![component("real", "9.9.9", Activation::Active)]);
    }

    /// **Anything that is not a status mirror announces nothing.**
    ///
    /// Each of these is a real failure mode of asking the beacon: it is not installed (empty body),
    /// it failed (an error object), it is a future shape, or the file was truncated mid-write.
    #[test]
    fn a_body_that_is_not_a_status_mirror_yields_no_components() {
        for body in [
            &b""[..],
            br#"{"status":"error","detail":"nope"}"#,
            br#"{"components":"not an array"}"#,
            br#"{"components":[{"component":"a","installed":"#,
            b"not json at all",
        ] {
            assert!(read_components(body).is_empty(), "{body:?}");
        }
    }

    /// **A name or version that forges layout is neutralised before it can reach a toast.**
    ///
    /// The version string travels from a file on disk into a notification body. A newline in it adds
    /// a line to the toast, and an added line is a complete sentence a person reads as DIG's own.
    #[test]
    fn a_forged_name_cannot_add_lines_to_the_toast() {
        let json = mirror(
            r#"{"component":"dig-node\n\nVerified by DIG","action":"u","result":"i","detail":"",
                "installed":{"version":"1.0.0‮gninnur ton","activation":"active"}}"#,
        );
        let read = read_components(&json);
        assert!(!read[0].name.contains('\n'), "{:?}", read[0].name);
        assert!(!read[0].version.contains('\u{202e}'), "{:?}", read[0].version);

        // And the neutralised values are what reach the rendered body.
        let mut ledger = AnnouncedVersions {
            announced: Some(BTreeMap::new()),
        };
        let body = ledger
            .announce(&read)
            .notification
            .expect("a first announcement")
            .body;
        assert!(!body.contains('\n'), "{body}");
        assert!(!body.contains('\u{202e}'), "{body}");
    }

    /// **The number of components one mirror can contribute is bounded.**
    ///
    /// The ledger is persisted, so an unbounded read is an unbounded file that every later run must
    /// parse. The fixture is deliberately over the cap rather than at it.
    #[test]
    fn a_mirror_cannot_contribute_more_components_than_the_cap() {
        let entries: Vec<String> = (0..MAX_COMPONENTS + 20)
            .map(|i| {
                format!(
                    r#"{{"component":"c{i}","action":"u","result":"i","detail":"",
                        "installed":{{"version":"1.0.0","activation":"active"}}}}"#
                )
            })
            .collect();
        assert_eq!(
            read_components(&mirror(&entries.join(","))).len(),
            MAX_COMPONENTS
        );
    }

    // ----------------------------------------------------------------------------------------
    // The ledger
    // ----------------------------------------------------------------------------------------

    /// **A first sight adopts in silence, and it is PERSISTED as an adoption.**
    ///
    /// Both halves matter and they fail differently: without the silence a fresh machine announces
    /// every component at first launch, and without `changed` the adoption is never written and the
    /// next run announces them anyway.
    #[test]
    fn a_first_sight_is_adopted_silently_and_must_be_written_back() {
        let mut ledger = AnnouncedVersions::unread();
        let outcome = ledger.announce(&[
            component("dig-node", "0.154.0", Activation::Active),
            component("digstore", "0.27.0", Activation::Active),
        ]);
        assert_eq!(outcome.notification, None, "a fresh machine says nothing");
        assert!(outcome.changed, "the adoption must be persisted");
        assert!(!ledger.is_unread());
    }

    /// **After adoption, an unchanged observation says nothing AND writes nothing.**
    ///
    /// This is the ordinary case — the watch re-reads the same record all day. `changed` being false
    /// is what stops it rewriting the ledger on every pass.
    #[test]
    fn an_unchanged_observation_is_silent_and_writes_nothing() {
        let observed = [component("dig-node", "0.154.0", Activation::Active)];
        let mut ledger = AnnouncedVersions::unread();
        ledger.announce(&observed);

        let outcome = ledger.announce(&observed);
        assert_eq!(outcome.notification, None);
        assert!(!outcome.changed);
    }

    /// **A new version announces exactly once, then goes quiet.**
    ///
    /// The second call is the assertion: a ledger that announced but failed to RECORD would re-toast
    /// the same install on every pass, which on a fifteen-minute cadence is ninety-six times a day.
    #[test]
    fn a_new_version_announces_once_and_not_again() {
        let mut ledger = AnnouncedVersions::unread();
        ledger.announce(&[component("dig-node", "0.154.0", Activation::Active)]);

        let updated = [component("dig-node", "0.155.0", Activation::Active)];
        let first = ledger.announce(&updated);
        let note = first.notification.expect("the new version is news");
        assert!(note.body.contains("0.155.0"), "{}", note.body);

        let second = ledger.announce(&updated);
        assert_eq!(second.notification, None, "announced twice");
        assert!(!second.changed);
    }

    /// **A version going DOWN is still news.**
    ///
    /// Switching from nightly back to stable really does install an earlier build. A ledger that only
    /// spoke for a HIGHER version would leave the person to discover the downgrade themselves, and
    /// "my version went backwards and nothing told me" reads as DIG having broken.
    #[test]
    fn a_downgrade_is_announced_too() {
        let mut ledger = AnnouncedVersions::unread();
        ledger.announce(&[component("dig-node", "0.156.0", Activation::Active)]);
        let note = ledger
            .announce(&[component("dig-node", "0.155.0", Activation::Active)])
            .notification
            .expect("a downgrade is a change the person must be told about");
        assert!(note.body.contains("0.155.0"), "{}", note.body);
    }

    /// **Only the component that moved is announced.**
    ///
    /// The fixture varies ONE of the two and keeps the other as a truthful control: a summarizer that
    /// simply named everything it was handed would pass a test where every component had moved.
    #[test]
    fn only_the_component_that_changed_is_named() {
        let mut ledger = AnnouncedVersions::unread();
        ledger.announce(&[
            component("dig-node", "0.154.0", Activation::Active),
            component("digstore", "0.27.0", Activation::Active),
        ]);
        let note = ledger
            .announce(&[
                component("dig-node", "0.155.0", Activation::Active),
                component("digstore", "0.27.0", Activation::Active),
            ])
            .notification
            .expect("one component moved");
        assert!(note.body.contains("dig-node"), "{}", note.body);
        assert!(
            !note.body.contains("digstore"),
            "the component that did not move was named: {}",
            note.body
        );
    }

    /// **Several installs in one pass are ONE toast that names each.**
    ///
    /// An overnight pass updates the whole set; delivering that as a burst the instant somebody
    /// touches the mouse is what the activity gate exists to prevent, and the gate cannot do it for
    /// us — every install shares one hold key.
    #[test]
    fn several_installs_coalesce_into_one_notification_naming_each() {
        let mut ledger = AnnouncedVersions::unread();
        ledger.announce(&[
            component("dig-node", "0.154.0", Activation::Active),
            component("digstore", "0.27.0", Activation::Active),
        ]);
        let note = ledger
            .announce(&[
                component("dig-node", "0.155.0", Activation::PendingRestart),
                component("digstore", "0.28.0", Activation::Active),
            ])
            .notification
            .expect("two components moved");
        assert_eq!(note.title, "DIG — 2 components were updated");
        assert!(note.body.contains("dig-node 0.155.0"), "{}", note.body);
        assert!(note.body.contains("digstore 0.28.0"), "{}", note.body);
        // And each keeps its OWN activation — the roll-up must not flatten two different facts into
        // one, which is the same collapse this module exists to prevent.
        assert!(note.body.contains("restart pending"), "{}", note.body);
        assert!(note.body.contains("running now"), "{}", note.body);
    }

    /// **The ledger cannot grow past the cap, however many passes it sees.**
    #[test]
    fn the_persisted_ledger_stays_bounded_across_passes() {
        let mut ledger = AnnouncedVersions::unread();
        ledger.announce(&[component("seed", "1.0.0", Activation::Active)]);
        for round in 0..4 {
            let batch: Vec<InstalledComponent> = (0..MAX_COMPONENTS)
                .map(|i| component(&format!("r{round}c{i}"), "1.0.0", Activation::Active))
                .collect();
            ledger.announce(&batch);
        }
        assert_eq!(ledger.announced.as_ref().unwrap().len(), MAX_COMPONENTS);
    }

    // ----------------------------------------------------------------------------------------
    // The copy
    // ----------------------------------------------------------------------------------------

    /// **Each activation renders its own sentence, and no two are the same.**
    ///
    /// This is the honesty rule stated as a test. Asserting the three strings individually would
    /// pass against an implementation that returned the reassuring one for two of the three, so the
    /// distinctness is asserted over the whole set.
    #[test]
    fn the_three_activations_read_differently_from_each_other() {
        let sentences = [
            Activation::Active.sentence(),
            Activation::PendingRestart.sentence(),
            Activation::Unknown.sentence(),
        ];
        let distinct: std::collections::BTreeSet<_> = sentences.iter().collect();
        assert_eq!(distinct.len(), 3, "two activations read the same: {sentences:?}");

        let shorts = [
            Activation::Active.short(),
            Activation::PendingRestart.short(),
            Activation::Unknown.short(),
        ];
        let distinct: std::collections::BTreeSet<_> = shorts.iter().collect();
        assert_eq!(distinct.len(), 3, "two activations read the same: {shorts:?}");
    }

    /// **An UNKNOWN activation never borrows the confident wording of a measured one.**
    ///
    /// The nearest wrong implementation is an `unwrap_or(Active)` somewhere on this path — six
    /// instances of an unknown rendered as a reassuring answer were fixed in this ecosystem in one
    /// week. So the assertion is not that the unknown copy contains a particular word, but that it
    /// does NOT contain the running claim, with the `Active` case as the control proving that claim
    /// is a thing this renderer can actually produce.
    #[test]
    fn an_unknown_activation_does_not_claim_the_build_is_running() {
        let mut ledger = AnnouncedVersions {
            announced: Some(BTreeMap::new()),
        };
        let unknown = ledger
            .announce(&[component("dig-node", "0.155.0", Activation::Unknown)])
            .notification
            .unwrap()
            .body;
        assert!(
            unknown.contains("could not be determined"),
            "the uncertainty must be stated, not omitted: {unknown}"
        );
        assert!(
            !unknown.contains("is running now"),
            "an unmeasured build was reported as running: {unknown}"
        );

        let mut ledger = AnnouncedVersions {
            announced: Some(BTreeMap::new()),
        };
        let active = ledger
            .announce(&[component("dig-node", "0.155.0", Activation::Active)])
            .notification
            .unwrap()
            .body;
        assert!(
            active.contains("is running now"),
            "the control: a measured build DOES make that claim, so the assertion above is about \
             the unknown case and not about a phrase this renderer never emits: {active}"
        );
    }

    /// **A PENDING RESTART says a restart is needed and does not claim the build is running.**
    #[test]
    fn a_pending_restart_asks_for_a_restart_rather_than_claiming_success() {
        let mut ledger = AnnouncedVersions {
            announced: Some(BTreeMap::new()),
        };
        let body = ledger
            .announce(&[component("dig-node", "0.155.0", Activation::PendingRestart)])
            .notification
            .unwrap()
            .body;
        assert!(body.contains("restarts"), "{body}");
        assert!(!body.contains("It is running now"), "{body}");
    }

    /// **No rendered sentence has a hole torn through it.**
    ///
    /// The defect no substring assertion can see (see [`crate::copy_hygiene`]): every word present,
    /// in the right order, with eighteen spaces in the middle.
    #[test]
    fn the_update_copy_is_not_torn() {
        let mut rendered: Vec<String> = Vec::new();
        for activation in [
            Activation::Active,
            Activation::PendingRestart,
            Activation::Unknown,
        ] {
            rendered.push(activation.sentence().to_string());
            rendered.push(activation.short().to_string());
            let mut ledger = AnnouncedVersions {
                announced: Some(BTreeMap::new()),
            };
            let note = ledger
                .announce(&[component("dig-node", "0.155.0", activation)])
                .notification
                .unwrap();
            rendered.push(note.title);
            rendered.push(note.body);
        }
        for text in &rendered {
            assert_eq!(crate::copy_hygiene::torn_run(text), None, "{text}");
        }
    }
}
