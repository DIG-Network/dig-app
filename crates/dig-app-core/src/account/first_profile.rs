//! The zero-profile fund-and-create prompt, and the once-a-day cadence that re-raises it
//! (dig_ecosystem#2950).
//!
//! # The user's sentence, and the three things it asks for
//!
//! *"when there are zero profiles there is supposed to be an automatic popout to fund your wallet to
//! create your first profile with a 'remind me later' button, that causes the popout to occur once a
//! day until the profile has been created"*
//!
//! Three obligations, and each is a separate way to get this wrong:
//!
//! 1. **It must be raisable at all.** The first-run wizard's gate reads the DID-only
//!    [`MintSeams`](crate::account::mint::MintSeams), which the binary hardcodes to
//!    `NoChainTransport` — deliberately, because a wired DID-only seam would let the wizard mint a
//!    DID *alone*, and a DIG profile is a DID singleton **and** a store. So this prompt is driven
//!    from the WHOLE-PROFILE seam instead
//!    ([`ProfileMintSeams`](crate::account::profile_mint::ProfileMintSeams), via
//!    [`ProfileCreation`]), which is the same reading the profiles card takes.
//! 2. **Once a day means once a day**, not once per launch. A person who opens the app five times
//!    before lunch must see it once, so the deferral is PERSISTED — a reminder held in memory is not
//!    a reminder — and a person who leaves the app open for a week must still be reminded, so the
//!    check runs on the tick as well as at start-up.
//! 3. **It must stop for good once a profile exists**, keyed on the profile REGISTRY rather than on
//!    a flag the prompt keeps about itself. A prompt that remembered its own completion would keep
//!    nagging an account whose profile was minted on another machine and synced here.
//!
//! # What it will NOT do, and why each refusal is the cheaper error
//!
//! **It never asks somebody to fund a ceremony that would refuse.** The prompt's whole content is
//! *send money here*, so raising it against a node that cannot complete a mint spends a person's
//! actual XCH on a wait that ends in a refusal. [`ProfileCreation::is_possible`] keys on the arm, so
//! an [`Unknown`](ProfileCreation::Unknown) node — nobody has asked it yet — withholds exactly as a
//! measured blocker does. That distinction is dig_ecosystem#2690's: an unmeasured node must not be
//! rendered as a broken one, and here it must not be rendered as a working one either.
//!
//! **It never reads a list it could not read as an empty one.** [`ProfilesReading`] has three
//! states and only [`Known`](ProfilesReading::Known) is an answer. Telling somebody with four
//! profiles that they have none, and then asking them to fund a fifth, is a claim about their
//! identity that no read supports.

use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::Deserialize;
use serde::Serialize;

use crate::account::profile_mint::whole_profile_cost_mojos;
use crate::account::profile_mint::DEFAULT_MINT_FEE_MOJOS;
use crate::confirm::ClaimPrompt;
use crate::profiles::ProfileCreation;
use crate::profiles::ProfilesReading;

/// The file the next-prompt time lives in, beside the DID ledger in the account's brand directory.
const REMINDER_FILE: &str = "first-profile-reminder.json";

/// How long a dismissal defers the prompt: one day, because that is the cadence the user asked for.
///
/// A single constant rather than a preference. The interval is the whole of what was requested, and
/// a knob here would be a way for the app to nag more often than a person agreed to.
pub const REMINDER_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Where the next-prompt time is kept.
///
/// A trait so the decision can be tested without a filesystem, and so the one write this feature
/// performs is visible at the call site rather than buried in a helper.
pub trait ReminderLedger {
    /// The time before which the prompt must not be raised, or `None` when it has never been
    /// deferred.
    ///
    /// `None` on an unreadable or absent file, deliberately. The two ways to be wrong are not
    /// symmetric: forgetting a deferral shows one extra prompt, while inventing one silently
    /// suppresses the feature for a day on every machine whose file is corrupt.
    fn deferred_until(&self) -> Option<SystemTime>;

    /// Record that the prompt must not be raised again before `at`. Returns whether it was stored.
    ///
    /// A `false` here means the next launch prompts again, which is the honest failure: the app
    /// would rather ask twice than silently stop asking.
    fn defer_until(&self, at: SystemTime) -> bool;
}

/// The stored reminder, as it sits on disk.
#[derive(Debug, Serialize, Deserialize)]
struct StoredReminder {
    /// Seconds since the Unix epoch. Stored as an absolute wall-clock instant rather than a
    /// remaining duration, because a duration would restart on every read and a machine that is
    /// closed each night would never reach the end of it.
    next_prompt_at_unix_secs: u64,
}

/// The reminder for the account housed in a brand directory.
///
/// Sits beside [`DidFile`](crate::account::did::DidFile), and for the same reason: it is a fact
/// about THIS installation's relationship to an account, not part of the account itself. Nothing
/// here is secret and nothing here is custody — losing the file costs one extra prompt.
pub struct ReminderFile {
    /// The file the next-prompt time lives in.
    path: PathBuf,
}

impl ReminderFile {
    /// The reminder for the account housed in `brand_dir`.
    pub fn new(brand_dir: &Path) -> Self {
        Self {
            path: brand_dir.join(REMINDER_FILE),
        }
    }
}

impl ReminderLedger for ReminderFile {
    fn deferred_until(&self) -> Option<SystemTime> {
        let raw = std::fs::read_to_string(&self.path).ok()?;
        let stored: StoredReminder = serde_json::from_str(&raw).ok()?;
        UNIX_EPOCH.checked_add(Duration::from_secs(stored.next_prompt_at_unix_secs))
    }

    fn defer_until(&self, at: SystemTime) -> bool {
        let Ok(since_epoch) = at.duration_since(UNIX_EPOCH) else {
            // A clock set before 1970. Storing nothing is right: the next launch asks again, which
            // is the behaviour of a machine that has never been prompted.
            return false;
        };
        let Some(dir) = self.path.parent() else {
            return false;
        };
        if std::fs::create_dir_all(dir).is_err() {
            return false;
        }
        let stored = StoredReminder {
            next_prompt_at_unix_secs: since_epoch.as_secs(),
        };
        match serde_json::to_string_pretty(&stored) {
            Ok(json) => std::fs::write(&self.path, json).is_ok(),
            Err(_) => false,
        }
    }
}

/// Why the prompt is being held back.
///
/// **One variant per REASON**, the rule [`CreationBlocked`](crate::profiles::CreationBlocked)
/// follows, so a log line names the actual cause. None of them is an error: every one is the prompt
/// working correctly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PromptHeld {
    /// The profile list has not been read, or could not be. **Not the same as zero profiles**, and
    /// the distinction is the whole reason [`ProfilesReading`] has three states.
    ProfilesNotRead,
    /// This account already has at least one profile, so the feature is finished here — permanently.
    /// Keyed on the registry, which is what makes it survive a reinstall and a sync from another
    /// machine.
    AlreadyHasAProfile,
    /// No node has said a whole profile can be minted here. Covers BOTH an unmeasured node and a
    /// measured blocker, because the prompt's answer to each is the same — say nothing — even though
    /// what a *surface* says about them differs (dig_ecosystem#2690).
    CreationNotPossible,
    /// The prompt was raised recently and dismissed. It comes back at `until`.
    Deferred {
        /// When the prompt may next be raised.
        until: SystemTime,
    },
}

/// Whether the zero-profile funding prompt should be raised right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirstProfilePrompt {
    /// Raise it. The account is enrolled, has no profiles, and a whole profile really can be minted.
    Raise,
    /// Do not raise it, and this is why.
    Held(PromptHeld),
}

impl FirstProfilePrompt {
    /// Whether the prompt should be put on screen.
    pub fn should_raise(&self) -> bool {
        matches!(self, Self::Raise)
    }
}

/// Decide whether to raise the fund-and-create prompt.
///
/// A pure function of four readings, which is what makes the once-a-day rule testable without
/// waiting a day: `now` is the clock seam, and the caller in the binary passes
/// [`SystemTime::now`].
///
/// # The order of the checks is part of the answer
///
/// Each guard is asked before the ones that would be a lie in its state:
///
/// 1. An unread list first, because *zero profiles* is a claim only a `Known` reading supports.
/// 2. An existing profile next, so a person who already has one is never told anything about
///    creation, funding or a node — the feature is simply over for them.
/// 3. Creation's availability third. Only now is *fund your wallet* a sentence that could come
///    true, so only now may the absence of a working node suppress it.
/// 4. The deferral last, because it is the one reason that is about the PROMPT rather than about
///    the account — and a deferral shadowing a permanent stop would keep re-asking a question that
///    had already been answered.
pub fn first_profile_prompt(
    profiles: &ProfilesReading,
    creation: ProfileCreation,
    reminder: &dyn ReminderLedger,
    now: SystemTime,
) -> FirstProfilePrompt {
    let Some(rows) = profiles.rows() else {
        return FirstProfilePrompt::Held(PromptHeld::ProfilesNotRead);
    };
    if !rows.is_empty() {
        return FirstProfilePrompt::Held(PromptHeld::AlreadyHasAProfile);
    }
    // Keys on the ARM, never on `blocked().is_none()`: `Unknown` has no reason to name, so a
    // `blocked`-derived answer would read *nobody has asked* as *yes, you can mint* and send someone
    // to fund a ceremony against a node that has never answered (dig_ecosystem#2690).
    if !creation.is_possible() {
        return FirstProfilePrompt::Held(PromptHeld::CreationNotPossible);
    }
    match reminder.deferred_until() {
        Some(until) if now < until => FirstProfilePrompt::Held(PromptHeld::Deferred { until }),
        _ => FirstProfilePrompt::Raise,
    }
}

/// Push the next prompt one [`REMINDER_INTERVAL`] out from `now`.
///
/// # Why this is called when the prompt is RAISED, not when the button is pressed
///
/// "Remind me later" is one of several ways a prompt leaves the screen; closing the window is
/// another, and on a machine whose shell kills the dialog there is a third. Deferring only on the
/// button would mean every other exit re-prompts on the next launch — which is exactly the
/// once-per-launch behaviour the user asked us to replace, and the one they would notice.
///
/// So the deferral is written when the prompt goes UP. Every dismissal path then yields the same
/// cadence, and the failure mode of a crash mid-prompt is one skipped day rather than a nag loop.
pub fn defer_for_a_day(reminder: &dyn ReminderLedger, now: SystemTime) -> bool {
    reminder.defer_until(now + REMINDER_INTERVAL)
}

/// What a whole profile costs today, in mojos — the number this prompt puts on screen.
///
/// Derived from the SAME expression [`ProfileMint::cost_mojos`](crate::account::profile_mint::ProfileMint::cost_mojos)
/// charges under, at the same default fee, so a displayed cost cannot come to be lower than what is
/// spent. `the_prompt_quotes_what_the_door_charges` holds the two together.
pub fn first_profile_cost_mojos() -> u64 {
    whole_profile_cost_mojos(DEFAULT_MINT_FEE_MOJOS)
}

/// The prompt itself: what a profile is, what it costs, where to send it, and a real way to say
/// later.
///
/// Public for the reason [`funding_claim`](crate::account::journey::funding_claim) is: the
/// screenshot gallery photographs THIS screen rather than a retyped copy of it, and a photograph of
/// retyped copy is a photograph of a second implementation.
pub fn first_profile_claim<'a>(address: &'a str, body: &'a str) -> ClaimPrompt<'a> {
    ClaimPrompt {
        title: copy::TITLE,
        heading: copy::HEADING,
        body,
        affirm: copy::COPY_ADDRESS,
        decline: Some(copy::LATER),
        // Neither control spends anything and neither is a claim about the world, so a bare Enter
        // may safely take the friendly one — copying an address to the clipboard.
        refusal_is_default: false,
        scannable: None,
        identifier: Some(address),
    }
}

/// The prompt's words.
///
/// # The one thing this copy may never do
///
/// **Round the cost, or describe it as free.** This screen asks for money, so the figure on it is
/// the figure the ceremony charges — [`first_profile_cost_mojos`], derived from the door's own
/// arithmetic. A placeholder here would be the app lying about money, which is the one class of
/// defect that stops a release outright.
pub mod copy {
    /// The window title.
    pub const TITLE: &str = "DIG — Create your first profile";
    /// The question being put to the user.
    pub const HEADING: &str = "Fund your wallet to create your first profile";
    /// The affirming control: copies the receiving address.
    pub const COPY_ADDRESS: &str = "Copy my address";
    /// The declining control, in the user's own words.
    pub const LATER: &str = "Remind me later";

    /// Said after the address reaches the clipboard.
    pub const COPIED_TITLE: &str = "DIG — Address copied";
    /// The heading of the copied notice.
    pub const COPIED_HEADING: &str = "Your receiving address is on the clipboard";
    /// The body of the copied notice.
    pub const COPIED_BODY: &str =
        "Paste it into your wallet to send XCH. DIG will offer to create your profile again \
         tomorrow, and the Profiles tab has the same address whenever you want it.";

    /// What the prompt says, with the real cost and the real address.
    ///
    /// Takes the cost rather than reading it, so the sentence and the charge cannot drift: the one
    /// caller passes [`super::first_profile_cost_mojos`], and a test asserts that value equals what
    /// the door charges.
    pub fn body(address: &str, cost_mojos: u64) -> String {
        format!(
            "A profile is your on-chain identity — a DID and a store — that lets you publish, sign \
             for an app and be found by other people. This account does not have one yet.\n\n\
             Creating it costs {cost_mojos} mojos in blockchain fees, paid from this account's \
             wallet, so the wallet needs at least that much before it can be created. Send XCH \
             to:\n\n{address}\n\n\
             Your account already holds funds, receives at this address, and reads everything on \
             the DIG Network without a profile. Nothing is created and nothing is spent by this \
             window."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::CreationBlocked;
    use crate::profiles::ProfileRow;
    use crate::profiles::ProfilesUnknown;
    use dig_account::ProfileIx;
    use std::cell::RefCell;

    /// A ledger held in memory, so the cadence can be exercised without a filesystem.
    #[derive(Default)]
    struct Remembered {
        /// The stored instant, if any.
        until: RefCell<Option<SystemTime>>,
    }

    impl ReminderLedger for Remembered {
        fn deferred_until(&self) -> Option<SystemTime> {
            *self.until.borrow()
        }

        fn defer_until(&self, at: SystemTime) -> bool {
            *self.until.borrow_mut() = Some(at);
            true
        }
    }

    /// A ledger that cannot store anything — the corrupt-file and read-only-disk case.
    struct Forgets;

    impl ReminderLedger for Forgets {
        fn deferred_until(&self) -> Option<SystemTime> {
            None
        }

        fn defer_until(&self, _at: SystemTime) -> bool {
            false
        }
    }

    /// A fixed instant, so nothing in these tests reads the wall clock.
    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    /// A list that answered, holding no profiles — the state every new account is in.
    fn no_profiles() -> ProfilesReading {
        ProfilesReading::Known(Vec::new())
    }

    /// A list that answered, holding one profile.
    fn one_profile() -> ProfilesReading {
        ProfilesReading::Known(vec![ProfileRow {
            ix: ProfileIx::ROOT,
            did: "did:chia:1example".to_owned(),
            label: None,
            hidden: false,
            active: true,
        }])
    }

    /// The ordinary case the whole ticket is about: enrolled, no profiles, a node that can mint.
    #[test]
    fn a_zero_profile_account_with_a_working_node_is_prompted() {
        assert_eq!(
            first_profile_prompt(
                &no_profiles(),
                ProfileCreation::Possible,
                &Remembered::default(),
                t0()
            ),
            FirstProfilePrompt::Raise
        );
    }

    /// **The stop condition is the REGISTRY.** An account holding a profile is never prompted again,
    /// whatever the reminder file says — which is what makes a profile minted on another machine and
    /// synced here end the prompt on this one.
    #[test]
    fn an_account_holding_a_profile_is_never_prompted_again() {
        let never_deferred = Remembered::default();

        assert_eq!(
            first_profile_prompt(
                &one_profile(),
                ProfileCreation::Possible,
                &never_deferred,
                t0()
            ),
            FirstProfilePrompt::Held(PromptHeld::AlreadyHasAProfile)
        );
    }

    /// **An unread list is not an empty one.** Both non-answers hold the prompt, and neither is
    /// reported as an account with no profiles.
    ///
    /// This is the guard that stops a person with four profiles being asked to fund a fifth while
    /// their registry is merely still loading.
    #[test]
    fn a_list_that_did_not_answer_never_reads_as_zero_profiles() {
        for unread in [
            ProfilesReading::Pending,
            ProfilesReading::Unknown(ProfilesUnknown::Unreadable("a truncated file".to_owned())),
        ] {
            assert_eq!(
                first_profile_prompt(
                    &unread,
                    ProfileCreation::Possible,
                    &Remembered::default(),
                    t0()
                ),
                FirstProfilePrompt::Held(PromptHeld::ProfilesNotRead),
                "{unread:?} was treated as an account with no profiles"
            );
        }
    }

    /// **Never ask for money the ceremony would refuse.** Every non-`Possible` creation arm holds
    /// the prompt — including `Unknown`, which is a node nobody has spoken to rather than a broken
    /// one (dig_ecosystem#2690).
    ///
    /// `Unknown` is the arm that matters here. It answers `blocked() == None`, so any guard written
    /// against `blocked()` would have raised a funding prompt against a node that has never
    /// answered — fail-open on a path that costs real XCH.
    #[test]
    fn a_node_that_cannot_mint_a_profile_is_never_asked_for_money() {
        let mut withheld = vec![ProfileCreation::Unknown];
        withheld.extend(CreationBlocked::EVERY.map(ProfileCreation::Blocked));

        for creation in withheld {
            assert_eq!(
                first_profile_prompt(
                    &no_profiles(),
                    creation,
                    &Remembered::default(),
                    t0()
                ),
                FirstProfilePrompt::Held(PromptHeld::CreationNotPossible),
                "{creation:?} reached a funding prompt"
            );
        }
    }

    /// **The cadence, proved by a clock seam rather than by waiting.**
    ///
    /// One dismissal, then three readings of the same ledger: a moment later, a minute before the
    /// day is up, and the moment it is. The middle one is the assertion that matters — a deferral
    /// that expired early would still pass a test that only checked "later".
    #[test]
    fn a_dismissed_prompt_returns_after_a_day_and_not_before() {
        let reminder = Remembered::default();
        assert!(defer_for_a_day(&reminder, t0()));

        let due = t0() + REMINDER_INTERVAL;
        for (when, expected) in [
            (t0() + Duration::from_secs(1), false),
            (due - Duration::from_secs(60), false),
            (due, true),
            (due + Duration::from_secs(1), true),
        ] {
            let verdict = first_profile_prompt(
                &no_profiles(),
                ProfileCreation::Possible,
                &reminder,
                when,
            );
            assert_eq!(
                verdict.should_raise(),
                expected,
                "at {:?} after the dismissal the prompt should_raise()=={expected}, got {verdict:?}",
                when.duration_since(t0()).expect("a later instant")
            );
        }
    }

    /// **Five launches inside one day show the prompt once.**
    ///
    /// The property the user asked for in the words they used, driven the way a person drives it:
    /// the app starts, the prompt goes up, the deferral is written, and every restart that day finds
    /// it held. Without the write-on-raise this passes only for the "Remind me later" button and
    /// fails for the close button — which is the once-per-launch behaviour being replaced.
    #[test]
    fn five_launches_in_a_day_raise_the_prompt_exactly_once() {
        let reminder = Remembered::default();
        let mut raised = 0;

        for launch in 0..5 {
            let now = t0() + Duration::from_secs(launch * 3600);
            if first_profile_prompt(&no_profiles(), ProfileCreation::Possible, &reminder, now)
                .should_raise()
            {
                raised += 1;
                defer_for_a_day(&reminder, now);
            }
        }

        assert_eq!(raised, 1, "five launches inside one day raised {raised} prompts");
    }

    /// A ledger that cannot store the deferral re-prompts rather than going silent.
    ///
    /// The safe direction, stated as a test because it is a choice and not an accident: a machine
    /// whose disk refuses the write asks again tomorrow, instead of losing the feature for good.
    #[test]
    fn an_unwritable_ledger_keeps_asking_rather_than_going_quiet() {
        assert!(!defer_for_a_day(&Forgets, t0()));
        assert!(first_profile_prompt(
            &no_profiles(),
            ProfileCreation::Possible,
            &Forgets,
            t0() + REMINDER_INTERVAL * 9
        )
        .should_raise());
    }

    /// The stored instant survives a round trip through a real file, which is what "survives a
    /// restart" means.
    ///
    /// An in-memory double proves the RULE and says nothing about the storage; this is the leg that
    /// speaks for the thing actually shipped.
    #[test]
    fn a_deferral_survives_a_round_trip_to_disk() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let due = t0() + REMINDER_INTERVAL;

        assert!(ReminderFile::new(dir.path()).defer_until(due));

        // A SECOND `ReminderFile` over the same directory, deliberately: one that reused the first
        // instance could pass on a value cached in memory, which is the very thing this asserts is
        // not happening.
        assert_eq!(ReminderFile::new(dir.path()).deferred_until(), Some(due));
    }

    /// An absent or corrupt reminder file reads as "never deferred", so the prompt still appears.
    ///
    /// Deliberately the fail-loud direction: inventing a deferral out of an unreadable file would
    /// suppress the feature on every machine whose file got truncated, and nobody would ever see it.
    #[test]
    fn an_unreadable_reminder_file_does_not_suppress_the_prompt() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let file = ReminderFile::new(dir.path());

        assert_eq!(file.deferred_until(), None, "an absent file deferred nothing");

        std::fs::write(dir.path().join(REMINDER_FILE), "{ this is not json").expect("written");
        assert_eq!(file.deferred_until(), None, "a corrupt file deferred nothing");
    }

    /// **The sentence on screen quotes what the door actually charges.**
    ///
    /// The prompt asks for money, so the number in it is the number the ceremony spends. Both sides
    /// are read here rather than compared against a literal, so a change to the fee moves them
    /// together or fails this test.
    #[test]
    fn the_prompt_quotes_what_the_door_charges() {
        let cost = first_profile_cost_mojos();
        assert_eq!(
            cost,
            whole_profile_cost_mojos(DEFAULT_MINT_FEE_MOJOS),
            "the prompt's cost is not the door's cost"
        );

        let body = copy::body("xch1example", cost);
        assert!(
            body.contains(&cost.to_string()),
            "the prompt does not state its cost: {body}"
        );
    }

    /// The prompt names the address it is asking money to be sent to, in the body AND as the
    /// identifier the window sets apart.
    ///
    /// A funding screen whose address appeared only in prose would be one the user has to
    /// hand-transcribe; one that appeared only as an identifier would lose it to a screen reader
    /// reading the body alone.
    #[test]
    fn the_prompt_shows_the_real_receiving_address() {
        let address = "xch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let body = copy::body(address, first_profile_cost_mojos());
        let claim = first_profile_claim(address, &body);

        assert!(body.contains(address), "the body does not carry the address");
        assert_eq!(claim.identifier, Some(address));
        assert_eq!(claim.decline, Some(copy::LATER));
    }
}
