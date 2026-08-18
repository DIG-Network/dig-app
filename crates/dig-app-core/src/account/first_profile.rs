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
//!    [`MintSeams`](crate::account::chain_mint::MintSeams), which the binary hardcodes to
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
use crate::confirm::ConfirmDecision;
use crate::confirm::QrArt;
use crate::profiles::ProfileCreation;
use crate::profiles::ProfilesReading;
use crate::wallet::overview::BalanceReading;

/// The file the next-prompt time lives in, beside the DID ledger in the account's brand directory.
const REMINDER_FILE: &str = "first-profile-reminder.json";

/// How long a dismissal defers the prompt: one day, because that is the cadence the user asked for.
///
/// A single constant rather than a preference. The interval is the whole of what was requested, and
/// a knob here would be a way for the app to nag more often than a person agreed to.
pub const REMINDER_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// The shortest gap between two node-hitting balance reads the "Recheck balance" control will make.
///
/// A held or repeatedly-clicked button must not become a request storm against a node that is
/// already the suspect. Five seconds is long enough that no human clicking produces load worth
/// naming, and short enough that somebody watching for a transfer never feels blocked — a Chia block
/// is about 52 seconds, so nothing can arrive faster than this anyway.
///
/// When it bites, the window SAYS so ([`copy::checked_recently`]) rather than silently doing
/// nothing, because a press that produces no visible change is exactly the failure this control
/// exists to rule out.
pub const RECHECK_THROTTLE: Duration = Duration::from_secs(5);

/// Whether a recheck asked for at `now` should actually hit the node.
///
/// `Err(seconds_ago)` when the last read is too recent to repeat, carrying how long ago it was so the
/// window can say it. A monotonic clock is not required: a `now` that went backwards yields
/// `duration_since` failing, which is treated as *long enough ago* — the fail-open direction here is
/// one extra read, and the fail-closed one would wedge the button permanently on a machine whose
/// clock was corrected.
pub fn recheck_allowed(last_read_at: Option<SystemTime>, now: SystemTime) -> Result<(), u64> {
    let Some(last) = last_read_at else {
        return Ok(());
    };
    match now.duration_since(last) {
        Ok(since) if since < RECHECK_THROTTLE => Err(since.as_secs()),
        _ => Ok(()),
    }
}

/// How many CONSECUTIVE self-dismissals of the deposit window are watched automatically.
///
/// The window carries its own two-minute deadline, so five of them is about ten minutes of watching
/// with nobody touching anything — enough to cover a realistic funding round trip (open another
/// wallet or a phone, send, come back), which is the whole reason the automatic re-draw exists.
///
/// It is BOUNDED because the window is not free while it is up. The tray's action worker is a single
/// slot held for the whole of a handler, so an unbounded re-raise silently swallows **"Lock now"** —
/// and since the idle window is a full day (dig_ecosystem#2953), `Lock now` is the only immediate way
/// a person can re-seal their session. Eating it is eating the escape hatch.
///
/// The same re-raise also outlasts the idle auto-lock (the tick takes the session with a `try_lock` it
/// skips on contention), which keeps key material resident past the window — a smaller concern now
/// that the window is 24 hours, but the same fix answers both. Returning gives both back, and nothing
/// is lost: the daily reminder was already written when this prompt was raised, so the prompt comes
/// back on its own cadence.
pub const DEPOSIT_SELF_DISMISSALS_WATCHED: u32 = 5;

/// How many drawings of the deposit window are watched in TOTAL, however they are answered.
///
/// [`DEPOSIT_SELF_DISMISSALS_WATCHED`] counts CONSECUTIVE self-dismissals and a press of "Recheck
/// balance" resets it — correctly, because that bound exists to end an *unattended* watch. But it
/// means a person pressing recheck against a wallet that never funds is never bounded at all, and the
/// costs named on that constant (the held action slot, the swallowed `Lock now`) are the same whether
/// the window is attended or not. This is the backstop for that case, and the two bounds answer
/// different failure modes rather than one being a weaker form of the other.
///
/// Twenty is well past any legitimate funding round trip: the window carries its own two-minute
/// deadline, so twenty drawings is at least forty minutes, and reaching it via `Approve` means twenty
/// deliberate presses. It is deliberately much larger than the consecutive bound so an unattended
/// window still ends on the tighter one.
pub const DEPOSIT_DRAWINGS_MAX: u32 = 20;

/// The total cap is a BACKSTOP, not a replacement: an unattended window must still end on the tighter
/// consecutive bound. Checked at compile time, because the relationship between the two constants is a
/// property of the constants themselves and a build that violated it should not exist.
const _: () = assert!(DEPOSIT_DRAWINGS_MAX > DEPOSIT_SELF_DISMISSALS_WATCHED);

/// What one drawing of the deposit window produced.
pub enum DepositWatch {
    /// The window was drawn, and the user — or its own deadline — answered.
    Answered(ConfirmDecision),
    /// Nothing was asked, because the wallet can now pay. The flow is over.
    Funded,
}

/// Drive the deposit window until it is done, re-drawing while it self-dismisses.
///
/// `draw` produces one drawing of the window; `recheck` answers a press of "Recheck balance" and
/// returns whether the whole flow is finished. Every exit path RETURNS, which is the property that
/// matters to the rest of the app (see [`DEPOSIT_SELF_DISMISSALS_WATCHED`]).
///
/// Two bounds run at once, and they answer different failure modes:
///
/// - [`DEPOSIT_SELF_DISMISSALS_WATCHED`] counts CONSECUTIVE self-dismissals, and an `Approve` RESETS
///   it deliberately — a press is a live human standing at the window, and that bound exists to end
///   an UNATTENDED watch, not to time out somebody who is still there.
/// - [`DEPOSIT_DRAWINGS_MAX`] counts EVERY drawing and nothing resets it, so the attended case is
///   bounded too. Without it, a person pressing "Recheck balance" against a wallet that never funds
///   holds the tray's single action slot indefinitely.
///
/// The throttle in [`recheck_allowed`] bounds node READS; it never bounded this loop.
pub fn watch_for_the_deposit(
    mut draw: impl FnMut() -> DepositWatch,
    mut recheck: impl FnMut() -> bool,
) {
    let mut self_dismissals = 0;
    let mut drawings = 0;
    loop {
        let DepositWatch::Answered(decision) = draw() else {
            return;
        };
        drawings += 1;
        if drawings >= DEPOSIT_DRAWINGS_MAX {
            return;
        }
        match decision {
            ConfirmDecision::Approve => {
                self_dismissals = 0;
                if recheck() {
                    return;
                }
            }
            // The window's own two-minute deadline elapsed: nobody pressed anything, so re-read and
            // redraw with whatever the balance now is — up to the bound.
            ConfirmDecision::Timeout => {
                self_dismissals += 1;
                if self_dismissals >= DEPOSIT_SELF_DISMISSALS_WATCHED {
                    return;
                }
            }
            // "Remind me later", Escape, or the frame's X — all one answer, and all already deferred.
            // `Unavailable` is a host with no desktop session to draw on, where continuing would spin.
            ConfirmDecision::Deny | ConfirmDecision::Unavailable => return,
        }
    }
}

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

/// What the app knows about the money that would PAY for a mint.
///
/// A narrowing of [`BalanceReading`] to the one question this flow asks, with the app's three-state
/// rule intact: **an unmeasured balance is not a zero balance**, and neither is a fault.
///
/// # Why this type exists rather than a bare `u64`
///
/// A shortfall is a claim about somebody's money. Computing one from a balance nobody read means a
/// deposit window telling a person they are short when the truth is that their node is not
/// answering — the absent-versus-zero collapse that showed a funded wallet as empty
/// (dig_ecosystem#2871). An `Option<u64>` would permit it by accident; this does not, because
/// [`Unmeasured`](Self::Unmeasured) has no number in it to subtract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintFunds {
    /// Nobody has measured the balance, or the read did not answer. **Not zero, and not a
    /// shortfall.**
    Unmeasured,
    /// A confirmed, spendable figure the chain actually answered with.
    ///
    /// # Confirmed, and deliberately not "confirmed plus what is on the way"
    ///
    /// Arrivals still in flight are excluded, because the gate this feeds opens a ceremony that
    /// SPENDS. Counting a submitted transfer would let the wizard open onto a mint whose funding
    /// coin does not exist yet, and dig-account would refuse it with the money apparently already
    /// there — the worst possible moment to be wrong.
    Measured {
        /// Spendable XCH, in mojos, as the chain answered it.
        spendable_mojos: u64,
    },
}

impl MintFunds {
    /// Narrow a wallet reading to the mint gate's question.
    ///
    /// [`BalanceReading::Pending`] and every [`BalanceReading::Unknown`] land on
    /// [`Unmeasured`](Self::Unmeasured) TOGETHER, and that is not a collapse of the distinction —
    /// the distinction is real and the wallet surface still draws it. It is that both answer this
    /// question identically: neither licenses a claim about how short somebody is. What the deposit
    /// window SAYS about the two differs, and it reads the original for that.
    pub fn of_balance(reading: &BalanceReading) -> Self {
        match reading {
            BalanceReading::Known { balances, .. } => Self::Measured {
                spendable_mojos: balances.xch_mojos(),
            },
            BalanceReading::Pending | BalanceReading::Unknown(_) => Self::Unmeasured,
        }
    }
}

/// Remembers that the wallet has ONCE been seen able to pay — the flow's hysteresis, in one place.
///
/// # Why a latch and not a second threshold
///
/// A balance can cross the mint cost and dip back under it without anybody spending anything: a coin
/// becomes momentarily unavailable, a replica answers from a slightly older height, a read lands
/// between two blocks. Without a latch each of those bounces the user between a deposit window and a
/// creation wizard, which is worse than either window being wrong — a screen that changes under
/// somebody's hands teaches them the app is broken.
///
/// The direction is deliberate and stated rather than tuned: **once sufficient, always sufficient,
/// for the life of this flow.** It is the safe direction because the ceremony itself re-checks — a
/// wizard opened on a balance that has since dipped refuses at the mint, honestly and without
/// spending, which costs one clear error message. The opposite error sends a funded person back to a
/// deposit screen to send money they have already sent.
///
/// It is cleared by the flow ENDING, never by a low reading: a minted profile stops the flow at
/// [`PromptHeld::AlreadyHasAProfile`], and "Remind me later" stops it at
/// [`PromptHeld::Deferred`], both of which are checked before the latch is ever consulted.
#[derive(Debug, Default)]
pub struct FundingLatch {
    /// Whether a sufficient balance has been observed.
    crossed: std::sync::atomic::AtomicBool,
}

impl FundingLatch {
    /// A latch that has seen nothing.
    pub const fn new() -> Self {
        Self {
            crossed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Whether the wallet has already been seen able to pay.
    pub fn has_crossed(&self) -> bool {
        self.crossed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Record that it has.
    pub fn note_crossed(&self) {
        self.crossed
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Forget, because the flow ended.
    pub fn reset(&self) {
        self.crossed
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// What the flow should be SHOWING, once it has been raised.
///
/// Split from [`first_profile_prompt`] deliberately: that decides whether to open the flow at all
/// and costs nothing, so the tick can ask it twice a second. This one needs a balance, which costs a
/// node round trip, so it is asked on the worker inside the flow rather than in the frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundingStep {
    /// The balance could not be measured. Say so — never a shortfall.
    Unmeasured,
    /// The wallet is short by this much, and cannot pay for a mint yet.
    Deposit {
        /// What the wallet actually holds, as measured. Carried on the variant rather than read
        /// again at the window, so the figure on screen is the one this decision was made from —
        /// and so a deposit window can only be built from a [`MintFunds::Measured`] reading, never
        /// from a balance nobody read (dig_ecosystem#2871).
        balance_mojos: u64,
        /// How many more mojos are needed. Never zero: at zero the step is
        /// [`Ready`](Self::Ready).
        shortfall_mojos: u64,
    },
    /// The wallet can pay. Open the create-profile wizard.
    Ready,
}

/// Decide what the flow shows for a funds reading.
///
/// `>=` rather than `>`: a wallet holding exactly the cost can pay exactly the cost.
///
/// The latch is consulted FIRST, so a wallet once seen sufficient never returns to a deposit
/// window — see [`FundingLatch`] for why that direction is the safe one.
pub fn funding_step(funds: &MintFunds, latch: &FundingLatch, cost_mojos: u64) -> FundingStep {
    if latch.has_crossed() {
        return FundingStep::Ready;
    }
    let MintFunds::Measured { spendable_mojos } = funds else {
        return FundingStep::Unmeasured;
    };
    match spendable_mojos.checked_sub(cost_mojos) {
        // `checked_sub` returning `Some` IS the comparison: the wallet covers the cost exactly when
        // subtracting it does not go negative. One expression rather than a `>=` beside a `-`, which
        // is how a boundary comes to be tested one way and computed the other.
        Some(_) => {
            latch.note_crossed();
            FundingStep::Ready
        }
        None => FundingStep::Deposit {
            balance_mojos: *spendable_mojos,
            shortfall_mojos: cost_mojos - spendable_mojos,
        },
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

/// The moment a balance was read, as the recheck answers name it: `14:03:22 UTC`.
///
/// # Why UTC, spelled out, rather than the user's own clock
///
/// This crate has no timezone database and no date library, so the only instant it can derive
/// honestly is the one the epoch counts. A bare `14:03:22` would be read as local time and be wrong
/// by hours for most people — a timestamp that lies is worse than none, because its whole job here
/// is to prove the read ran. Naming the zone costs four characters and makes it true everywhere.
///
/// Seconds resolution is deliberate: [`RECHECK_THROTTLE`] is five seconds, so two answerable presses
/// can never carry the same label.
pub fn read_at_label(now: SystemTime) -> String {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let day = secs % 86_400;
    format!(
        "{:02}:{:02}:{:02} UTC",
        day / 3600,
        (day % 3600) / 60,
        day % 60
    )
}

/// The prompt itself: what a profile is, what it costs, where to send it, and a real way to say
/// later.
///
/// Public for the reason [`funding_claim`](crate::account::journey::funding_claim) is: the
/// screenshot gallery photographs THIS screen rather than a retyped copy of it, and a photograph of
/// retyped copy is a photograph of a second implementation.
pub fn first_profile_claim<'a>(
    address: &'a str,
    body: &'a str,
    scannable: Option<&'a QrArt>,
) -> ClaimPrompt<'a> {
    ClaimPrompt {
        title: copy::TITLE,
        heading: copy::HEADING,
        body,
        affirm: copy::RECHECK,
        decline: Some(copy::LATER),
        // Neither control spends anything and neither is a claim about the world, so a bare Enter
        // may safely take the affirming one — asking the node for a fresh balance.
        refusal_is_default: false,
        scannable,
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
///
/// # One unit for the whole flow: XCH (dig_ecosystem#2950)
///
/// Every money figure this module renders goes through `chain_mint::xch`, the crate's single
/// mojos-to-XCH conversion. The deposit body and the three windows a person reaches FROM it — the
/// recheck answer, the unknown-balance window, the wallet-can-pay window — all describe the same
/// quantity, so quoting one of them in mojos makes the flow contradict itself about a price.
pub mod copy {
    use crate::account::chain_mint::xch;

    /// The window title.
    pub const TITLE: &str = "DIG — Create your first profile";
    /// The question being put to the user.
    pub const HEADING: &str = "Fund your wallet to create your first profile";
    /// The affirming control: asks the node for a FRESH balance.
    ///
    /// # Why a manual control exists beside an automatic one
    ///
    /// The window re-reads by itself every time its deadline elapses, so nobody has to press this
    /// for the flow to work. It is here because this node has a history of stalling SILENTLY — a
    /// replica frozen for hours while still reporting `synced` (dig_ecosystem#2851), a wedged
    /// service still answering HTTP (dig_ecosystem#2880) — and the automatic path renders every one
    /// of those as a window that simply never changes. A person staring at a stale figure needs a
    /// way to ask again that does not depend on the thing that is stuck.
    ///
    /// It changes WHEN the balance is read. It never changes what counts as funded.
    pub const RECHECK: &str = "Recheck balance";
    /// The declining control, in the user's own words. Dismisses the whole flow for a day.
    pub const LATER: &str = "Remind me later";

    /// Said when a recheck found the balance still short — with the moment it was read.
    ///
    /// # The read time is not decoration
    ///
    /// A press that changes nothing on screen is indistinguishable from a button that does nothing,
    /// and this button exists precisely for people who already suspect nothing is happening. The
    /// timestamp is the only part of the answer that is guaranteed to differ between two presses, so
    /// it is what proves the read ran.
    pub fn still_short(shortfall_mojos: u64, read_at: &str) -> String {
        format!(
            "Checked at {read_at}: this wallet is still {} short of what a profile costs. \
             Nothing has arrived yet, or what has arrived is not spendable — a transfer becomes \
             spendable once the blockchain confirms it, which usually takes a few minutes.",
            xch(shortfall_mojos)
        )
    }

    /// Said when a recheck could not measure the balance at all.
    ///
    /// The most likely reason somebody pressed the button, and the one the automatic path renders as
    /// silence. It names the fault the wallet reading named, so the remedy is the node's own rather
    /// than a generic outage, and it never states a shortfall — nothing was measured to be short by.
    pub fn cannot_measure(why: &str, read_at: &str) -> String {
        format!(
            "Checked at {read_at}: DIG could not read this wallet's balance, so it cannot say \
             whether the funds have arrived. This is about reading the balance, not about your \
             money — the address above is unaffected and anything sent to it is safe.\n\n{why}"
        )
    }

    /// Said when a recheck was asked for again too soon.
    ///
    /// States what it DID rather than pretending to have run: a button that silently ignored a press
    /// would be the same invisible no-op the recheck exists to rule out.
    pub fn checked_recently(seconds_ago: u64) -> String {
        format!(
            "DIG checked {seconds_ago} seconds ago and is not asking the node again yet. It \
             re-checks by itself while this window is open, and the answer above is from that last \
             read."
        )
    }

    /// The title over every recheck answer.
    pub const RECHECK_TITLE: &str = "DIG — Balance checked";
    /// The heading over every recheck answer.
    pub const RECHECK_HEADING: &str = "Here is what DIG found";

    /// What the prompt says, with the real cost.
    ///
    /// Takes the cost rather than reading it, so the sentence and the charge cannot drift: the one
    /// caller passes [`super::first_profile_cost_mojos`], and a test asserts that value equals what
    /// the door charges.
    ///
    /// # The address is deliberately NOT in here
    ///
    /// It is the prompt's [`identifier`](crate::confirm::ClaimPrompt::identifier), which the window
    /// draws set apart in Space Mono — the face that reads character by character, which is what an
    /// address needs and what prose wrapping at an arbitrary column destroys. An early revision put
    /// it in both, and the photograph showed the same 62 characters twice, one of them broken across
    /// a line: two addresses on a funding screen is an invitation to copy the wrong one.
    /// # Three figures, all in XCH (dig_ecosystem#2950)
    ///
    /// The balance is stated beside the cost because a person deciding how much to send has to do
    /// the subtraction otherwise, and the unit is XCH because that is the unit of the wallet they
    /// will send FROM. Every one is rendered by `chain_mint::xch`, this crate's single mojos-to-XCH
    /// conversion: a money figure has twice reached a screen here through the wrong divisor, and
    /// both times a second copy of the conversion was what let it through.
    pub fn body(balance_mojos: u64, shortfall_mojos: u64, cost_mojos: u64) -> String {
        format!(
            "A profile is your on-chain identity — a DID and a store — that lets you publish, sign \
             for an app and be found by other people. This account does not have one yet.\n\n\
             Creating one costs {}. This wallet holds {}, so it needs {} more before it can. Scan \
             the code or send XCH to the address below; DIG will notice when it arrives.\n\n\
             This window creates nothing and spends nothing. Reading the DIG Network never needs a \
             profile.",
            xch(cost_mojos),
            xch(balance_mojos),
            xch(shortfall_mojos)
        )
    }

    /// What the window says when the balance could not be measured AT ALL.
    ///
    /// # This is the window that must never become the deposit window
    ///
    /// A shortfall is a subtraction, and there is nothing here to subtract from: nobody has read
    /// this wallet. Rendering that as *you need funds* is the absent-versus-zero collapse that
    /// showed a funded wallet as empty (dig_ecosystem#2871), and on this screen it would be the app
    /// telling somebody with money that they have none — a claim about their money that no read
    /// supports. So this states the cost, states that the balance is unknown, names the node's own
    /// reason, and asks for nothing.
    pub fn unmeasured_body(why: &str, cost_mojos: u64) -> String {
        format!(
            "A profile is your on-chain identity — a DID and a store — that lets you publish, sign \
             for an app and be found by other people. This account does not have one yet.\n\n\
             Creating one costs {}. DIG cannot read this wallet's balance at the moment, so \
             it does not know whether that has already been sent — this is about reading the \
             balance, not about your money. Anything already sent to the address below is safe.\n\n\
             Choose {RECHECK} once the node is answering, or {LATER}.\n\n{why}",
            xch(cost_mojos)
        )
    }

    /// The title over the window shown when the wallet CAN pay.
    pub const READY_TITLE: &str = "DIG — Create your first profile";
    /// Its heading.
    pub const READY_HEADING: &str = "This wallet can pay for a profile";

    /// The affirming control on the ready window. It SPENDS, so it says so.
    ///
    /// Named for what pressing it does rather than for agreement: `OK` on a window that charges
    /// money is the shape of a control somebody presses to make a window go away.
    pub const CREATE: &str = "Create my profile";
    /// The declining control. Nothing is started and the funds stay where they are.
    pub const NOT_NOW: &str = "Not now";

    /// What the ready window says: the offer, and exactly what pressing it costs.
    ///
    /// # This sentence changed the moment the ceremony landed, and it had to
    ///
    /// It used to promise that *nothing has been spent* and that creation *arrives in a coming
    /// version*. Both were true of a build with no ceremony behind it and both became false the
    /// instant an affirming control could reach
    /// [`ProfileMintDoor::begin`](crate::account::profile_mint::ProfileMintDoor::begin) — a
    /// reassurance left standing beside a button that spends real XCH is the app lying about money.
    ///
    /// The promise survives only where it is still true: this WINDOW spends nothing, and declining
    /// spends nothing. Pressing [`CREATE`] does.
    ///
    /// # The resumption promise had to go, and its replacement is a warning
    ///
    /// It also used to say that a started creation *carries on, and DIG picks it up again*. Nothing
    /// picks it up: the driver always starts at
    /// [`begin`](crate::account::profile_mint::ProfileMintDoor::begin) and there is no advance-only
    /// path in this build. Told they could close it safely, a person would close it — and be left
    /// having paid for a creation this version cannot continue. So the sentence says the opposite of
    /// what it said, because the truth is the opposite.
    pub fn ready_body(cost_mojos: u64) -> String {
        format!(
            "This wallet now holds enough to create a profile. Creating one costs {}, taken from \
             this wallet when you choose {CREATE}.\n\n\
             DIG will submit two transactions — your identity, then its store — and wait for the \
             blockchain to confirm both. That usually takes a few minutes. Leave DIG running until \
             it says the profile is ready: this version can only START a creation, so one that is \
             interrupted cannot yet be picked back up, and the money it has already spent stays \
             spent.\n\n\
             Choosing {NOT_NOW} spends nothing and changes nothing.",
            xch(cost_mojos)
        )
    }

    /// The offer itself: the window whose affirming control spends real XCH.
    ///
    /// Public for the reason [`super::first_profile_claim`] is — the screenshot gallery photographs
    /// THIS window rather than a retyped copy of it.
    ///
    /// `refusal_is_default` is **true**, unlike the funding claim's: there the affirming control
    /// re-reads a balance, and here it spends. A bare Enter must not buy anything.
    pub fn create_offer(body: &str) -> crate::confirm::ClaimPrompt<'_> {
        crate::confirm::ClaimPrompt {
            title: READY_TITLE,
            heading: READY_HEADING,
            body,
            affirm: CREATE,
            decline: Some(NOT_NOW),
            refusal_is_default: true,
            scannable: None,
            identifier: None,
        }
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
            store_id: "0xexamplestore".to_owned(),
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
                first_profile_prompt(&no_profiles(), creation, &Remembered::default(), t0()),
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
            let verdict =
                first_profile_prompt(&no_profiles(), ProfileCreation::Possible, &reminder, when);
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

        assert_eq!(
            raised, 1,
            "five launches inside one day raised {raised} prompts"
        );

        // ...and the sixth launch, the next day, is prompted again — because the profile still does
        // not exist. Without this the test passes for an implementation that raised the prompt once
        // and then never again, which is a different feature from the one that was asked for.
        let tomorrow = t0() + REMINDER_INTERVAL;
        assert!(
            first_profile_prompt(
                &no_profiles(),
                ProfileCreation::Possible,
                &reminder,
                tomorrow
            )
            .should_raise(),
            "the prompt did not come back the next day"
        );
    }

    /// **The live machine's own balance opens the wizard, and never builds a deposit body.**
    ///
    /// The fixture is the figure measured on the user's machine — 1.599 XCH against a 20,002-mojo
    /// cost, some 80,000x over — because that is what ships to them, and a deposit window there
    /// would be the app telling a funded person they have no money.
    ///
    /// It is driven from a whole [`BalanceReading`] rather than from a [`MintFunds`], which is the
    /// point: every other funding test starts at the narrowed type and so cannot see a mistake in
    /// the narrowing itself. The nearest wrong implementation — one that read the DIG figure, or a
    /// pending arrival, or defaulted a `Known` to unmeasured — is invisible to those and fails here.
    ///
    /// The assertion is written as an exhaustive match rather than an equality so that the failure
    /// message can carry the shortfall the code would have PUT ON SCREEN.
    #[test]
    fn the_measured_live_balance_opens_the_wizard_rather_than_a_deposit_window() {
        use crate::wallet::engine::BalanceAsOf;
        use crate::wallet::overview::Balances;

        let funded = BalanceReading::Known {
            balances: Balances::of_xch_and_dig(1_599_179_999_973, 0),
            as_of: BalanceAsOf::Replica {
                height: 9_150_343,
                caught_up: true,
            },
        };

        let funds = MintFunds::of_balance(&funded);
        assert_eq!(
            funds,
            MintFunds::Measured {
                spendable_mojos: 1_599_179_999_973
            },
            "a measured, spendable balance was narrowed to something else"
        );

        match funding_step(&funds, &FundingLatch::new(), first_profile_cost_mojos()) {
            FundingStep::Ready => {}
            FundingStep::Deposit {
                shortfall_mojos, ..
            } => panic!(
                "a wallet holding 1.599 XCH was asked for {shortfall_mojos} more mojos before it \
                 could create a profile"
            ),
            FundingStep::Unmeasured => {
                panic!("a balance the node answered with was reported as unmeasured")
            }
        }
    }

    /// **A cold cache draws no window at all until something has been read.**
    ///
    /// [`BalanceReading::default`] is what every not-yet-populated snapshot carries — the first
    /// frames of a launch, and a poisoned status lock. The flow reaches this state before its forced
    /// read has landed, so what it means here decides what the very first draw of the window says.
    ///
    /// `Deposit` is the wrong answer and `Ready` is the dangerous one: the first would tell a funded
    /// person they are short, the second would open a ceremony on a balance nobody has read.
    #[test]
    fn a_cold_cache_is_unmeasured_and_is_neither_a_shortfall_nor_a_go_ahead() {
        let cold = BalanceReading::default();
        assert_eq!(
            MintFunds::of_balance(&cold),
            MintFunds::Unmeasured,
            "an unpopulated reading carried a figure"
        );
        assert_eq!(
            funding_step(
                &MintFunds::of_balance(&cold),
                &FundingLatch::new(),
                first_profile_cost_mojos()
            ),
            FundingStep::Unmeasured
        );
    }

    /// The unmeasured window states the cost and the node's reason, and claims nothing about money.
    #[test]
    fn the_unmeasured_window_names_a_reason_and_never_a_shortfall() {
        const WHY: &str = "DIG could not reach a node.";
        let body = copy::unmeasured_body(WHY, first_profile_cost_mojos());

        assert!(
            body.contains(WHY),
            "the node's own reason is missing: {body}"
        );
        assert!(
            body.contains("0.000000020002 XCH"),
            "the cost is missing: {body}"
        );
        assert!(
            !body.contains("short") && !body.contains("needs"),
            "an unmeasured balance was rendered as a shortfall: {body}"
        );
    }

    /// **The ready window OFFERS the creation, states what pressing it costs, and no longer
    /// promises that nothing will be spent.**
    ///
    /// The negative half is what changed and is the load-bearing one. This window's affirming
    /// control now reaches `ProfileMintDoor::begin`, so the reassurance it used to carry — *nothing
    /// was started and NOTHING HAS BEEN SPENT* — became a sentence sitting beside a button that
    /// spends real XCH. A stale promise on a money window is the one defect class that stops a
    /// release, and it is exactly the kind that survives a feature landing because nobody re-reads
    /// the copy.
    ///
    /// The forward-looking promise goes for the same reason: creation no longer *arrives in a
    /// coming version*, it is on the screen.
    #[test]
    fn the_ready_window_offers_the_creation_and_drops_the_stale_no_spend_promise() {
        let body = copy::ready_body(first_profile_cost_mojos());

        assert!(
            body.contains("0.000000020002 XCH"),
            "the cost is missing: {body}"
        );
        assert!(
            body.contains(copy::CREATE),
            "the window must name the control that spends: {body}"
        );
        for stale in [
            "NOTHING HAS BEEN SPENT",
            "coming version",
            "cannot run the creation",
            "untouched",
        ] {
            assert!(
                !body.contains(stale),
                "the window still carries {stale:?}, which is false now that it can spend: {body}"
            );
        }
    }

    /// **The offer does not promise that an interrupted creation will be picked back up.**
    ///
    /// Makes impossible: telling somebody it is safe to close the window, immediately above a
    /// control that spends real XCH on a creation nothing resumes. `create_profile` is the only
    /// driver, it always starts at `ProfileMintDoor::begin`, and there is no advance-only path in
    /// this build — so *"a creation that has started carries on, and DIG picks it up again"* was an
    /// instruction to lose money.
    ///
    /// The positive half is what keeps this from passing on an empty string, and it is also the
    /// only reason the negative half is safe to make: a window that merely dropped the promise
    /// would leave a person with no idea that quitting costs them.
    #[test]
    fn the_offer_does_not_promise_a_resumption_this_build_cannot_do() {
        let body = copy::ready_body(first_profile_cost_mojos());

        for promise in [
            "picks it up again",
            "carries on",
            "close the progress window at any time",
            "without cancelling anything",
        ] {
            assert!(
                !body.contains(promise),
                "the offer promised {promise:?}, and nothing resumes a stopped creation: {body}"
            );
        }
        assert!(
            body.contains("Leave DIG running") && body.contains("cannot yet be picked back up"),
            "the offer must say what an interruption actually costs: {body}"
        );
    }

    /// **The offer's default answer is the REFUSAL.**
    ///
    /// Makes impossible: a bare Enter buying a profile. The funding claim next door sets
    /// `refusal_is_default: false` — correctly, since its affirming control only re-reads a balance
    /// — and copying that posture onto a window that spends is a one-word difference nothing else
    /// would catch. Both controls are asserted present too, because a window with no decline is the
    /// trap `professional-ui` forbids.
    #[test]
    fn the_create_offer_never_spends_on_a_bare_enter() {
        let body = copy::ready_body(first_profile_cost_mojos());
        let offer = copy::create_offer(&body);

        assert!(offer.refusal_is_default, "Enter must not buy a profile");
        assert_eq!(offer.affirm, copy::CREATE);
        assert_eq!(offer.decline, Some(copy::NOT_NOW));

        // Control: the funding claim, whose affirming control spends nothing, keeps the opposite
        // posture — so this is a real distinction rather than a blanket rule.
        assert!(!first_profile_claim("xch1example", &body, None).refusal_is_default);
    }

    /// Two answerable presses can never carry the same read time.
    ///
    /// The label's whole job is to prove a read ran, so a resolution coarser than the throttle would
    /// make two legitimate presses indistinguishable — the invisible no-op, wearing a timestamp.
    #[test]
    fn two_presses_a_throttle_apart_are_labelled_differently() {
        let first = read_at_label(t0());
        let second = read_at_label(t0() + RECHECK_THROTTLE);

        assert_ne!(
            first, second,
            "two reads {RECHECK_THROTTLE:?} apart read alike"
        );
        assert!(
            first.ends_with(" UTC"),
            "the zone is unstated, so the time reads as local and is wrong for most people: {first}"
        );
        assert_eq!(
            first.len(),
            "00:00:00 UTC".len(),
            "unexpected shape: {first}"
        );
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

        assert_eq!(
            file.deferred_until(),
            None,
            "an absent file deferred nothing"
        );

        std::fs::write(dir.path().join(REMINDER_FILE), "{ this is not json").expect("written");
        assert_eq!(
            file.deferred_until(),
            None,
            "a corrupt file deferred nothing"
        );
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

        assert_eq!(
            cost, 20_002,
            "the whole-profile cost moved; the copy must move with it"
        );

        // The expected strings are computed from the requirement — 20,002 mojos IS
        // 0.000000020002 XCH, because a mojo is 10^-12 XCH — and NOT read off what the code emits.
        // The send dialog shipped `50000000 XCH` for 50,000,000 mojos precisely because its test
        // agreed with the code instead of with the arithmetic (dig_ecosystem#2950).
        let body = copy::body(2, cost - 2, cost);
        assert!(
            body.contains("0.000000020002 XCH"),
            "the prompt does not state its cost in XCH: {body}"
        );
        assert!(
            body.contains("0.000000000002 XCH"),
            "the prompt does not state the BALANCE the user has: {body}"
        );
        assert!(
            body.contains("0.00000002 XCH"),
            "the prompt does not state the SHORTFALL, which is the actionable half: {body}"
        );
    }

    /// **A figure a person is asked to send is never truncated to nothing.**
    ///
    /// The whole cost of a profile is 20,002 mojos — six orders of magnitude below the two decimal
    /// places money is usually shown to. A renderer that rounded, or that formatted to a fixed
    /// short precision, would put `0 XCH` on a window whose entire purpose is to say that something
    /// is still owed, and the person would read *nothing is needed* and close it.
    #[test]
    fn a_nonzero_requirement_is_never_rendered_as_zero() {
        let cost = first_profile_cost_mojos();

        for (balance, shortfall) in [(1, cost - 1), (2, cost - 2), (cost - 1, 1)] {
            let body = copy::body(balance, shortfall, cost);
            assert!(
                !body.contains("0 XCH"),
                "a figure collapsed to zero on a window asking for money: {body}"
            );
        }

        // The one figure that may legitimately read as zero is a balance that WAS measured and is
        // genuinely empty. That is a fact about the wallet, not a rounding artefact — and it is the
        // state the gallery photographs.
        assert!(
            copy::body(0, cost, cost).contains("0 XCH"),
            "a measured empty wallet did not say so"
        );

        // One mojo is the smallest thing that can be owed, and the case a rounding renderer loses
        // first.
        assert!(
            copy::body(cost - 1, 1, cost).contains("0.000000000001 XCH"),
            "a one-mojo shortfall did not survive being written down"
        );
    }

    /// **A real wallet's balance reads as the XCH it holds.**
    ///
    /// 1,599,179,999,973 mojos is a live figure from this project's own funded test wallet. Divided
    /// by the CAT divisor it would read as 1,599,179.999973 — the class of error that showed a `$DIG`
    /// holding nobody had (dig_ecosystem#2879) — and undivided it would read as one and a half
    /// trillion XCH.
    #[test]
    fn a_real_balance_reads_as_the_xch_it_is() {
        let cost = first_profile_cost_mojos();
        let balance = 1_599_179_999_973_u64;
        // Not a shortfall this wallet actually has — it could pay many times over — but the body is
        // asked to render that balance, and the string it produces is the thing under test.
        let body = copy::body(balance, cost, cost);

        assert!(
            body.contains("1.599179999973 XCH"),
            "a 1.599 XCH balance was not rendered as 1.599 XCH: {body}"
        );
        assert!(
            !body.contains("1599179999973"),
            "the balance was printed in mojos with an XCH label: {body}"
        );
    }

    /// **Every figure in this flow is XCH — the recheck answer included (dig_ecosystem#2950).**
    ///
    /// The defect this pins: a person read `0.000000020002 XCH` on the deposit window, pressed
    /// [`copy::RECHECK`], and was answered in grouped mojos. Same flow, same quantity, two units —
    /// the confusion class behind dig_ecosystem#2879. So the three neighbours of the deposit body
    /// are asserted TOGETHER, because a fix applied to one of them reads as complete on its own.
    ///
    /// The expected strings are computed from the requirement — a mojo is 10^-12 XCH, so 20,002
    /// mojos IS `0.000000020002 XCH` — and never read off what the code emits. The absence of the
    /// grouped form is asserted alongside, since a body that states BOTH units would satisfy every
    /// positive assertion here while being exactly the screen the user complained about.
    #[test]
    fn the_recheck_answer_and_both_cost_windows_speak_xch_not_mojos() {
        const COST: u64 = 20_002;
        const IN_XCH: &str = "0.000000020002 XCH";
        const GROUPED_MOJOS: &str = "20,002";

        assert_eq!(
            first_profile_cost_mojos(),
            COST,
            "the fixture no longer matches what a profile costs"
        );

        let sentences = [
            ("still_short", copy::still_short(COST, "14:32:07")),
            (
                "unmeasured_body",
                copy::unmeasured_body("DIG could not reach a node.", COST),
            ),
            ("ready_body", copy::ready_body(COST)),
        ];

        for (which, sentence) in sentences {
            assert!(
                sentence.contains(IN_XCH),
                "{which} did not state {COST} mojos as {IN_XCH}: {sentence}"
            );
            assert!(
                !sentence.contains(GROUPED_MOJOS),
                "{which} still quotes grouped mojos beside the XCH figure: {sentence}"
            );
            assert!(
                !sentence.contains("mojos"),
                "{which} still names mojos as its unit: {sentence}"
            );
        }
    }

    /// **The unmeasured window states no balance at all — not even zero.**
    ///
    /// Nobody read this wallet, so there is no figure to state. `0 XCH` here would be the app
    /// telling somebody with money that they have none (dig_ecosystem#2871/#2879), which is a claim
    /// about their money that no read supports.
    #[test]
    fn the_unmeasured_window_states_no_balance_figure() {
        let body = copy::unmeasured_body("DIG could not reach a node.", first_profile_cost_mojos());

        assert!(
            !body.contains("0 XCH"),
            "an unread balance was rendered as zero: {body}"
        );
        assert!(
            !body.contains("holds"),
            "the unmeasured window claimed what the wallet holds: {body}"
        );
    }

    /// **An unmeasured balance is never a shortfall.**
    ///
    /// The trap this rules out: a node that is not answering renders as a deposit window telling
    /// somebody they are short by an amount nobody measured. Every non-`Known` wallet reading —
    /// still fetching, and each distinct fault — must reach [`FundingStep::Unmeasured`], because
    /// none of them contains a number this flow is entitled to subtract from (dig_ecosystem#2871,
    /// #2690).
    #[test]
    fn a_balance_that_was_not_read_is_never_reported_as_a_shortfall() {
        use crate::wallet::overview::BalanceUnknown;

        let unread = [
            BalanceReading::Pending,
            BalanceReading::Unknown(BalanceUnknown::NoNode),
            BalanceReading::Unknown(BalanceUnknown::NodeTimedOut),
            BalanceReading::Unknown(BalanceUnknown::NoChainSource),
            BalanceReading::Unknown(BalanceUnknown::NodeCannotRead),
        ];

        for reading in unread {
            let funds = MintFunds::of_balance(&reading);
            assert_eq!(funds, MintFunds::Unmeasured, "{reading:?} carried a figure");
            assert_eq!(
                funding_step(&funds, &FundingLatch::new(), first_profile_cost_mojos()),
                FundingStep::Unmeasured,
                "{reading:?} produced a claim about how short the wallet is"
            );
        }
    }

    /// The gate at the boundary: one mojo under is short, exactly the cost is enough.
    ///
    /// The exact-cost case is the one an inequality typo gets wrong, and getting it wrong tells a
    /// funded person to send money they do not need.
    #[test]
    fn the_funding_gate_opens_at_exactly_the_cost() {
        let cost = first_profile_cost_mojos();

        assert_eq!(
            funding_step(
                &MintFunds::Measured {
                    spendable_mojos: cost - 1
                },
                &FundingLatch::new(),
                cost
            ),
            FundingStep::Deposit {
                balance_mojos: cost - 1,
                shortfall_mojos: 1
            }
        );
        assert_eq!(
            funding_step(
                &MintFunds::Measured {
                    spendable_mojos: cost
                },
                &FundingLatch::new(),
                cost
            ),
            FundingStep::Ready
        );
        assert_eq!(
            funding_step(
                &MintFunds::Measured { spendable_mojos: 0 },
                &FundingLatch::new(),
                cost
            ),
            FundingStep::Deposit {
                balance_mojos: 0,
                shortfall_mojos: cost
            }
        );
    }

    /// **The flow does not flap.** Once the wallet has been seen able to pay, a later dip does not
    /// send the user back to a deposit window.
    ///
    /// Driven as a sequence rather than asserted on the latch directly, because what is being
    /// guarded is the behaviour a person experiences — two windows trading places under their hands
    /// — not the flag's value.
    #[test]
    fn a_wallet_once_seen_funded_does_not_return_to_the_deposit_window() {
        let cost = first_profile_cost_mojos();
        let latch = FundingLatch::new();

        assert_eq!(
            funding_step(
                &MintFunds::Measured {
                    spendable_mojos: cost
                },
                &latch,
                cost
            ),
            FundingStep::Ready
        );

        // A coin momentarily unavailable, a replica answering from an older height, a read between
        // two blocks. None of these is somebody spending, and none may reopen the deposit window.
        for dipped in [
            MintFunds::Measured { spendable_mojos: 0 },
            MintFunds::Unmeasured,
        ] {
            assert_eq!(
                funding_step(&dipped, &latch, cost),
                FundingStep::Ready,
                "{dipped:?} after a sufficient reading reopened the deposit window"
            );
        }

        latch.reset();
        assert_eq!(
            funding_step(&MintFunds::Measured { spendable_mojos: 0 }, &latch, cost),
            FundingStep::Deposit {
                balance_mojos: 0,
                shortfall_mojos: cost
            },
            "a reset latch must forget, or the flow could never ask for funds again"
        );
    }

    /// The recheck throttle admits the first press, refuses a fast second, and admits one after the
    /// interval — and a backwards clock never wedges it shut.
    #[test]
    fn the_recheck_throttle_bites_briefly_and_never_permanently() {
        assert_eq!(
            recheck_allowed(None, t0()),
            Ok(()),
            "the first press was refused"
        );
        assert_eq!(
            recheck_allowed(Some(t0()), t0() + Duration::from_secs(1)),
            Err(1),
            "a press one second later hit the node"
        );
        assert_eq!(
            recheck_allowed(Some(t0()), t0() + RECHECK_THROTTLE),
            Ok(()),
            "a press at the interval was still refused"
        );
        assert_eq!(
            recheck_allowed(Some(t0() + Duration::from_secs(60)), t0()),
            Ok(()),
            "a clock correction wedged the button shut"
        );
    }

    /// Every recheck answer names the moment it was read.
    ///
    /// A press that changes nothing on screen is indistinguishable from a broken button, and this
    /// control exists for people who already suspect nothing is happening — so the read time, which
    /// is the one part guaranteed to differ between two presses, must be in every answer.
    #[test]
    fn every_recheck_answer_states_when_it_read() {
        const READ_AT: &str = "14:32:07";

        let answers = [
            copy::still_short(500, READ_AT),
            copy::cannot_measure("DIG could not reach a node.", READ_AT),
        ];

        for answer in answers {
            assert!(
                answer.contains(READ_AT),
                "a recheck answer does not say when it read: {answer}"
            );
        }

        // The unmeasured answer must not also state a shortfall — it has none to state.
        let unmeasured = copy::cannot_measure("DIG could not reach a node.", READ_AT);
        assert!(
            !unmeasured.contains("short"),
            "an unmeasured balance was reported as a shortfall: {unmeasured}"
        );

        // The throttled answer is the one that did NOT read, so it says how long ago instead of
        // pretending to a fresh time.
        let throttled = copy::checked_recently(2);
        assert!(
            throttled.contains('2') && throttled.contains("not asking"),
            "a throttled press did not say it declined to re-read: {throttled}"
        );
    }

    /// The address appears EXACTLY ONCE, as the identifier the window sets apart.
    ///
    /// Both directions are asserted. It must be present, or the funding screen names no destination;
    /// and it must not also be in the body, because the photograph of the revision that had both
    /// showed the same 62 characters twice with one copy broken across a line — two addresses on a
    /// screen asking for money is an invitation to copy the wrong one.
    #[test]
    fn the_prompt_shows_the_receiving_address_exactly_once() {
        let address = "xch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let body = copy::body(
            first_profile_cost_mojos() - 1_000,
            1_000,
            first_profile_cost_mojos(),
        );
        let qr = QrArt::encode(address);
        let claim = first_profile_claim(address, &body, qr.as_ref());

        assert_eq!(claim.identifier, Some(address));
        assert!(
            !body.contains(address),
            "the address is in the body as well as the identifier: {body}"
        );
        assert_eq!(claim.decline, Some(copy::LATER));
        assert_eq!(claim.affirm, copy::RECHECK);
    }

    /// **The QR encodes the address the mint will actually fund from, and nothing else.**
    ///
    /// The trap: a QR pointing at any other address silently sends money to a wallet the ceremony
    /// will not spend from, and the person has no way to see that from the picture. At zero profiles
    /// the funding index is `ProfileIx::ROOT`, which is why the address funded before minting is the
    /// one the first profile inherits — so the ONE address in this window has to be the one the
    /// caller was handed, carried through to both the code and the identifier without substitution.
    #[test]
    fn the_qr_and_the_identifier_carry_the_same_address() {
        let address = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";
        let body = copy::body(
            first_profile_cost_mojos() - 1_000,
            1_000,
            first_profile_cost_mojos(),
        );
        let qr = QrArt::encode(address);
        let claim = first_profile_claim(address, &body, qr.as_ref());

        assert_eq!(claim.identifier, Some(address));
        assert!(
            claim.scannable.is_some(),
            "the deposit window has no scannable code, which is half of what was asked for"
        );
        // The code is built from the SAME `&str` the identifier shows, so there is no second place
        // an address could enter this window. Asserting the pointer identity of the source rather
        // than decoding the matrix: what could realistically go wrong here is a caller passing two
        // different addresses, not `QrArt` mis-encoding one.
        assert!(std::ptr::eq(
            claim.identifier.expect("an identifier"),
            address
        ));
    }

    /// **No rendered copy string bakes source indentation into user-facing text.**
    ///
    /// A raw multi-line literal carries its source indentation into the rendered output, showing
    /// ragged gaps and extra spaces mid-sentence. `cargo fmt` can reflow continuations and
    /// reintroduce indentation with nobody editing the copy itself, so every copy function that
    /// renders a message must be guarded by this assertion. Use `\` line continuations and
    /// `\n\n\` paragraph breaks instead of raw strings.
    #[test]
    fn no_copy_string_carries_source_indentation() {
        let cost = first_profile_cost_mojos();

        let functions_and_outputs = vec![
            ("body", copy::body(0, cost, cost)),
            ("still_short", copy::still_short(100, "14:32:07")),
            (
                "cannot_measure",
                copy::cannot_measure("DIG could not read this wallet.", "14:32:07"),
            ),
            ("checked_recently", copy::checked_recently(5)),
            (
                "unmeasured_body",
                copy::unmeasured_body("DIG could not reach a node.", cost),
            ),
            ("ready_body", copy::ready_body(cost)),
        ];

        for (func_name, output) in functions_and_outputs {
            // Assert no run of 2+ consecutive spaces.
            assert!(
                !output.contains("  "),
                "{}() has consecutive spaces in its output: {:?}",
                func_name,
                output
            );

            // Assert no newline immediately followed by a space (source indentation after a line break).
            assert!(
                !output.contains("\n "),
                "{}() has source indentation after a line break: {:?}",
                func_name,
                output
            );
        }
    }

    /// A deposit window that answers from a script, counting how many times it was drawn.
    ///
    /// It gives up after [`RUNAWAY`] drawings so an unbounded re-raise fails as a WRONG COUNT rather
    /// than as a hung test — a hang is indistinguishable from a dead runner, and this defect is
    /// precisely "the loop never returns".
    struct WindowScript {
        answers: std::sync::Mutex<std::collections::VecDeque<ConfirmDecision>>,
        /// The answer once the script runs out — the self-dismissal, since that is what a window
        /// nobody is touching does forever.
        then: ConfirmDecision,
        drawings: std::sync::Mutex<u32>,
    }

    /// Far above any legitimate bound, so exceeding it can only mean the loop is unbounded.
    const RUNAWAY: u32 = 50;

    impl WindowScript {
        fn answering(answers: &[ConfirmDecision], then: ConfirmDecision) -> Self {
            Self {
                answers: std::sync::Mutex::new(answers.iter().copied().collect()),
                then,
                drawings: std::sync::Mutex::new(0),
            }
        }

        fn drawings(&self) -> u32 {
            *self.drawings.lock().unwrap()
        }
    }

    impl crate::confirm::NativeConfirmer for WindowScript {
        fn confirm_pair(&self, _prompt: &crate::confirm::PairPrompt<'_>) -> ConfirmDecision {
            unreachable!("the deposit window never pairs")
        }
        fn confirm_connect(&self, _prompt: &crate::confirm::ConnectPrompt<'_>) -> ConfirmDecision {
            unreachable!("the deposit window never connects")
        }
        fn confirm_sign(&self, _prompt: &crate::confirm::SignPrompt<'_>) -> ConfirmDecision {
            unreachable!("the deposit window never signs")
        }
        fn confirm_claim(&self, _prompt: &ClaimPrompt<'_>) -> ConfirmDecision {
            let mut drawings = self.drawings.lock().unwrap();
            *drawings += 1;
            if *drawings > RUNAWAY {
                return ConfirmDecision::Deny;
            }
            self.answers
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(self.then)
        }
    }

    /// Run the watch against `window`, counting a recheck press as `recheck_finishes`.
    fn watch(window: &WindowScript, recheck_finishes: bool) -> u32 {
        use crate::confirm::NativeConfirmer;

        watch_for_the_deposit(
            || {
                DepositWatch::Answered(
                    window.confirm_claim(&first_profile_claim("xch1t", "b", None)),
                )
            },
            || recheck_finishes,
        );
        window.drawings()
    }

    /// **A window nobody touches stops re-raising itself** (dig_ecosystem#2950).
    ///
    /// While it is up, the tray's single action slot is held and the tick that runs the idle
    /// auto-lock skips its `try_lock`, so an unbounded watch keeps key material resident and drops
    /// "Lock now" silently. The count is the observable: finite, and exactly the bound.
    #[test]
    fn an_unattended_deposit_window_stops_re_raising_itself() {
        let window = WindowScript::answering(&[], ConfirmDecision::Timeout);

        assert_eq!(
            watch(&window, false),
            DEPOSIT_SELF_DISMISSALS_WATCHED,
            "a window that only ever self-dismisses must be drawn exactly the bounded number of \
             times and then let go of the session"
        );
    }

    /// **A press of "Recheck balance" resets the bound**, because a bound on an UNATTENDED watch must
    /// not time out somebody who is standing at the window.
    #[test]
    fn a_recheck_press_resets_the_self_dismissal_bound() {
        let mut script =
            vec![ConfirmDecision::Timeout; DEPOSIT_SELF_DISMISSALS_WATCHED as usize - 1];
        script.push(ConfirmDecision::Approve);
        let window = WindowScript::answering(&script, ConfirmDecision::Timeout);

        assert_eq!(
            watch(&window, false),
            DEPOSIT_SELF_DISMISSALS_WATCHED * 2,
            "four self-dismissals and a press, then a FULL fresh run of self-dismissals — without \
             the reset the press would not clear the four already counted, and the watch would end \
             one drawing later at six"
        );
    }

    /// **An attended window is bounded too** (dig_ecosystem#2956).
    ///
    /// `DEPOSIT_SELF_DISMISSALS_WATCHED` counts CONSECUTIVE self-dismissals and an `Approve` resets
    /// it, so a person who keeps pressing "Recheck balance" against a wallet that never funds holds
    /// the tray's single action slot forever — measured at 51 drawings, stopped only by [`RUNAWAY`].
    /// The total cap is the backstop for exactly that case.
    #[test]
    fn a_forever_attended_deposit_window_stops_at_the_total_drawings_cap() {
        let window = WindowScript::answering(&[], ConfirmDecision::Approve);

        assert_eq!(
            watch(&window, false),
            DEPOSIT_DRAWINGS_MAX,
            "a window answered `Approve` forever, against a recheck that never finishes, must stop \
             at the TOTAL cap — the consecutive bound can never trip, because every press resets it"
        );
    }

    /// **A recheck that finishes the flow returns at once**, drawing the window only the once.
    #[test]
    fn a_recheck_that_finishes_the_flow_returns() {
        let window = WindowScript::answering(&[ConfirmDecision::Approve], ConfirmDecision::Timeout);

        assert_eq!(watch(&window, true), 1);
    }

    /// **"Remind me later" returns immediately** — the deferral was written when the prompt was
    /// raised, so there is nothing left to do.
    #[test]
    fn a_deferral_returns_immediately() {
        let window = WindowScript::answering(&[ConfirmDecision::Deny], ConfirmDecision::Timeout);

        assert_eq!(watch(&window, false), 1);
    }

    /// **A wallet that can already pay is asked nothing at all.**
    #[test]
    fn a_funded_wallet_draws_no_deposit_window() {
        let window = WindowScript::answering(&[], ConfirmDecision::Timeout);

        watch_for_the_deposit(
            || DepositWatch::Funded,
            || unreachable!("nothing to recheck"),
        );

        assert_eq!(window.drawings(), 0);
    }
}
