//! What the Wallet tab may say about a send, and when it may offer one (dig_ecosystem#2819).
//!
//! [`send`](crate::wallet::send) performs a send. This module is the half a person sees: the states a
//! send passes through, and the rule deciding whether the **Send** control can be pressed at all.
//!
//! # Why both live here rather than in the pane
//!
//! A pane cannot be tested against a real spend, and the bin that dispatches one cannot be tested at
//! all (`dig-app.rs` is a `main`, and dig_ecosystem#2377 is the record of what hides in one). So every
//! decision — is this destination payable, is this amount a number, is there enough money, is a send
//! already running, what did that error MEAN — is made here, where a test can put a wrong answer in
//! front of it. The pane draws the answer and returns the intent; it decides nothing.
//!
//! # The one rule that outranks the others
//!
//! **No state here may be read as money having moved.** A push a mempool accepted is
//! [`SendProgress::Pending`], never a success; a push the node never answered is
//! [`SendProgress::Unknown`], never a failure — see that variant for why the difference is worth a
//! whole state.

use dig_account::{PendingTransfer, TransferRequest, TransferStatus};

use crate::amount::{parse_asset_amount, AmountProblem};
use crate::wallet::overview::BalanceReading;
use crate::wallet::send::{SendError, DEFAULT_SEND_FEE_MOJOS};
use crate::wallet::state::Asset;

/// How far the current send has got, or that there is none.
///
/// Held in [`TrayView`](crate::tray_menu::TrayView) so the window repaints as it moves, and projected
/// into the pane. Every variant is a state a person is SHOWN, which is why `Unknown` exists as its own
/// arm rather than collapsing into `Failed`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SendProgress {
    /// No send is running. The form is offered.
    #[default]
    Idle,
    /// A send is being built and confirmed — the custody ceremony is in front of the person now.
    ///
    /// It covers the build as well as the signature because the two are one uninterruptible call
    /// ([`SendSession::send`](crate::wallet::send::SendSession::send) takes `self` by value), and a
    /// person cannot act differently in one than in the other.
    Signing,
    /// A mempool accepted the bundle and the chain has not settled it yet.
    ///
    /// `blocks_since_push` is carried so the wait is LEGIBLE: a Chia block is roughly 18.75 seconds,
    /// so a screen that only said "waiting" would be indistinguishable from a hang after a minute.
    Pending {
        /// The payment coin a person can look up themselves.
        payment_coin_id: String,
        /// Blocks the chain has produced since the push.
        blocks_since_push: u32,
    },
    /// The node was never able to say whether it took the bundle.
    ///
    /// **Not a failure.** The bundle may be sitting in a mempool right now, so the money may well be
    /// moving; rebuilding could pay the recipient twice
    /// ([`SendError::PushUnanswered`]). The only safe
    /// thing a person can do is keep watching, and the surface says exactly that.
    Unknown {
        /// The payment coin to watch. It exists even here, which is what makes watching possible.
        payment_coin_id: String,
        /// What went wrong asking, in the node's own words.
        detail: String,
    },
    /// The payment coin is buried on chain. This is the only state that means the money arrived.
    Confirmed {
        /// The payment coin id.
        payment_coin_id: String,
        /// The height it confirmed at.
        confirmed_height: u32,
    },
    /// The transfer is over and will never settle.
    ///
    /// # The two ways to arrive here are not the same statement
    ///
    /// [`of_error`](Self::of_error) reaches it BEFORE any broadcast — the build refused, the gate
    /// refused, the mempool refused, or the push provably never left. Nothing moved and nothing ever
    /// existed on chain.
    ///
    /// [`of_status`](Self::of_status) reaches it AFTER a push, from `dig-account`'s proof of death: a
    /// source coin was observed SPENT while the payment coin is absent, so these bytes can never be
    /// included. Something did happen on chain — just not this payment — and the person has a coin id
    /// worth looking up. `payment_coin_id` is what tells the two apart, and the surface MUST NOT tell
    /// the second one that no money has moved.
    Failed {
        /// Why, verbatim from whoever decided it — the mempool, the builder, or the custody gate.
        reason: String,
        /// The payment coin, present exactly when this transfer had been pushed.
        payment_coin_id: Option<String>,
    },
    /// The attempt fell over part-way and this app does not know how far it got.
    ///
    /// # Why a panic cannot be reported as a failure (dig_ecosystem#2895)
    ///
    /// [`AbandonedSend`] fires on an unwind from anywhere between building and the push returning,
    /// and a panic establishes only that this app stopped — never that nothing left. Reporting it as
    /// [`Failed`](Self::Failed) drew [`SEND_FAILED_BODY`], whose first words are *"Nothing was sent
    /// and no money has moved"*: a claim about the user's money made out of this app's own crash.
    ///
    /// It is deliberately NOT [`Unknown`](Self::Unknown), which would be the honest word but is
    /// [`in_flight`](Self::in_flight) and carries a payment coin id to watch. A panic yields no coin
    /// id, so `Unknown` would close the form for the process lifetime with nothing to check and no
    /// escape — `professional-ui`'s trap. So the form reopens and the sentence carries the warning
    /// instead: a person who may have sent money is told to look before sending again.
    Abandoned {
        /// Where the attempt was when it stopped, for the person and for a bug report.
        detail: String,
    },
}

impl SendProgress {
    /// Whether a send is running right now, so a second one must not be offered.
    ///
    /// `Unknown` counts. Its transfer's fate is undecided, and starting a fresh send while one may
    /// already be in a mempool is precisely how a recipient gets paid twice.
    pub fn in_flight(&self) -> bool {
        matches!(
            self,
            Self::Signing | Self::Pending { .. } | Self::Unknown { .. }
        )
    }

    /// Read a finished send's error as the state to show for it.
    ///
    /// The whole mapping is one match with no wildcard, so a new [`SendError`] variant cannot inherit
    /// another's meaning — and the one variant that is not a failure is the reason this is a function
    /// rather than `Failed { reason: error.to_string() }` at each call site.
    pub fn of_error(error: &SendError) -> Self {
        match error {
            SendError::PushUnanswered { pending, detail } => Self::Unknown {
                payment_coin_id: pending.payment_coin_id().to_string(),
                detail: detail.clone(),
            },
            SendError::Locked
            | SendError::WalletBehindActiveProfile(_)
            | SendError::Build(_)
            | SendError::Sign(_)
            | SendError::PeakUnreadable(_)
            // Provably never broadcast — see `PublishFailure::may_have_reached_a_mempool`. It is a
            // failure precisely so the person is not left unable to send over a bundle that does
            // not exist.
            | SendError::PushNotSent(_)
            | SendError::Rejected { .. } => Self::Failed {
                reason: error.to_string(),
                // No push survived, so there is no coin to look up. `None` is what lets the surface
                // say "no money has moved" here and NOT say it after a proof of death.
                payment_coin_id: None,
            },
        }
    }

    /// Read a poll of a pushed transfer as the state to show for it.
    ///
    /// `Awaiting` becomes [`Pending`](Self::Pending) and never anything hopeful: an accepted push is
    /// not a payment, and the number of blocks is what tells a person the wait is progressing.
    pub fn of_status(pending: &PendingTransfer, status: &TransferStatus) -> Self {
        match status {
            TransferStatus::Awaiting { blocks_since_push } => Self::Pending {
                payment_coin_id: pending.payment_coin_id().to_string(),
                blocks_since_push: *blocks_since_push,
            },
            TransferStatus::Confirmed(settled) => Self::Confirmed {
                payment_coin_id: settled.payment_coin_id().to_string(),
                confirmed_height: settled.confirmed_height(),
            },
            // A proof of death: the transfer WAS pushed, so the coin id goes with it.
            TransferStatus::Failed { reason } => Self::Failed {
                reason: reason.clone(),
                payment_coin_id: Some(pending.payment_coin_id().to_string()),
            },
        }
    }

    /// The state a just-accepted push is in, before anything has been polled.
    pub fn accepted(pending: &PendingTransfer) -> Self {
        Self::Pending {
            payment_coin_id: pending.payment_coin_id().to_string(),
            blocks_since_push: 0,
        }
    }
}

/// Why the **Send** control cannot be pressed.
///
/// A reason and not a bare `false`, because `professional-ui`'s never-trap rule makes an unexplained
/// grey control worse than an absent one: a person who cannot see the condition goes looking for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendBlocked {
    /// The account is sealed, so nothing can be built or signed.
    AccountSealed,
    /// A send is already running.
    AlreadySending,
    /// The destination field is empty. Said gently — an empty form is not a mistake.
    NoDestination,
    /// The destination is not a mainnet payment address. Carries dig-account's own words, which name
    /// the offending prefix rather than calling the address merely invalid.
    BadDestination(String),
    /// The amount field does not hold a number of XCH.
    BadAmount(AmountProblem),
    /// The amount plus the fee is more than the wallet is known to hold.
    ///
    /// Only ever reached from a MEASURED balance: a balance nobody has read blocks nothing, because
    /// refusing a send over a figure the app does not have would be inventing the figure.
    NotEnough {
        /// What the send would cost, in mojos, fee included.
        needed: u64,
        /// What the wallet holds, in mojos, as last read.
        spendable: u64,
    },
}

impl SendBlocked {
    /// The sentence shown under the refused control, naming the condition that lifts it.
    ///
    /// Written as whole sentences here rather than in the pane's copy module because they are about
    /// the RULE, and the rule is here — a second author would be free to write a sentence describing a
    /// condition this module does not actually check.
    pub fn sentence(&self) -> String {
        match self {
            Self::AccountSealed => "Unlock your account and Send becomes available.".to_string(),
            Self::AlreadySending => {
                "One payment is already on its way. Send again once it has settled.".to_string()
            }
            Self::NoDestination => {
                "Enter the address you are paying and the amount to send.".to_string()
            }
            Self::BadDestination(reason) => format!("That is not a payment address: {reason}"),
            Self::BadAmount(problem) => amount_sentence(*problem),
            Self::NotEnough { needed, spendable } => format!(
                "That is more than this wallet holds. The payment and its fee come to {} XCH, and \
                 the last reading was {} XCH.",
                crate::amount::format_asset_amount(Asset::Xch, *needed),
                crate::amount::format_asset_amount(Asset::Xch, *spendable)
            ),
        }
    }
}

/// What to say about an amount that is not a number of XCH.
///
/// Each problem gets its own sentence: someone who typed a thirteenth decimal place has a different
/// next move from someone who typed a word.
fn amount_sentence(problem: AmountProblem) -> String {
    match problem {
        AmountProblem::Empty => "Enter the amount of XCH to send.".to_string(),
        AmountProblem::NotANumber => {
            "Enter the amount as a plain number of XCH, like 0.25.".to_string()
        }
        AmountProblem::TooManyDecimals { allowed } => format!(
            "XCH goes to {allowed} decimal places, and this has more. Chia cannot move a smaller \
             amount than that."
        ),
        AmountProblem::TooLarge => "That is more XCH than can exist.".to_string(),
    }
}

/// What a person has typed into the send form, and the state it is being judged against.
///
/// Borrowed rather than owned because it is assembled fresh from the pane's own fields on every frame.
#[derive(Debug, Clone, Copy)]
pub struct SendDraft<'a> {
    /// The destination, exactly as typed.
    pub destination: &'a str,
    /// The amount in whole XCH, exactly as typed.
    pub amount: &'a str,
    /// Whether the account is open. A sealed account can build nothing.
    pub account_open: bool,
    /// What this wallet is known to hold, or that nobody has read it.
    pub balance: &'a BalanceReading,
    /// How the current send is going.
    pub progress: &'a SendProgress,
}

impl SendDraft<'_> {
    /// The transfer this draft describes, or why it cannot be sent.
    ///
    /// # The order of the checks is deliberate
    ///
    /// State first, then the fields left to right. A locked account is told to unlock rather than to
    /// fix an address it has no reason to have typed yet, and a person mid-send is told a payment is
    /// already running rather than being handed a validation complaint about a stale form.
    ///
    /// # Errors
    ///
    /// [`SendBlocked`], carrying the sentence the pane draws beneath the refused control.
    pub fn assess(&self) -> Result<TransferRequest, SendBlocked> {
        if !self.account_open {
            return Err(SendBlocked::AccountSealed);
        }
        if self.progress.in_flight() {
            return Err(SendBlocked::AlreadySending);
        }
        if self.destination.trim().is_empty() {
            return Err(SendBlocked::NoDestination);
        }

        let amount = parse_asset_amount(Asset::Xch, self.amount).map_err(SendBlocked::BadAmount)?;
        // Through `TransferRequest::to_address`, never a hand-rolled bech32 check: that constructor is
        // the ONE place a typed string is judged payable, and it refuses a non-`xch` prefix because
        // paying the puzzle hash inside one burns the funds.
        let request = TransferRequest::to_address(self.destination.trim(), amount)
            .map_err(|e| SendBlocked::BadDestination(e.to_string()))?
            .with_fee(DEFAULT_SEND_FEE_MOJOS);

        // The affordability check runs LAST and only against a real reading. `checked_add` because an
        // amount near `u64::MAX` plus a fee is otherwise a wrap into an affordable-looking number.
        let needed = amount
            .checked_add(DEFAULT_SEND_FEE_MOJOS)
            .ok_or(SendBlocked::BadAmount(AmountProblem::TooLarge))?;
        if let BalanceReading::Known { balances, .. } = self.balance {
            if needed > balances.xch_mojos {
                return Err(SendBlocked::NotEnough {
                    needed,
                    spendable: balances.xch_mojos,
                });
            }
        }
        Ok(request)
    }
}

/// The one send this app is running, and everything that moves it along.
///
/// # Why the shell owns a handle and not a state machine
///
/// The tray binary cannot be tested (dig_ecosystem#2377), so it must not decide anything. It holds one
/// of these, calls [`send`](Self::send) when the pane returns an intent, and calls
/// [`observe`](Self::observe) on each repaint to put the current state into the view. Every transition
/// — what an error meant, when a poll is due, whether a second send may start — happens in here.
///
/// # How often the chain is asked
///
/// [`observe`](Self::observe) is called on every repaint, twice a second, and a status poll is a node
/// round trip. So a poll happens at most once per `POLL_INTERVAL`, which is under one Chia block: a
/// faster cadence could only ever return the same answer.
#[derive(Default)]
pub struct SendHolder {
    watched: std::sync::Mutex<Watched>,
    /// The money gate, kept ACROSS sends (dig_ecosystem#2890).
    ///
    /// The rolling window behind `AutoSendPolicy::max_confirmations_per_period` lives inside the
    /// `PolicyAuthorizer` that [`MoneyPath`](crate::account::money::MoneyPath) holds, so building a
    /// fresh path per send handed every send an empty ledger and made that ceiling unreachable —
    /// the exact host mistake `account::money`'s own module doc names. Held here, the ledger
    /// measures a window.
    gate: std::sync::Mutex<Option<UnlockGate>>,
}

/// The money path built for one unlock, and the address that identifies which unlock it belongs to.
///
/// # Why the address is the key
///
/// A `MoneyPath` decodes the profile's hot-wallet receive address at construction, because that is
/// what the vault outflow rule compares a payee against. The address is therefore the one piece of
/// the gate that can go stale — a profile switch moves it — and a gate rebuilt only on a *lock*
/// would keep comparing against the profile the user just left. Keying on the address means the
/// ledger survives everything that leaves the gate's own premise intact, and nothing that does not.
struct UnlockGate {
    /// The receive address this gate was built against.
    address: String,
    /// The gate itself, holding the rolling confirmation ledger.
    ///
    /// Behind an [`Arc`](std::sync::Arc) so that "is this the same gate?" is answerable. Replacing
    /// the gate writes into this same `Option` slot, so the slot's ADDRESS is identical either way —
    /// a rebuild and a reuse are indistinguishable by reference. `Arc::ptr_eq` distinguishes them,
    /// which is what lets the reuse test fail when the gate is rebuilt.
    money: std::sync::Arc<
        crate::account::money::MoneyPath<
            crate::account::auth::HarnessAuthProvider<crate::account::ceremony::PromptedCeremony>,
        >,
    >,
}

/// How long to leave between chain polls of a pending transfer.
///
/// A Chia block is roughly 18.75 seconds, so this is comfortably inside one block: the reading cannot
/// go stale by a whole block, and the node is not asked twice for one answer.
pub(crate) const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// The send being watched, if any.
#[derive(Default)]
struct Watched {
    /// What the surface is showing.
    progress: SendProgress,
    /// The transfer to poll, present exactly while one has been pushed.
    pending: Option<PendingTransfer>,
    /// When the chain may next be asked. `None` means "as soon as anyone looks".
    next_poll: Option<std::time::Instant>,
    /// Whether a mempool actually ACCEPTED this bundle.
    ///
    /// # Why polling cannot answer this, and why the surface lies without it
    ///
    /// `TransferStatus::Awaiting` means only *the payment coin is not on chain yet*, which is the
    /// identical answer a bundle that was never broadcast produces — the coin is absent either way.
    /// So a poll of an UNJUDGED transfer promotes an honest "nobody knows" into
    /// [`SendProgress::Pending`], and the person reads *"the network has taken this payment and is
    /// settling it"* about a bundle that may never have left. On the token-less path that sentence is
    /// known false, and the coin id offered for lookup will never exist.
    ///
    /// Set ONLY by [`SendHolder::accepted`], which is reached only from a real `PushOutcome`. While
    /// it is `false`, `Awaiting` changes nothing; `Confirmed` and `Failed` are genuine chain verdicts
    /// and still resolve the state.
    judged: bool,
}

impl SendHolder {
    /// What the surface should show right now, with no chain read.
    pub fn progress(&self) -> SendProgress {
        self.lock().progress.clone()
    }

    /// Claim the one send slot, moving to [`SendProgress::Signing`], or report that it is taken.
    ///
    /// # Why this is a compare-and-set and not a check the caller makes
    ///
    /// It is the ONLY thing standing between a person and two payments. Every other guard is
    /// advisory: [`SendDraft::assess`] judges the send state carried by the PUBLISHED view, and the
    /// tray publishes nothing while the action worker holds the session — which it does for the whole
    /// ceremony, up to two minutes. So the window keeps drawing an enabled **Send** button, on a form
    /// that still says `Idle`, for the entire time a send is running. A second click in that window
    /// used to be accepted, and the first thing it did was erase the pending transfer of the send
    /// already under way.
    ///
    /// Reading the state and then setting it would leave the same hole, one lock acquisition wide, so
    /// both happen under a single lock here. It deliberately does NOT rely on the tray's
    /// `ActionWorker` busy flag: the guarantee has to hold wherever a send is started from, and a
    /// guard that depends on another component's timing is a guard nobody can check.
    ///
    /// Returns `false` when a send is already in flight, in which case NOTHING was disturbed.
    #[must_use = "a refused claim means another send is running; do not proceed"]
    pub fn begin(&self) -> bool {
        let mut watched = self.lock();
        if watched.progress.in_flight() {
            return false;
        }
        watched.progress = SendProgress::Signing;
        watched.pending = None;
        watched.next_poll = None;
        watched.judged = false;
        true
    }

    /// Record a push a mempool accepted, and begin watching its payment coin.
    ///
    /// The one place a transfer becomes JUDGED, which is what lets a later poll report a wait as real.
    pub fn accepted(&self, pending: PendingTransfer) {
        let mut watched = self.lock();
        watched.progress = SendProgress::accepted(&pending);
        watched.pending = Some(pending);
        watched.next_poll = Some(std::time::Instant::now() + POLL_INTERVAL);
        watched.judged = true;
    }

    /// Record that an attempt stopped without ever recording its own outcome.
    ///
    /// Reached only from [`AbandonedSend`]'s unwind. It frees the send slot — the alternative is a
    /// form nobody can use again — while claiming nothing about where the money got to
    /// (dig_ecosystem#2895). Nothing is left to poll: a panic yields no payment coin.
    pub fn abandoned(&self, detail: impl Into<String>) {
        let mut watched = self.lock();
        watched.progress = SendProgress::Abandoned {
            detail: detail.into(),
        };
        watched.pending = None;
        watched.next_poll = None;
        watched.judged = false;
    }

    /// Record how a send ended.
    ///
    /// An unanswered push keeps its transfer and keeps being polled, because its fate is undecided and
    /// the chain is the only thing that can decide it. Every other error stops the watch: nothing was
    /// broadcast, so there is nothing to watch.
    pub fn finished(&self, error: &SendError) {
        let mut watched = self.lock();
        watched.progress = SendProgress::of_error(error);
        match error {
            SendError::PushUnanswered { pending, .. } => {
                watched.pending = Some((**pending).clone());
                watched.next_poll = Some(std::time::Instant::now() + POLL_INTERVAL);
                // Unjudged, and it stays that way: no mempool ever said anything about this bundle.
                watched.judged = false;
            }
            _ => {
                watched.pending = None;
                watched.next_poll = None;
                watched.judged = false;
            }
        }
    }

    /// Ask the chain about the watched transfer, if one is due, and report what to show.
    ///
    /// A read that FAILS changes nothing: the app's ability to ask is not a fact about the transfer,
    /// and turning a timeout into a failure would tell a person their payment died because their node
    /// was busy. A settled transfer stops being polled — a confirmation does not become less true.
    ///
    /// # An unjudged transfer cannot be promoted by a poll
    ///
    /// `Awaiting` is the same answer whether a bundle is queued in a mempool or was never broadcast
    /// at all, so for a transfer no mempool ever accepted it establishes nothing and MUST leave
    /// [`SendProgress::Unknown`] standing. Only `Confirmed` and `Failed` are verdicts, and those
    /// resolve it either way.
    pub fn observe<C>(&self, chain: &C, now: std::time::Instant) -> SendProgress
    where
        C: dig_chainsource_interface::ChainSource + ?Sized,
    {
        let mut watched = self.lock();
        let due = watched.next_poll.map_or(true, |at| now >= at);
        let Some(pending) = watched.pending.as_ref().filter(|_| due) else {
            return watched.progress.clone();
        };
        if let Ok(status) = dig_account::transfer_status(pending, chain) {
            let establishes_nothing =
                !watched.judged && matches!(status, TransferStatus::Awaiting { .. });
            if !establishes_nothing {
                watched.progress = SendProgress::of_status(pending, &status);
                if !watched.progress.in_flight() {
                    watched.pending = None;
                }
            }
        }
        watched.next_poll = Some(now + POLL_INTERVAL);
        watched.progress.clone()
    }

    /// Perform the whole send the pane asked for, and record how it went.
    ///
    /// # Why the shell's arm for this is one call
    ///
    /// Everything below is a decision — is there an account, is there a node, what did the failure
    /// mean — and the tray binary can execute none of it under test (dig_ecosystem#2377). So the
    /// binary's `TrayAction::SendXch` arm calls this and nothing else. The custody ceremony is the
    /// PRODUCTION one: the person approves the payment in the app's own prompt, and the account's key
    /// never leaves this process (§908).
    ///
    /// The custody policy is fixed at a zero auto-send allowance, so no amount is small enough to
    /// leave without a human. Making that configurable is deliberately not done here
    /// (dig_ecosystem#2881) — raising it is exactly what would let money move unattended.
    ///
    /// It BLOCKS for as long as the person takes to decide, so the caller must be a worker thread and
    /// not the repaint loop.
    ///
    /// # Why it takes the shared status rather than an [`EngineState`](crate::engine::EngineState)
    ///
    /// The node is read here and the read guard is DROPPED before anything blocks. A caller holding
    /// that guard across this call would hold it across the confirm ceremony — which has a
    /// two-minute deadline — and the agent's own tick, which needs the write side, would be stalled
    /// for the whole time a person was reading the dialog.
    /// # Two things it will not do, whatever the caller does
    ///
    /// It refuses outright while another send is in flight ([`begin`](Self::begin)), and it leaves no
    /// state behind if the ceremony PANICS: the whole attempt runs under a guard that records a
    /// failure on an unwind. Without it, `ActionWorker` would catch the panic, the tray would survive,
    /// and the form would sit at `Signing` — in flight, unpollable because nothing was pushed, and so
    /// refusing every later send until the app restarts.
    pub fn send(
        &self,
        status: &crate::agent::SharedStatus,
        residency: Option<&crate::account::residency::AccountResidency>,
        request: &TransferRequest,
    ) {
        if !self.begin() {
            return;
        }
        let mut guard = AbandonedSend::watching(self);
        let outcome = self.perform(status, residency, request);
        guard.completed();
        match outcome {
            Ok(in_flight) => self.accepted(in_flight.finish()),
            Err(error) => self.finished(&error),
        }
    }

    /// The money gate for this unlock, built once and reused (dig_ecosystem#2890).
    ///
    /// A gate is rebuilt only when the receive address it rules against changes — see [`UnlockGate`]
    /// for why that, and not a lock, is the right trigger. The returned guard keeps the gate borrowed
    /// for the whole send, which is safe because [`begin`](Self::begin) admits one send at a time.
    fn gate_for(
        &self,
        residency: &crate::account::residency::AccountResidency,
        custody: dig_account::CustodyPolicy,
    ) -> Result<std::sync::MutexGuard<'_, Option<UnlockGate>>, SendError> {
        use crate::account::auth::HarnessAuthProvider;
        use crate::account::boot::DEFAULT_ACCOUNT_ID;
        use crate::account::ceremony::PromptedCeremony;
        use crate::account::money::MoneyPath;

        // Read before the gate is consulted, so a profile switch is caught here rather than by a
        // stale address comparison inside a gate that outlived it.
        let Some(Ok(address)) = residency.receiving_address() else {
            // The residency locked, or its address stopped deriving, between the click and this
            // call. Nothing was built.
            return Err(SendError::Locked);
        };

        let mut held = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if held.as_ref().is_none_or(|gate| gate.address != address) {
            let money = MoneyPath::new(
                residency.clone(),
                HarnessAuthProvider::new(PromptedCeremony::unlocking("confirm this payment")),
                dig_account::AccountId::new(DEFAULT_ACCOUNT_ID),
                dig_wallet_backend::types::Network::Mainnet,
                custody,
                dig_account::AutoSendPolicy::default(),
                std::sync::Arc::new(dig_account::SystemClock),
            )
            .map_err(|_| SendError::Locked)?;
            *held = Some(UnlockGate {
                address,
                money: std::sync::Arc::new(money),
            });
        }
        Ok(held)
    }

    /// Build, gate, sign and push — every step that can fail, and none that record state.
    ///
    /// Split out from [`send`](Self::send) so that recording the outcome happens in exactly one place,
    /// and so an unwind through here cannot be mistaken for a recorded one.
    fn perform(
        &self,
        status: &crate::agent::SharedStatus,
        residency: Option<&crate::account::residency::AccountResidency>,
        request: &TransferRequest,
    ) -> Result<crate::wallet::send::InFlightSend, SendError> {
        use crate::chain::{ControlChainSource, ControlSpendPublisher};
        use crate::wallet::send::SendSession;
        use dig_account::{CustodyPolicy, HotWallet};

        let Some(residency) = residency else {
            return Err(SendError::Locked);
        };
        // Cloned out from under the lock, which is then released — see the docs above.
        let engine = match status.read() {
            Ok(status) => status.engine.clone(),
            // A poisoned status lock says nothing about the node, and a send built against a node
            // nothing can describe is a send that must not be attempted.
            Err(_) => crate::engine::EngineState::initial(),
        };
        let crate::engine::EngineState::Connected { endpoint, .. } = &engine else {
            return Err(SendError::PeakUnreadable(
                dig_account::TransferError::ChainUnreachable(
                    "no node is connected, so nothing could be built or broadcast".to_string(),
                ),
            ));
        };

        let custody = CustodyPolicy::Hot(HotWallet { auto_send_limit: 0 });
        let held = self.gate_for(residency, custody)?;
        let money = &held
            .as_ref()
            .expect("gate_for leaves a gate in place or returns an error")
            .money;

        let chain = ControlChainSource::new(endpoint);
        let publisher = ControlSpendPublisher::new(endpoint);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                SendError::Sign(crate::account::money::MoneyPathError::Sign(format!(
                    "this app could not start the worker the confirmation needs: {e}"
                )))
            })?;
        runtime
            .block_on(SendSession::new(residency, money, custody, &chain, &publisher).send(request))
    }

    /// Poll the watched transfer against the connected node, if there is one.
    ///
    /// A disconnected node changes nothing: the transfer is on the chain's books either way, and the
    /// surface keeps saying what it last knew rather than inventing a verdict from this app's own
    /// inability to look.
    pub fn observe_node(&self, engine: &crate::engine::EngineState) -> SendProgress {
        match engine {
            crate::engine::EngineState::Connected { endpoint, .. } => self.observe(
                &crate::chain::ControlChainSource::new(endpoint),
                std::time::Instant::now(),
            ),
            crate::engine::EngineState::Disconnected { .. } => self.progress(),
        }
    }

    /// Take the lock, recovering from a poisoned one.
    ///
    /// A poisoned lock means an earlier send panicked. Refusing every later send — leaving a person
    /// with a wallet that has silently stopped working — is a worse answer than carrying on with the
    /// state as it stands, which is the same call the tray's session lock makes.
    fn lock(&self) -> std::sync::MutexGuard<'_, Watched> {
        self.watched
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Restores the send form if the attempt it is watching never records an outcome.
///
/// # Why a guard rather than a `catch_unwind`
///
/// The send slot is claimed before anything can fail, and a panic anywhere in build, ceremony, signing
/// or push would otherwise leave it claimed forever: `ActionWorker` catches the unwind and keeps the
/// tray running, so the process survives with `progress = Signing` — in flight, and unpollable because
/// nothing was ever pushed. `SendDraft::assess` then answers `AlreadySending` to every later send for
/// a payment that never existed, with no way out but a restart. A `Drop` runs on the unwind path
/// wherever the panic came from, which a `catch_unwind` around one call cannot promise.
///
/// A panicking send is reported as [`SendProgress::Abandoned`] — neither a failure nor an unknown
/// outcome. It is not a failure because a panic cannot establish that nothing left this machine
/// (dig_ecosystem#2895), and it is not `Unknown` because that state holds the form closed and offers
/// a coin id to watch, and a panic produces no coin id to offer.
struct AbandonedSend<'a> {
    holder: &'a SendHolder,
    /// Whether the attempt is still outstanding. Cleared by [`completed`](Self::completed).
    outstanding: bool,
}

impl<'a> AbandonedSend<'a> {
    fn watching(holder: &'a SendHolder) -> Self {
        Self {
            holder,
            outstanding: true,
        }
    }

    /// The attempt returned, so its own outcome is about to be recorded.
    fn completed(&mut self) {
        self.outstanding = false;
    }
}

impl Drop for AbandonedSend<'_> {
    fn drop(&mut self) {
        if self.outstanding {
            self.holder
                .abandoned("this app stopped part-way through the payment");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::engine::BalanceAsOf;
    use crate::wallet::overview::{BalanceUnknown, Balances};

    /// A real mainnet payment address, so the destination rule is exercised against the thing it
    /// actually judges rather than against a shape.
    const PAYABLE: &str = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";

    /// A funded reading: one XCH, comfortably more than the fixtures spend.
    fn funded() -> BalanceReading {
        BalanceReading::Known {
            balances: Balances {
                xch_mojos: 1_000_000_000_000,
                dig_units: 0,
            },
            as_of: BalanceAsOf::Replica {
                height: 7_000_000,
                caught_up: true,
            },
        }
    }

    /// A draft that would send successfully, so each test varies exactly ONE thing away from it.
    fn ready<'a>(balance: &'a BalanceReading, progress: &'a SendProgress) -> SendDraft<'a> {
        SendDraft {
            destination: PAYABLE,
            amount: "0.25",
            account_open: true,
            balance,
            progress,
        }
    }

    /// **A complete, affordable draft on an open account produces the transfer it describes.**
    ///
    /// The control every refusal test needs: without it, an `assess` that refused everything would
    /// satisfy all of them.
    #[test]
    fn a_complete_draft_becomes_a_transfer_carrying_the_typed_amount_and_the_fixed_fee() {
        let balance = funded();
        let progress = SendProgress::Idle;
        let request = ready(&balance, &progress)
            .assess()
            .expect("a funded, open, well-formed draft is sendable");
        assert_eq!(
            request.amount_mojos(),
            250_000_000_000,
            "the amount was not read as whole XCH"
        );
        assert_eq!(
            request.fee_mojos(),
            DEFAULT_SEND_FEE_MOJOS,
            "the fee shown on the card is not the fee that would be paid"
        );
    }

    /// **A sealed account is refused before anything else, and the reason names the unlock.**
    ///
    /// Varied from a draft that is otherwise perfectly sendable, so the refusal can only come from the
    /// lock.
    #[test]
    fn a_sealed_account_is_offered_no_send_and_is_told_why() {
        let balance = funded();
        let progress = SendProgress::Idle;
        let draft = SendDraft {
            account_open: false,
            ..ready(&balance, &progress)
        };
        assert_eq!(draft.assess(), Err(SendBlocked::AccountSealed));
        assert!(draft
            .assess()
            .unwrap_err()
            .sentence()
            .to_lowercase()
            .contains("unlock"));
    }

    /// **While a send is running, a second one is refused — in every in-flight state.**
    ///
    /// All three are asserted, and `Unknown` is the one that matters: its transfer may already be in a
    /// mempool, so a second send is how a recipient gets paid twice. The two settled states are the
    /// control — they must NOT block, or the form would be a one-shot.
    #[test]
    fn a_second_send_is_refused_while_one_is_in_flight_and_offered_once_it_settles() {
        let balance = funded();
        for progress in [
            SendProgress::Signing,
            SendProgress::Pending {
                payment_coin_id: "aa".to_string(),
                blocks_since_push: 2,
            },
            SendProgress::Unknown {
                payment_coin_id: "aa".to_string(),
                detail: "the node did not answer".to_string(),
            },
        ] {
            assert!(
                progress.in_flight(),
                "{progress:?} is not treated as running"
            );
            assert_eq!(
                ready(&balance, &progress).assess(),
                Err(SendBlocked::AlreadySending),
                "{progress:?} allowed a second send to start"
            );
        }
        for progress in [
            SendProgress::Idle,
            SendProgress::Confirmed {
                payment_coin_id: "aa".to_string(),
                confirmed_height: 7_000_000,
            },
            SendProgress::Failed {
                reason: "the network rejected the transfer".to_string(),
                payment_coin_id: None,
            },
        ] {
            assert!(!progress.in_flight(), "{progress:?} blocks a fresh send");
            assert!(
                ready(&balance, &progress).assess().is_ok(),
                "{progress:?} left the form unusable after the send finished"
            );
        }
    }

    /// **A destination that is not a mainnet payment address is refused, in dig-account's words.**
    ///
    /// The `txch` case is the one worth having: it decodes cleanly and is the right shape, and paying
    /// the puzzle hash inside it would burn the money. A shape-only check accepts it.
    #[test]
    fn a_destination_that_is_not_a_mainnet_payment_address_is_refused() {
        let balance = funded();
        let progress = SendProgress::Idle;
        for destination in [
            "txch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3s3cq0z0",
            "xch1nonsense",
            "not an address at all",
        ] {
            let draft = SendDraft {
                destination,
                ..ready(&balance, &progress)
            };
            assert!(
                matches!(draft.assess(), Err(SendBlocked::BadDestination(_))),
                "{destination} was accepted as a payment address"
            );
        }
        // Empty is its own, gentler state: a form must not scold someone for not having typed yet.
        let empty = SendDraft {
            destination: "  ",
            ..ready(&balance, &progress)
        };
        assert_eq!(empty.assess(), Err(SendBlocked::NoDestination));
    }

    /// **An amount that is not a number of XCH is refused, carrying the problem the parser named.**
    ///
    /// The refusals come through [`crate::amount::parse_asset_amount`] rather than a second rule, so
    /// the form and the arithmetic cannot come to disagree about what a valid amount is.
    #[test]
    fn an_unusable_amount_is_refused_with_the_parsers_own_verdict() {
        let balance = funded();
        let progress = SendProgress::Idle;
        for (typed, expected) in [
            ("", AmountProblem::Empty),
            ("lots", AmountProblem::NotANumber),
            ("-1", AmountProblem::NotANumber),
            (
                "0.0000000000001",
                AmountProblem::TooManyDecimals { allowed: 12 },
            ),
        ] {
            let draft = SendDraft {
                amount: typed,
                ..ready(&balance, &progress)
            };
            assert_eq!(
                draft.assess(),
                Err(SendBlocked::BadAmount(expected)),
                "{typed:?} was not refused as {expected:?}"
            );
        }
    }

    /// **A send costing more than the wallet holds is refused, and the fee is part of the cost.**
    ///
    /// The fixture is the whole point: the wallet holds EXACTLY the amount being sent, so an
    /// affordability check that forgot the fee would let it through and the build would fail later,
    /// after the person had confirmed a payment. Both sides of the bound are asserted — one mojo more
    /// than the cost passes.
    #[test]
    fn the_fee_counts_towards_affordability_and_the_exact_cost_still_passes() {
        let progress = SendProgress::Idle;
        let amount = 250_000_000_000_u64;
        let holding = |xch_mojos: u64| BalanceReading::Known {
            balances: Balances {
                xch_mojos,
                dig_units: 0,
            },
            as_of: BalanceAsOf::Replica {
                height: 7_000_000,
                caught_up: true,
            },
        };

        let exactly_the_amount = holding(amount);
        assert_eq!(
            ready(&exactly_the_amount, &progress).assess(),
            Err(SendBlocked::NotEnough {
                needed: amount + DEFAULT_SEND_FEE_MOJOS,
                spendable: amount,
            }),
            "a wallet holding the amount but not the fee was allowed to send"
        );

        let exactly_the_cost = holding(amount + DEFAULT_SEND_FEE_MOJOS);
        assert!(
            ready(&exactly_the_cost, &progress).assess().is_ok(),
            "a wallet holding exactly the amount and the fee was refused its own money"
        );
    }

    /// **A balance nobody has read blocks nothing.**
    ///
    /// Refusing a send over a figure the app does not have would be inventing the figure — the same
    /// money lie the Wallet tab refuses in the other direction when it declines to draw an unknown
    /// balance as `0`. The build refuses an unaffordable transfer on its own, with the chain's answer
    /// rather than a guess.
    #[test]
    fn an_unread_balance_does_not_refuse_a_send() {
        let progress = SendProgress::Idle;
        for balance in [
            BalanceReading::Pending,
            BalanceReading::Unknown(BalanceUnknown::NoNode),
        ] {
            assert!(
                ready(&balance, &progress).assess().is_ok(),
                "{balance:?} was treated as a balance of zero"
            );
        }
    }

    /// **A send that panics part-way leaves the form usable, and one that completes is left alone.**
    ///
    /// `ActionWorker` catches the unwind and the tray survives, so without the guard the holder keeps
    /// the slot it claimed: `Signing` forever, in flight, and unpollable because nothing was pushed —
    /// `assess` then answers `AlreadySending` to every later send until the app restarts.
    ///
    /// The pair is the property. A guard that fired unconditionally would also leave the form usable
    /// in the first case, and would destroy the outcome of every ordinary send; the second half is
    /// what rules that out.
    #[test]
    fn a_send_abandoned_by_a_panic_frees_the_form_and_a_completed_one_keeps_its_outcome() {
        let holder = SendHolder::default();
        assert!(holder.begin(), "an idle holder offers its send slot");
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = AbandonedSend::watching(&holder);
            panic!("the ceremony fell over");
        }));
        assert!(panicked.is_err(), "the fixture did not actually panic");
        assert!(
            !holder.progress().in_flight(),
            "a panicked send kept the slot, so no further send can ever be started"
        );
        assert!(matches!(holder.progress(), SendProgress::Abandoned { .. }));

        // A completed attempt is disarmed, so the guard writes nothing over its outcome.
        assert!(holder.begin(), "the freed slot is offered again");
        {
            let mut guard = AbandonedSend::watching(&holder);
            guard.completed();
        }
        assert_eq!(
            holder.progress(),
            SendProgress::Signing,
            "the guard overwrote the outcome of a send that finished normally"
        );
    }

    /// **An unanswered push is NOT rendered as a failure, and every other error is.**
    ///
    /// The load-bearing distinction of this whole module. `PushUnanswered` means the outcome is
    /// unknown and the bundle may already be in a mempool; showing it as "it did not send" invites the
    /// one action that can pay twice. Asserted alongside the five errors that genuinely mean nothing
    /// was broadcast, so the test can tell a real mapping from one that returns `Unknown` for
    /// everything.
    #[test]
    fn an_unanswered_push_is_an_unknown_outcome_while_every_other_error_is_a_failure() {
        let rejected = SendError::Rejected {
            reason: "DOUBLE_SPEND".to_string(),
        };
        assert_eq!(
            SendProgress::of_error(&rejected),
            SendProgress::Failed {
                reason: rejected.to_string(),
                payment_coin_id: None,
            }
        );
        assert_eq!(
            SendProgress::of_error(&SendError::Locked),
            SendProgress::Failed {
                reason: SendError::Locked.to_string(),
                payment_coin_id: None,
            }
        );
        assert_eq!(
            SendProgress::of_error(&SendError::WalletBehindActiveProfile("slot 3".to_string())),
            SendProgress::Failed {
                reason: SendError::WalletBehindActiveProfile("slot 3".to_string()).to_string(),
                payment_coin_id: None,
            }
        );
        assert!(!SendProgress::of_error(&rejected).in_flight());
    }

    /// **The confirmation ledger survives one send and is still there for the next**
    /// (dig_ecosystem#2890).
    ///
    /// The nearest wrong implementation — and the one that shipped — builds a `MoneyPath` inside
    /// `perform`, so every send hands the `PolicyAuthorizer` an empty rolling window and
    /// `max_confirmations_per_period` can never be reached. No assertion about a send's OUTCOME can
    /// see that, because a per-request gate and a per-unlock gate approve identically until the
    /// ceiling would have bitten. So the fixture asks the question directly: is the gate the SAME
    /// gate?
    ///
    /// Identity is `Arc::ptr_eq`, deliberately. The first version of this test compared the address
    /// of the retained field and passed even when the gate was rebuilt on every call — a rebuild
    /// writes into the same `Option` slot, so the address is the same either way. Measured: with the
    /// cache condition forced to always rebuild, the address form stayed GREEN and this form fails.
    #[test]
    fn the_money_gate_is_built_once_per_unlock_and_reused_by_every_later_send() {
        let residency = crate::test_support::test_residency();
        let custody =
            dig_account::CustodyPolicy::Hot(dig_account::HotWallet { auto_send_limit: 0 });
        let holder = SendHolder::default();

        let first = {
            let held = holder
                .gate_for(&residency, custody)
                .expect("an unlocked residency yields a gate");
            std::sync::Arc::clone(&held.as_ref().expect("a gate is present").money)
        };
        let second = {
            let held = holder
                .gate_for(&residency, custody)
                .expect("the same unlocked residency yields a gate");
            std::sync::Arc::clone(&held.as_ref().expect("a gate is present").money)
        };

        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "a second send got a fresh gate, so it also got a fresh confirmation ledger"
        );
    }

    /// **A locked residency yields no gate, and leaves no gate behind to be reused**
    /// (dig_ecosystem#2890).
    ///
    /// The control on the test above. Caching a gate is only safe while the premise it was built on
    /// still holds, and the nearest wrong implementation of the cache hands back the retained gate
    /// without re-checking that the account is still open — which would let a relocked account keep
    /// spending through a gate built when it was not.
    #[test]
    fn a_locked_residency_is_refused_rather_than_served_a_retained_gate() {
        let residency = crate::test_support::test_residency();
        let custody =
            dig_account::CustodyPolicy::Hot(dig_account::HotWallet { auto_send_limit: 0 });
        let holder = SendHolder::default();

        holder
            .gate_for(&residency, custody)
            .expect("the gate is built while the account is open");
        crate::session_lock::SessionKeys::lock_all(&residency);

        assert!(
            matches!(holder.gate_for(&residency, custody), Err(SendError::Locked)),
            "a relocked account was served the gate built for its earlier unlock"
        );
    }
}
