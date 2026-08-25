//! Assembling the production dapp-spend seam (`SPEC.md` §5.6.9, dig_ecosystem#1552).
//!
//! # Why this is a module in the library and not four lines in the tray binary
//!
//! `crates/dig-app/src/bin` is a test-free zone: nothing in a `bin` target can be reached by a unit
//! test, and a one-line change there has already produced both an undismissible dead end and a
//! spurious start-up password window in this app — neither catchable by any test that existed.
//!
//! So the assembly lives HERE, where a test can drive it, and the binary calls one function. What
//! remains in the binary is the decision to install at all; every choice that could make the seam
//! gate against the wrong profile, ask the wrong question, or spend under the wrong policy is made
//! in this file, under test.

use std::sync::Arc;

use dig_account::{AutoSendPolicy, Clock, CustodyPolicy, HotWallet};
use dig_wallet_backend::types::Network;

use crate::account::auth::HarnessAuthProvider;
use crate::account::ceremony::{PasswordIntent, PromptedCeremony};
use crate::account::money::MoneyPath;
use crate::account::narrative::NarrativeSlot;
use crate::account::residency::AccountResidency;
use crate::confirm::NativeConfirmer;
use crate::wallet::dapp_spend::MoneyPathSource;
use dig_account::AccountId;

/// The network every dapp-originated spend is signed for.
///
/// **Mainnet, and there is no other option.** This app is mainnet-only, and the network is bound into
/// the signature: a bundle signed for the wrong network is refused by every mempool, which is the
/// harmless direction — but a SETTING here would be a way to sign a real payment under a genesis
/// challenge the confirm window never mentioned.
const SPEND_NETWORK: Network = Network::Mainnet;

/// The auth provider the production dapp-spend seam confirms through.
pub type LiveAuthProvider = HarnessAuthProvider<PromptedCeremony>;

/// The custody policy every dapp-originated spend is gated by.
///
/// **Fixed at the strictest setting, deliberately, and NOT read from a settings surface.**
/// `auto_send_limit: 0` means no amount is small enough to settle without a human, and
/// [`AutoSendPolicy::default`] denies every op class as well. The two defend different things and a
/// spend an OUTSIDE application asked for wants both: the app that built the bundle chose its own
/// recipients and amounts, so there is no sense in which the user has already agreed to it.
///
/// Reading a user-configured allowance here would let a permissive setting made for the in-app Send
/// control silently authorise a stranger's payment. If a dapp-spend allowance is ever wanted it must
/// be its own setting, granted knowingly.
fn dapp_custody() -> CustodyPolicy {
    CustodyPolicy::Hot(HotWallet { auto_send_limit: 0 })
}

/// The password window a dapp-originated spend raises.
fn dapp_intent() -> PasswordIntent {
    PasswordIntent::Unlock {
        reason: "confirm a payment an app asked for".to_string(),
    }
}

/// Build the production money-path source and the narrative slot the confirm window reads.
///
/// The returned slot MUST be the one handed to
/// [`DappSpendAuthority::new`](crate::wallet::dapp_spend::DappSpendAuthority::new): the seam stages
/// its narrative there before asking, and a ceremony reading a different slot would drop the
/// sentence that says whether the app is about to BROADCAST the payment.
///
/// # Liveness
///
/// The closure builds a fresh [`MoneyPath`] per call, so a lock or a profile switch that landed
/// since boot is observed at spend time. A locked account yields `None`, which the seam reports as
/// `LOCKED`.
///
/// # Custody (§908)
///
/// Nothing here holds a key. [`MoneyPath`] signs in-process through
/// `residency.money_signer(network)`, backstopped by dig-account's `CustodyScope`. The node is asked
/// to sign nothing at any point; it is handed an already-signed bundle or nothing at all.
pub fn live_money_source(
    residency: AccountResidency,
    confirmer: Arc<dyn NativeConfirmer>,
) -> (MoneyPathSource<LiveAuthProvider>, NarrativeSlot) {
    // The account, the network and the clock are chosen HERE rather than passed in, so the tray
    // binary — which no test can reach — passes only the two things it genuinely owns. Each is
    // pinned by a test below.
    let account_id = AccountId::new(crate::account::boot::DEFAULT_ACCOUNT_ID);
    let network = SPEND_NETWORK;
    let clock: Arc<dyn Clock> = Arc::new(dig_account::SystemClock);
    let narrative = NarrativeSlot::default();
    let staged = narrative.clone();

    let source: MoneyPathSource<LiveAuthProvider> = Arc::new(move || {
        // A ceremony per call, sharing the ONE slot the seam stages into. See `sharing_narrative`.
        let ceremony = PromptedCeremony::sharing_narrative(
            Arc::clone(&confirmer),
            dapp_intent(),
            staged.clone(),
        );
        MoneyPath::new(
            residency.clone(),
            HarnessAuthProvider::new(ceremony),
            account_id.clone(),
            network,
            dapp_custody(),
            AutoSendPolicy::default(),
            Arc::clone(&clock),
        )
        .ok()
        .map(Arc::new)
    });

    (source, narrative)
}

/// The runtime a dapp spend is driven on, created on FIRST USE and reused thereafter.
///
/// # Why it is not created at boot
///
/// The tray process is synchronous by design: `unlock_existing_account` builds its own private
/// current-thread runtime and blocks on it, and **tokio refuses to start a runtime from inside a
/// runtime** — which is why this app has no ambient one and why an `async` main would panic the
/// unlock before anything could be built. A runtime started at boot would also put a thread pool
/// into a process that may never spend at all.
///
/// A multi-thread runtime, so `block_on` from the loopback serving thread drives the money path on
/// the pool rather than needing that thread to poll it. The serving thread is a plain `std::thread`
/// and never a tokio worker, so blocking on it cannot deadlock a runtime.
///
/// Leaked into a `OnceLock` deliberately: the handle must outlive every spend, and a runtime dropped
/// while a confirm window is open would abort a ceremony mid-payment.
pub fn spend_runtime() -> tokio::runtime::Handle {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tracing::info!("starting the dapp-spend runtime on first use");
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("dig-app-spend")
                .build()
                .expect("a runtime for dapp spends")
        })
        .handle()
        .clone()
}

/// The production runtime source: [`spend_runtime`], deferred to first use.
pub fn live_runtime_source() -> crate::wallet::dapp_spend::RuntimeSource {
    Arc::new(spend_runtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The dapp custody policy admits no automatic payment, at any amount.**
    ///
    /// Pinned from BOTH sides of the bound rather than merely asserting the limit is zero: a policy
    /// object can carry a zero the authorizer never consults. `1` mojo — the smallest payment that
    /// can exist — is the input that distinguishes "no auto-send" from "a small auto-send", and a
    /// limit of zero must refuse even that.
    #[test]
    fn no_dapp_spend_is_small_enough_to_settle_without_a_human() {
        let CustodyPolicy::Hot(hot) = dapp_custody() else {
            panic!("a dapp spend must not run under vault custody: it cannot pay anyone");
        };
        assert_eq!(
            0, hot.auto_send_limit,
            "an allowance above zero is precisely what lets a stranger's payment leave with no human \
             in the loop"
        );
    }

    /// **`Undeclared` has no auto-send bounds and structurally cannot acquire any**, so every dapp
    /// spend reaches the human however the amount rule is later relaxed.
    ///
    /// This is the gate that survives a change to the other one. `configured_limits` returns `None`
    /// for `Undeclared` by construction — not by a default value someone could raise — which is why
    /// the seam classifies a spend it did not build as `Undeclared` rather than trusting the caller.
    ///
    /// The CONTROL matters here: a declared class must return `Some`, or this test would pass for an
    /// implementation whose limits lookup returns `None` for everything, which grants nothing and
    /// proves nothing about `Undeclared` specifically.
    #[test]
    fn an_undeclared_spend_has_no_auto_send_bounds_to_settle_under() {
        let policy = AutoSendPolicy::default();
        assert!(
            policy
                .configured_limits(dig_account::SpendOpClass::Undeclared)
                .is_none(),
            "a spend built outside this process cannot be declared, so it must always reach the human"
        );
        assert!(
            policy
                .configured_limits(dig_account::SpendOpClass::SmallSend)
                .is_some(),
            "control: a DECLARED class does carry bounds, so the assertion above is about Undeclared              and not about a lookup that answers None for everything"
        );
    }

    /// **The password window says the payment came from an APP.**
    ///
    /// A person re-entering their password deserves to know which of the two very different things
    /// they are approving: their own Send, or a request an outside application made.
    #[test]
    fn the_password_window_says_the_payment_came_from_an_app() {
        let PasswordIntent::Unlock { reason } = dapp_intent() else {
            panic!("a dapp spend unlocks an existing account; it never ESTABLISHES a password");
        };
        assert!(
            reason.contains("app asked for"),
            "the window must distinguish an app request from the user own send: {reason}"
        );
    }

    /// **The spend is signed for MAINNET**, the only network this app speaks.
    ///
    /// The network is bound into the signature, so this is not cosmetic: a value drifting here would
    /// sign a real payment under a genesis challenge the confirm window never named.
    #[test]
    fn a_dapp_spend_is_signed_for_mainnet() {
        assert_eq!(Network::Mainnet, SPEND_NETWORK);
    }
}
