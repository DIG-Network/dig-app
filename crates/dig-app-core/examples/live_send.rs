//! A REAL mainnet XCH send, driven by a human, against a live dig-node (dig_ecosystem#2819).
//!
//! # THIS SPENDS REAL MONEY
//!
//! Everything here is mainnet. The amount leaves the account's wallet permanently, the fee is paid to
//! a farmer, and nothing about it can be undone once a mempool accepts the bundle. There is no dry
//! run, and adding one would defeat the purpose: this exists to prove that the send flow moves actual
//! money through actual custody, which a simulation cannot establish.
//!
//! NOT a test. CI has no dig-node, no account, and nobody to type a password, so this is a
//! `cargo run --example` a person points at their own machine.
//!
//! ```text
//! cargo run -p dig-app-core --example live_send -- <destination-xch1…> <amount-mojos> [endpoint]
//! ```
//!
//! # What it uses, and what it deliberately does not
//!
//! The account is unlocked through the app's OWN boot path
//! ([`unlock_existing_account`](dig_app_core::account::boot::unlock_existing_account)), so the
//! password is typed into the app's trusted prompt window and never into a terminal. The confirm
//! ceremony is the production one for the same reason: an example that approved its own spend would
//! prove only that the fake approves. Neither the password, the seed, the recovery phrase nor the
//! node's control token is printed here, and none of them is ever read by this file.
//!
//! Windows and macOS only — the prompt path is unimplemented on Linux (`account/boot.rs:23`), so
//! there is no window to type a password into there.

use dig_account::{
    transfer_status, AccountId, AutoSendPolicy, CustodyPolicy, HotWallet, SystemClock,
    TransferRequest, TransferStatus,
};
use dig_app_core::account::boot::{unlock_existing_account, DEFAULT_ACCOUNT_ID};
use dig_app_core::account::ceremony::PromptedCeremony;
use dig_app_core::account::money::MoneyPath;
use dig_app_core::chain::{ControlChainSource, ControlSpendPublisher};
use dig_app_core::environment::AppEnvironment;
use dig_app_core::wallet::send::{SendSession, DEFAULT_SEND_FEE_MOJOS};
use std::sync::Arc;
use std::time::Duration;

/// How long to wait between polls. A Chia block arrives roughly every 18.75 seconds, so anything much
/// shorter prints the same answer repeatedly.
const POLL_INTERVAL: Duration = Duration::from_secs(15);

/// Give up printing after this many polls. Giving up watching is not a failure of the transfer — the
/// payment coin id is printed either way, so a human can keep looking.
const MAX_POLLS: u32 = 80;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let destination = args
        .next()
        .expect("usage: live_send <destination-xch1…> <amount-mojos> [endpoint]");
    let amount_mojos: u64 = args
        .next()
        .expect("usage: live_send <destination-xch1…> <amount-mojos> [endpoint]")
        .parse()
        .expect("the amount must be a whole number of mojos");
    let endpoint = args
        .next()
        .unwrap_or_else(|| "http://127.0.0.1:9778".into());

    let brand_dir = AppEnvironment::from_host()
        .brand_dir()
        .expect("this host has a DIG data directory");

    // Unlock through the app's own prompt. A wrong password or a cancelled window leaves the account
    // locked and ends this run having spent nothing.
    let booted = unlock_existing_account(&brand_dir, "send XCH from your DIG wallet")
        .expect("the account unlocked");
    let residency = booted.residency;

    // The sending address, printed BEFORE anything is built, so a human can confirm the money is
    // leaving the wallet they expect rather than a sibling profile's.
    let from = residency
        .receiving_address()
        .expect("an unlocked account")
        .expect("a derivable address");
    println!("endpoint            {endpoint}");
    println!("profile             {}", booted.profile_id);
    println!("sending from        {from}");
    println!("sending to          {destination}");
    println!("amount              {amount_mojos} mojos");
    println!("fee                 {DEFAULT_SEND_FEE_MOJOS} mojos");

    // Every send goes to the human: a zero auto-send allowance means no amount is small enough to
    // settle without a confirmation, and `AutoSendPolicy`'s default denies every op class as well.
    // The two defend different things, and this slice wants both. Making either configurable is
    // deferred; raising `auto_send_limit` above zero is precisely what would let a payment leave with
    // no human in the loop.
    let custody = CustodyPolicy::Hot(HotWallet { auto_send_limit: 0 });
    let money = MoneyPath::new(
        residency.clone(),
        // The PRODUCTION ceremony. The spend confirmation a person sees here is the one the app
        // shows; a fake would make this run a proof about the fake.
        dig_app_core::account::auth::HarnessAuthProvider::new(PromptedCeremony::unlocking(
            "confirm this payment",
        )),
        // The account the residency was actually opened as. This string is what the confirm ceremony
        // NAMES to the user while asking them to approve a real payment, so a decorative label here
        // would have the dialog spend from one account while naming another.
        AccountId::new(DEFAULT_ACCOUNT_ID),
        dig_wallet_backend::types::Network::Mainnet,
        custody,
        AutoSendPolicy::default(),
        Arc::new(SystemClock),
    )
    .expect("an unlocked residency yields a money path");

    let chain = ControlChainSource::new(&endpoint);
    let publisher = ControlSpendPublisher::new(&endpoint);
    let request = TransferRequest::to_address(&destination, amount_mojos)
        .expect("a mainnet xch1… destination")
        .with_fee(DEFAULT_SEND_FEE_MOJOS);

    println!("\nbuilding, then asking you to confirm…");
    let in_flight = SendSession::new(&residency, &money, custody, &chain, &publisher)
        .send(&request)
        .await
        .unwrap_or_else(|e| panic!("the send did not reach the chain: {e}"));

    let pending = in_flight.pending();
    println!("\naccepted by the mempool — NOT yet a payment");
    println!("payment coin id     {}", pending.payment_coin_id());
    println!("pushed at height    {}", pending.pushed_at_height());

    for poll in 1..=MAX_POLLS {
        std::thread::sleep(POLL_INTERVAL);
        let peak = chain_peak(&chain);
        match transfer_status(pending, &chain) {
            Ok(TransferStatus::Awaiting { blocks_since_push }) => {
                println!(
                    "poll {poll:>3}  peak {peak}  {blocks_since_push} blocks since push  awaiting"
                );
            }
            Ok(TransferStatus::Confirmed(settled)) => {
                println!("poll {poll:>3}  peak {peak}  CONFIRMED");
                println!("\npayment coin id     {}", settled.payment_coin_id());
                println!("confirmed height    {}", settled.confirmed_height());
                println!("amount              {} mojos", settled.amount_mojos());
                return;
            }
            Ok(TransferStatus::Failed { reason }) => {
                println!("poll {poll:>3}  peak {peak}  FAILED: {reason}");
                return;
            }
            // A read that failed is not a verdict. Print it and keep polling — the transfer is
            // unaffected by this app's ability to ask about it.
            Err(e) => println!("poll {poll:>3}  peak {peak}  could not read the chain: {e}"),
        }
    }

    println!(
        "\ngave up watching after {MAX_POLLS} polls; the transfer is unaffected. Coin id above."
    );
}

/// The chain's peak as a printable string — `?` where it cannot be read, since an unreadable peak is
/// not a height and must not be printed as one.
fn chain_peak(chain: &ControlChainSource) -> String {
    use dig_chainsource_interface::ChainSource;
    match chain.peak_height() {
        Ok(Some(height)) => height.to_string(),
        _ => "?".to_string(),
    }
}
