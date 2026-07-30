//! Drive the REAL second-factor enrolment windows, against a throwaway account (dig_ecosystem#1840).
//!
//! Unit tests can prove the arithmetic and the sequence; they cannot prove that a real authenticator app
//! accepts the key we print, or that the windows are legible. This example is how that is checked: it
//! runs the production journey through the production [`native_confirmer`], so every window it draws is
//! the one a user gets — the same window class, the same DPI scaling, the same Windows Hello prompt.
//!
//! ```text
//! cargo run -p dig-app-core --example second_factor_demo
//! ```
//!
//! It seals into a TEMPORARY directory under a demo sealer, so it touches no real account and leaves
//! nothing behind. That is also its limit: it exercises the FLOW and the WINDOWS, not the production
//! DIGOP1 sealing, which the vault's own tests cover.
//!
//! Walk it end to end with a phone: type the key it shows into an authenticator, enter the code it then
//! asks for, and confirm the recovery codes. Then let it run the disable step, which must raise Windows
//! Hello / Touch ID before it will turn anything off.

use std::path::Path;

use dig_app_core::account::second_factor::journey::{
    challenge, disable, enrol, EnrolOutcome, SystemClock,
};
use dig_app_core::account::second_factor::vault::SecondFactorVault;
use dig_app_core::confirm::native_confirmer;
use dig_app_core::sealer::{ProfileSealer, SealError};
use zeroize::Zeroizing;

/// A demo sealer: a keyed prefix, NOT a cipher.
///
/// The production sealer needs an unlocked account, which this example deliberately does not have. Using
/// an obviously-fake sealer keeps that honest — nobody can mistake this example's temporary blob for a
/// real at-rest artifact — while still exercising the vault's write/read/domain-tag path.
struct DemoSealer;

impl ProfileSealer for DemoSealer {
    fn seal(&self, profile_did: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let mut out = format!("{profile_did}|").into_bytes();
        out.extend_from_slice(plaintext);
        Ok(out)
    }

    fn open(&self, profile_did: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let prefix = format!("{profile_did}|").into_bytes();
        ciphertext
            .strip_prefix(&prefix[..])
            .map(|rest| Zeroizing::new(rest.to_vec()))
            .ok_or(SealError::Open)
    }
}

fn main() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    run(dir.path());
}

/// The whole walkthrough, so `main` stays a two-liner.
fn run(dir: &Path) {
    let confirmer = native_confirmer();
    let vault = SecondFactorVault::new(DemoSealer, dir, "did:chia:demo-profile");

    println!("Enrolment windows follow. Every one of them can be closed without enrolling.");
    let outcome = enrol(confirmer.as_ref(), &vault, &SystemClock);
    println!("enrol    : {outcome:?}");
    if !matches!(outcome, EnrolOutcome::Enrolled { .. }) {
        println!("Nothing was enrolled, so there is nothing left to demonstrate.");
        return;
    }

    // The challenge a destructive verb runs. Answer it with a RECOVERY code rather than an
    // authenticator code to walk the lost-phone path, which is the one that has to work when the
    // device this was all set up on is gone.
    println!("A code challenge follows — the one replacing or removing an account has to pass.");
    println!(
        "challenge: {:?}",
        challenge(
            confirmer.as_ref(),
            &vault,
            "replace this account",
            &SystemClock
        )
    );

    println!("Disable window follows; it must ask the platform authenticator before it removes anything.");
    println!("disable  : {:?}", disable(confirmer.as_ref(), &vault));
}
