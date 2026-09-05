//! Drive the REAL second-factor enrolment windows, against a throwaway account (dig-app#348).
//!
//! Unit tests can prove the sequence and the verifier; they cannot prove that a real security key
//! completes the platform's own ceremony, or that the windows are legible. This example is how that is
//! checked: it runs the production journey through the production [`native_confirmer`] AND the
//! production [`platform_authenticator`], so every window it draws is the one a user gets — the same
//! window class, the same DPI scaling, the same Windows Hello prompt, and the same `webauthn.dll`
//! ceremony against real hardware.
//!
//! ```text
//! cargo run -p dig-app-core --example second_factor_demo
//! ```
//!
//! It seals into a TEMPORARY directory under a demo sealer, so it touches no real account and leaves
//! nothing behind. That is also its limit: it exercises the FLOW and the WINDOWS, not the production
//! DIGOP1 sealing, which the vault's own tests cover.
//!
//! Walk it end to end with a real roaming key: touch the security key when the platform asks, then
//! confirm the recovery codes it shows. Then let it run the disable step, which must raise Windows
//! Hello / Touch ID AND ask for the factor itself before it will turn anything off (dig-app#349) -- a
//! recovery code works there too, which is the lost-key way out.
//!
//! On a build with no WebAuthn client (macOS and Linux today, dig-app#372) the enrolment step refuses
//! before drawing any window and the run stops there. That is the honest outcome, not a failure of the
//! example.

use std::path::Path;

use dig_app_core::account::second_factor::authenticator::platform_authenticator;
use dig_app_core::account::second_factor::journey::{
    challenge, disable_locked, disable_unlocked, enrol, EnrolOutcome, SystemClock,
};
use dig_app_core::account::second_factor::vault::DirectoryEnrolment;
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
    // The client this build ships: the real `webauthn.dll` ceremony on Windows, and `NoProvider`
    // everywhere else. Deliberately not a test double — proving the platform accepts a real key is
    // the only thing this example can prove that the unit tests cannot.
    let authenticator = platform_authenticator();
    let vault = SecondFactorVault::new(DemoSealer, dir, "did:chia:demo-profile");

    println!("Enrolment windows follow. Every one of them can be closed without enrolling.");
    let outcome = enrol(confirmer.as_ref(), &vault, authenticator.as_ref());
    println!("enrol    : {outcome:?}");
    if !matches!(outcome, EnrolOutcome::Enrolled { .. }) {
        println!("Nothing was enrolled, so there is nothing left to demonstrate.");
        return;
    }

    // The challenge a destructive verb runs. Touch the key to walk the ordinary path; decline it and
    // answer with a RECOVERY code instead to walk the lost-key path, which is the one that has to
    // work when the key this was all set up on is gone.
    println!("A factor challenge follows — the one replacing or removing an account has to pass.");
    println!(
        "challenge: {:?}",
        challenge(
            confirmer.as_ref(),
            &vault,
            authenticator.as_ref(),
            "replace this account",
            &SystemClock
        )
    );

    // The LOCKED branch first, because it is the one that must REFUSE. It draws no window at all --
    // there is no confirmer to draw with -- so a run that pops anything here is a defect.
    println!(
        "locked   : {:?}  (must be NeedsUnlock, and no window may appear)",
        disable_locked(&DirectoryEnrolment::new(dir))
    );

    println!(
        "Disable windows follow; they must ask Hello AND the factor before removing anything."
    );
    println!(
        "disable  : {:?}",
        disable_unlocked(
            confirmer.as_ref(),
            &vault,
            authenticator.as_ref(),
            &SystemClock
        )
    );
}
