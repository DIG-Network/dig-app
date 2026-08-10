//! A `WalletSlot` must not be constructible from a bare `ProfileIx`.
//!
//! This is the direct successor of the property `open_or_enroll`'s signature has carried since
//! dig_ecosystem#2236: a wallet may be opened only at an index something vouched for. Both forms are
//! exercised because they fail for DIFFERENT reasons — the tuple form because the field is private,
//! the conversion form because no such conversion exists — and a refactor could reintroduce either
//! one alone.
//!
//! # Why the conversion is written as `.into()` and not as `WalletSlot::from(..)`
//!
//! `WalletSlot::from(ix)` resolves to the reflexive `From<WalletSlot>` impl, so rustc reports a type
//! mismatch and attaches a `note: associated function defined here` pointing INTO `core`. Whether
//! that note carries the std source lines under it depends on whether the `rust-src` component is
//! installed — which is true on a developer machine with rust-analyzer and false on CI. `trybuild`
//! compares stderr exactly, so the guard passed or failed on the ENVIRONMENT rather than on the
//! code, and it failed on all three CI platforms while passing locally.
//!
//! `.into()` asks the same question and gets an answer that never leaves this crate: *the trait
//! `From<ProfileIx>` is not implemented for `WalletSlot`*. It is also the stronger phrasing, because
//! it names the missing impl rather than a mismatched argument.
use dig_account::ProfileIx;
use dig_app_core::account::WalletSlot;

fn main() {
    let _tuple = WalletSlot(ProfileIx(1));
    let _converted: WalletSlot = ProfileIx(1).into();
}
