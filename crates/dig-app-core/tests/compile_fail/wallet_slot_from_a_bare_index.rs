//! A `WalletSlot` must not be constructible from a bare `ProfileIx`.
//!
//! This is the direct successor of the property `open_or_enroll`'s signature has carried since
//! dig_ecosystem#2236: a wallet may be opened only at an index something vouched for. Both forms are
//! exercised because they fail for DIFFERENT reasons — the tuple form because the field is private,
//! the `From` form because no such conversion exists — and a refactor could reintroduce either one
//! alone.
use dig_account::ProfileIx;
use dig_app_core::account::WalletSlot;

fn main() {
    let _tuple = WalletSlot(ProfileIx(1));
    let _converted = WalletSlot::from(ProfileIx(1));
}
