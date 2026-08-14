//! A second send cannot be started while one is in flight.
//!
//! # Why a compile-fail test rather than a runtime one
//!
//! The property is that the second call is UNEXPRESSIBLE. A runtime test could only observe that some
//! guard returned an error, and would pass identically in a build where the guard had been replaced by
//! a boolean a caller can forget to check — which is the regression this exists to catch.
//!
//! No session is constructed here, deliberately: the property belongs to `send`'s signature (it takes
//! `self` by value), so a generic function that merely HOLDS a session is enough to ask the question,
//! and asking it that way keeps the answer free of any fixture's own failures.
use dig_account::mint::SpendPublisher;
use dig_account::{AuthProvider, TransferRequest};
use dig_app_core::wallet::send::SendSession;
use dig_chainsource_interface::ChainSource;

async fn two_sends_from_one_session<C, Pub, P>(
    session: SendSession<'_, C, Pub, P>,
    request: &TransferRequest,
) where
    C: ChainSource + ?Sized,
    Pub: SpendPublisher + ?Sized,
    P: AuthProvider,
{
    let _first = session.send(request).await;
    let _second = session.send(request).await;
}

fn main() {}
