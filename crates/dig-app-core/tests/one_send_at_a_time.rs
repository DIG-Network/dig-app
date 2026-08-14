//! One `SendSession` can be spent on only ONE send, and the compiler is what enforces it.
//!
//! `SendSession::send` consumes the session, so the second call has nothing left to call it on.
//!
//! # What this does NOT prove, stated because it once claimed to
//!
//! It is a property of the TYPE, not of the app. Consuming a value constrains only that value, and the
//! production path (`wallet::sending::SendHolder::send`) builds a fresh session per attempt — so this
//! test says nothing about whether two sends can run at once there. That guarantee is
//! `SendHolder::begin`'s compare-and-set, and it is asserted directly in
//! `a_send_is_refused_while_another_is_in_flight_and_leaves_it_undisturbed`.
//!
//! This test is still worth having: the signature it pins is what stops a caller reusing a session
//! whose coins are already committed to a bundle.

/// Starting a second send from a session already spent on one must fail to compile.
#[test]
fn a_session_cannot_start_a_second_send() {
    trybuild::TestCases::new().compile_fail("tests/compile_fail/two_sends_from_one_session.rs");
}
