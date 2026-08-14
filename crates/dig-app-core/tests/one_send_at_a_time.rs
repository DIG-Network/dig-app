//! A profile can have only ONE send in flight, and the compiler is what enforces it.
//!
//! `SendSession::send` consumes the session, so the second call has nothing left to call it on. That
//! is the whole guarantee — there is no flag, no lock and no window in which two sends could both be
//! building against the same coins and select the same input twice.

/// Starting a second send from a session already spent on one must fail to compile.
#[test]
fn a_session_cannot_start_a_second_send() {
    trybuild::TestCases::new().compile_fail("tests/compile_fail/two_sends_from_one_session.rs");
}
