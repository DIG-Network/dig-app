//! The `live_send` example must perform its unlock OUTSIDE any tokio runtime.
//!
//! # The bug this exists to catch, which really happened
//!
//! `unlock_existing_account` is synchronous by design and bridges to the async unlock ceremony by
//! building its OWN current-thread runtime and calling `block_on` (`src/account/boot.rs:295`), so that
//! the tray shell need not own a runtime. Tokio refuses to start a runtime from within a runtime, so
//! an `async fn main` under `#[tokio::main]` panics at that bridge — which is exactly what the first
//! revision of the example did, and it was found by RUNNING it, not by compiling it.
//!
//! # Why this is a source-text test, and what it can and cannot see
//!
//! An example's `main` cannot be called from a test: it is a separate binary, and running it would
//! prompt for a password and spend real money. The panic also needs a real account, a real prompt and
//! a real node, none of which CI has. So the property is checked where it is decidable — in the source
//! — by asserting the ORDER of the two constructs.
//!
//! It is honest about being narrow. It cannot see a runtime entered some third way (a `Handle`, a
//! nested helper, a dependency that installs one), and it would not catch the same mistake in a
//! different file. What it does catch is the specific, cheap-to-reintroduce regression: putting the
//! unlock back inside a runtime by attributing `main` or by hoisting the runtime above the unlock.

/// The example's CODE, with every comment line dropped.
///
/// Stripping comments is not tidiness — it is required for correctness. The example documents this
/// very hazard by NAMING `#[tokio::main]` in prose, so a naive substring search over the whole file
/// matches the explanation of the bug and fails on a correct file. That happened on the first run of
/// this test. A guard that cannot tell code from a comment about code is not measuring the code.
///
/// Read from `CARGO_MANIFEST_DIR` so the test does not depend on the working directory a runner
/// happens to choose.
fn live_send_code() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/live_send.rs");
    let source = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "the live_send example is readable at {}: {e}",
            path.display()
        )
    });
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join(
            "
",
        )
}

/// `main` must not be attributed onto a runtime.
///
/// The attribute is the one-line change that reintroduces the panic, and it looks entirely innocent
/// next to an `async` call.
#[test]
fn the_example_main_is_not_a_tokio_main() {
    let code = live_send_code();
    assert!(
        !code.contains("#[tokio::main"),
        "live_send's `main` must stay synchronous: `#[tokio::main]` puts the unlock inside a \
         runtime, and `unlock_existing_account` builds its own (src/account/boot.rs:295), which \
         tokio refuses"
    );
}

/// The unlock must come BEFORE any runtime is built.
///
/// Asserted as an order rather than as a presence, because both constructs are legitimately in this
/// file and only their sequence is the property. A test that merely confirmed the unlock was called
/// would pass just as happily with the runtime hoisted above it.
#[test]
fn the_unlock_happens_before_any_runtime_is_built() {
    let code = live_send_code();
    let unlock = code
        .find("unlock_existing_account(&brand_dir")
        .expect("live_send unlocks the account through the app's own boot path");
    let runtime = code
        .find("tokio::runtime::Builder")
        .expect("live_send builds a runtime for the send");
    assert!(
        unlock < runtime,
        "live_send must unlock BEFORE it builds a runtime; found the runtime at byte {runtime} and \
         the unlock at byte {unlock}"
    );
}
