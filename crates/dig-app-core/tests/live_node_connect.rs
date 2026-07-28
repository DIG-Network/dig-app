//! Does dig-app connect to a REAL dig-node on this machine? (dig_ecosystem#949)
//!
//! Everything else about the connector is proven against a fake node over a real socket in
//! `control`/`engine`'s own unit tests. This test closes the last gap those cannot: that the bytes
//! the connector sends are the bytes an ACTUAL installed dig-node accepts — the class of drift a
//! symmetric fake can never catch, because the fake was written from the same reading of the wire.
//!
//! It is `#[ignore]`d because it needs a dig-node installed and running, which CI does not have. Run
//! it on a machine that has one:
//!
//! ```text
//! cargo test -p dig-app-core --test live_node_connect -- --ignored --nocapture
//! ```

use std::time::Duration;

use dig_app_core::engine::{EngineConnector, EngineState, NodeConnector};

/// The connector must find the locally-installed node through the §5.3 ladder alone — no configured
/// endpoint, no hand-fed token — and come back with the node's own status.
#[test]
#[ignore = "needs a dig-node installed and running on this machine"]
fn the_connector_reaches_the_locally_installed_dig_node() {
    let state = NodeConnector::new(Duration::from_secs(3)).probe("");

    let EngineState::Connected { endpoint, status } = &state else {
        panic!(
            "no node was reached. Start one with `dig-node run` (or `dig-node start`) and re-run.\n\
             state: {state:?}"
        );
    };

    println!("connected to {endpoint}: {}", state.summary());
    assert!(status.running, "a responding node reports running=true");
    assert_eq!(
        status.service, "dig-node",
        "the answering service must identify as dig-node"
    );
    assert!(
        !status.version.is_empty(),
        "the node must report its version — this is what the tray displays"
    );
    // A real node has been up for some time and knows its own bound address; both being present is
    // what distinguishes a genuine snapshot from a default-constructed one.
    assert!(status.addr.contains(':'), "addr should be host:port");
}
