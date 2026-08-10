//! Manual real-node check for the control chain seams (dig_ecosystem#2560).
//!
//! NOT a test: CI has no dig-node, so this is a `cargo run --example` a human points at a live
//! node. It proves the client talks to the real server rather than only to a scripted fixture —
//! which a loopback double, however faithful, cannot establish.
//!
//! Reads only; it never pushes, so it needs no control token and cannot spend.
//!
//! ```text
//! cargo run -p dig-app-core --example chain_probe -- <coin-id-hex> [endpoint]
//! ```
use dig_app_core::chain::ControlChainSource;
use dig_chainsource_interface::ChainSource;

fn main() {
    let mut args = std::env::args().skip(1);
    let coin_hex = args
        .next()
        .expect("usage: chain_probe <coin-id-hex> [endpoint]");
    let endpoint = args
        .next()
        .unwrap_or_else(|| "http://localhost:9778".into());
    let bytes: [u8; 32] = hex::decode(coin_hex.trim_start_matches("0x"))
        .expect("a 64-hex coin id")
        .try_into()
        .expect("32 bytes");
    let coin_id = chia_protocol::Bytes32::new(bytes);

    let source = ControlChainSource::new(&endpoint);
    println!("endpoint            {endpoint}");
    println!("peak_height         {:?}", source.peak_height());
    println!("coin_record         {:?}", source.coin_record(coin_id));
    println!(
        "coin_spend          {:?}",
        source.coin_spend(coin_id).map(|s| s.map(|s| s.coin.amount))
    );
    println!(
        "children            {:?}",
        source.coin_records_by_parent(coin_id).map(|c| c.len())
    );
    println!(
        "lineage             {:?}",
        source.resolve_singleton_lineage(coin_id).err()
    );
    println!("freshness           {:?}", source.last_freshness());
}
