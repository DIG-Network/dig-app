//! Print the `xch1…` address for each wallet public key the local node watches.
//!
//! NOT a test and not part of the product: a human-run probe that turns the hex keys
//! `control.wallet.watched` reports back into the addresses those keys receive at, so a live
//! wallet can be matched to a profile without guessing (dig_ecosystem#2819).
//!
//! ```text
//! cargo run -p dig-app-core --example watched_addresses -- <pubkey-hex> [<pubkey-hex> …]
//! ```
use chia_bls::PublicKey;
use chia_puzzle_types::standard::StandardArgs;
use chia_sdk_utils::Address;

fn main() {
    for hex_key in std::env::args().skip(1) {
        let bytes: [u8; 48] = hex::decode(hex_key.trim_start_matches("0x"))
            .expect("a 96-hex public key")
            .try_into()
            .expect("48 bytes");
        let key = PublicKey::from_bytes(&bytes).expect("a valid BLS public key");
        let puzzle_hash = StandardArgs::curry_tree_hash(key).into();
        let address = Address::new(puzzle_hash, "xch".to_string())
            .encode()
            .expect("bech32m encode");
        println!("{hex_key}  {address}");
    }
}
