//! Human-readable transaction decoding for the APP-SIGN sign-confirm window (SIGN-2, `SPEC.md`
//! §5.6.5, **security-critical**).
//!
//! dig-app MUST NEVER present "sign these opaque bytes?" — a blind-sign request is refused (§5.6.5).
//! Before the native confirm (SIGN-3) can ask the human to authorize a signature, the payload is
//! decoded into human terms: for a spend, the recipients and amounts it creates plus the fee. This
//! module is that decoder.
//!
//! # The decode binds display to what is signed
//!
//! The signed message is the domain-separated `DIGNET-SIGN-v1 ‖ payload_type ‖ payload` (§5.6.5,
//! `session.rs::sign_callback_message`). To close the display-vs-signed gap a signing oracle would
//! otherwise exploit, **for `payload_type = "spend"` the `payload` IS the streamable
//! [`SpendBundle`] bytes** — the decoder renders directly from the same bytes that get signed, so the
//! human can never approve one transaction while a different one is signed. There is no separate
//! "decode hint" that could disagree with the payload.
//!
//! # Fail closed
//!
//! An unknown `payload_type` ⇒ [`DecodeReject::UnknownType`] (`SIGN_UNKNOWN_TYPE`); a known type whose
//! bytes do not decode ⇒ [`DecodeReject::BadPayload`] (`SIGN_BAD_PAYLOAD`). Either way nothing is
//! signed. The allowlist is exactly the set of `payload_type`s this module can render.

use chia_protocol::SpendBundle;
use chia_sdk_driver::{Layer, Puzzle, StandardLayer};
use chia_sdk_types::{run_puzzle, Condition};
use chia_sdk_utils::Address;
use chia_traits::Streamable;
use clvm_traits::FromClvm;
use clvmr::serde::node_from_bytes;
use clvmr::{Allocator, NodePtr};

/// The `payload_type` tag for a Chia spend bundle — the one decoder SIGN-2 ships (§5.6.5). Its
/// `payload` is the streamable [`SpendBundle`] bytes.
pub const SPEND_PAYLOAD_TYPE: &str = "spend";

/// Why a `sign.request` payload could not be decoded for display. Maps to the §5.6.7 wire codes
/// `SIGN_UNKNOWN_TYPE` and `SIGN_BAD_PAYLOAD`. Both mean "nothing was signed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeReject {
    /// `payload_type` is not on the decoder allowlist — a blind-sign request, refused.
    UnknownType,
    /// A known `payload_type` whose bytes did not decode into a displayable transaction.
    BadPayload,
}

/// One coin a spend creates: the human recipient (a bech32m `xch1…` address) and the amount in mojos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedOutput {
    /// The recipient rendered as a bech32m XCH address (falls back to the hex puzzle hash if the
    /// address cannot be encoded).
    pub recipient: String,
    /// The created amount, in mojos.
    pub amount: u64,
}

/// A transaction decoded into the human terms the sign-confirm window displays (§5.6.5): the outputs
/// it creates, the total it spends, and the fee. Rendered directly from the bytes that are signed.
///
/// **Only native-XCH sends are decoded to amounts.** A `payload_type = "spend"` bundle may spend a CAT
/// (e.g. $DIG — 3 decimals, `1 $DIG = 1000 CAT-mojos`) or an unrecognized puzzle. Those amounts are NOT
/// XCH mojos and their recipients are NOT plain XCH addresses, so rendering them with the XCH divisor +
/// an `xch1…` recipient would show a CONFIDENTLY-FALSE figure (a million-$DIG drain reading as dust XCH).
/// To stay honest, [`outputs`](Self::outputs) enumerates ONLY the outputs of native-XCH standard-p2
/// coin spends; when the bundle also spends a non-XCH coin, [`all_inputs_native_xch`](Self::all_inputs_native_xch)
/// is `false` and the summary fails closed with a warning instead of a fabricated amount (WSEC-B). The
/// full CAT/$DIG-aware rendering is a separate follow-up (#958's CAT decoder).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTx {
    /// The native-XCH coins the spend creates (`CREATE_COIN` outputs of standard-p2 spends), in order.
    /// Non-XCH (CAT / unrecognized) outputs are deliberately NOT included — they cannot be verified as
    /// XCH (see [`all_inputs_native_xch`](Self::all_inputs_native_xch)).
    pub outputs: Vec<DecodedOutput>,
    /// The total input the spend consumes, in mojos (the sum of the spent coins' amounts). This is the
    /// raw coin amount regardless of asset, so for a CAT coin it is a CAT-mojo count, not XCH.
    pub total_input: u64,
    /// The network fee, in mojos (`total_input − total_created`). Only meaningful — and only shown as an
    /// XCH figure — when [`all_inputs_native_xch`](Self::all_inputs_native_xch) is `true`; a mixed/CAT
    /// bundle makes this arithmetic meaningless, so it is `0` and the summary suppresses it.
    pub fee: u64,
    /// `true` iff EVERY spent coin is a native-XCH standard-p2 coin. When `false` the bundle spends a
    /// CAT (e.g. $DIG) or an unrecognized puzzle whose amounts/recipients cannot be safely rendered as
    /// XCH; the summary then refuses to print a figure for the non-XCH portion (WSEC-B, fail-closed).
    pub all_inputs_native_xch: bool,
}

impl DecodedTx {
    /// The raw, mojo-level decode for the confirm window's details section (one fact per line): each
    /// native-XCH recipient + amount, a note when a non-XCH asset is also spent, then the fee and total.
    /// Denominated in mojos (1 XCH = 1_000_000_000_000 mojos).
    pub fn summary(&self) -> String {
        let mut lines = Vec::with_capacity(self.outputs.len() + 3);
        for output in &self.outputs {
            lines.push(format!(
                "Send {} mojos to {}",
                output.amount, output.recipient
            ));
        }
        if self.all_inputs_native_xch {
            lines.push(format!("Fee: {} mojos", self.fee));
        } else {
            lines.push(
                "Also spends a non-XCH asset (e.g. a CAT / $DIG token); its amounts and recipients \
                 are not shown, and the XCH fee cannot be derived."
                    .to_string(),
            );
        }
        lines.push(format!("Total spent: {} mojos", self.total_input));
        lines.join("\n")
    }
}

/// Decode `payload` of kind `payload_type` into a displayable [`DecodedTx`], or reject it so the
/// caller refuses to sign (§5.6.5, fail-closed).
///
/// The only known type is [`SPEND_PAYLOAD_TYPE`]; any other ⇒ [`DecodeReject::UnknownType`].
pub fn decode(payload_type: &str, payload: &[u8]) -> Result<DecodedTx, DecodeReject> {
    match payload_type {
        SPEND_PAYLOAD_TYPE => decode_spend(payload),
        _ => Err(DecodeReject::UnknownType),
    }
}

/// Decode a streamable [`SpendBundle`] into its created outputs + fee by running each coin spend's
/// puzzle and reading its `CREATE_COIN` conditions. Any parse or evaluation failure ⇒
/// [`DecodeReject::BadPayload`] (never a partial render).
fn decode_spend(payload: &[u8]) -> Result<DecodedTx, DecodeReject> {
    let bundle = SpendBundle::from_bytes(payload).map_err(|_| DecodeReject::BadPayload)?;

    let mut allocator = Allocator::new();
    let mut outputs = Vec::new();
    let mut total_input: u64 = 0;
    let mut total_created: u64 = 0;
    let mut all_inputs_native_xch = true;

    for spend in &bundle.coin_spends {
        total_input = total_input.saturating_add(spend.coin.amount);
        match native_xch_outputs(&mut allocator, spend)? {
            Some(spend_outputs) => {
                for output in spend_outputs {
                    total_created = total_created.saturating_add(output.amount);
                    outputs.push(output);
                }
            }
            // A CAT / unrecognized coin: its outputs are not XCH and are deliberately not rendered.
            None => all_inputs_native_xch = false,
        }
    }

    // The XCH fee is only derivable when every input is native XCH; a mixed bundle leaves it at 0 and
    // the summary suppresses it rather than showing a meaningless figure (WSEC-B, fail-closed).
    let fee = if all_inputs_native_xch {
        total_input.saturating_sub(total_created)
    } else {
        0
    };

    Ok(DecodedTx {
        outputs,
        total_input,
        fee,
        all_inputs_native_xch,
    })
}

/// Classify one coin spend and, if it is a native-XCH standard-p2 spend, run it and collect its
/// `CREATE_COIN` outputs. Returns:
///
/// - `Ok(Some(outputs))` — a standard-p2 (native XCH) spend; the outputs are real XCH sends.
/// - `Ok(None)` — a CAT or otherwise unrecognized outer puzzle: NOT native XCH. The puzzle is
///   deliberately NOT run (we neither trust nor render its CAT-denominated outputs), so the caller
///   flags the whole transaction as non-native and the summary fails closed with a warning (WSEC-B).
/// - `Err(BadPayload)` — a standard puzzle whose bytes/conditions do not decode; fail the whole decode.
///
/// The classification uses [`StandardLayer::parse_puzzle`], which recognizes ONLY the canonical
/// standard-p2 (`p2_delegated_puzzle_or_hidden_puzzle`) mod hash — a CAT's outer puzzle has a different
/// mod hash and is rejected, so a CAT can never be mistaken for a plain XCH send.
fn native_xch_outputs(
    allocator: &mut Allocator,
    spend: &chia_protocol::CoinSpend,
) -> Result<Option<Vec<DecodedOutput>>, DecodeReject> {
    let puzzle_ptr = node_from_bytes(allocator, spend.puzzle_reveal.as_ref())
        .map_err(|_| DecodeReject::BadPayload)?;

    // Is the outer puzzle the canonical standard-p2 (native XCH) layer? Anything else — a CAT ($DIG),
    // NFT, or unknown puzzle — is not a verifiable XCH send.
    if StandardLayer::parse_puzzle(allocator, Puzzle::parse(allocator, puzzle_ptr))
        .ok()
        .flatten()
        .is_none()
    {
        return Ok(None);
    }

    let solution = node_from_bytes(allocator, spend.solution.as_ref())
        .map_err(|_| DecodeReject::BadPayload)?;
    let conditions =
        run_puzzle(allocator, puzzle_ptr, solution).map_err(|_| DecodeReject::BadPayload)?;
    let conditions =
        Vec::<NodePtr>::from_clvm(allocator, conditions).map_err(|_| DecodeReject::BadPayload)?;

    let mut outputs = Vec::new();
    for condition in conditions {
        if let Ok(Condition::CreateCoin(create)) =
            Condition::<NodePtr>::from_clvm(allocator, condition)
        {
            outputs.push(DecodedOutput {
                recipient: render_recipient(create.puzzle_hash),
                amount: create.amount,
            });
        }
    }
    Ok(Some(outputs))
}

/// Render a coin's puzzle hash as the `xch1…` bech32m address the confirm window shows, falling back
/// to the raw hex hash if bech32m encoding fails (display only — never affects what is signed).
fn render_recipient(puzzle_hash: chia_protocol::Bytes32) -> String {
    Address::new(puzzle_hash, "xch".to_string())
        .encode()
        .unwrap_or_else(|_| hex::encode(puzzle_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_bls::{PublicKey, SecretKey, Signature};
    use chia_protocol::{Bytes32, Coin, CoinSpend};
    use chia_puzzle_types::cat::CatArgs;
    use chia_puzzle_types::standard::StandardArgs;
    use chia_puzzle_types::{DeriveSynthetic, Memos};
    use chia_sdk_driver::{Layer, SpendContext, StandardLayer};
    use chia_sdk_types::conditions::CreateCoin;
    use chia_sdk_types::Conditions;
    use chip35_dl_coin::master_to_wallet_unhardened;

    /// A synthetic standard-layer public key from a seed — the on-chain spending key of a wallet.
    fn synthetic_pk(seed: u8) -> PublicKey {
        let master = SecretKey::from_seed(&[seed; 32]);
        master_to_wallet_unhardened(&master.public_key(), 0).derive_synthetic()
    }

    /// A standard puzzle hash (bech32m-encodable), for a `CREATE_COIN` recipient.
    fn recipient_ph(seed: u8) -> Bytes32 {
        StandardArgs::curry_tree_hash(synthetic_pk(seed)).into()
    }

    /// Build a real spend bundle: a standard-layer coin of `input` mojos owned by `spender` that
    /// creates one coin of `pay` mojos to `recipient`. The remainder is the (implicit) fee.
    fn spend_bundle_bytes(spender: u8, input: u64, recipient: Bytes32, pay: u64) -> Vec<u8> {
        let pk = synthetic_pk(spender);
        let mut ctx = SpendContext::new();
        let coin = Coin {
            parent_coin_info: Bytes32::new([1u8; 32]),
            puzzle_hash: StandardArgs::curry_tree_hash(pk).into(),
            amount: input,
        };
        let conditions = Conditions::new().with(CreateCoin::new(recipient, pay, Memos::None));
        StandardLayer::new(pk)
            .spend(&mut ctx, coin, conditions)
            .expect("standard-layer spend of an owned coin");
        let coin_spends = ctx.take();
        SpendBundle::new(coin_spends, Signature::default())
            .to_bytes()
            .expect("streamable spend bundle")
    }

    /// Build a spend bundle whose one coin is a CAT (e.g. $DIG): the standard p2 puzzle wrapped in the
    /// CAT outer layer. Its outer mod hash is the CAT puzzle, NOT standard-p2, so the decoder must
    /// classify it as non-native-XCH. The amount (`1_000_000_000` CAT-mojos = 1,000,000 $DIG) is the
    /// exact drain that would misrender as a dust "0.000001 XCH" if treated as XCH.
    fn cat_spend_bundle_bytes(spender: u8, cat_mojos: u64) -> Vec<u8> {
        let pk = synthetic_pk(spender);
        let mut ctx = SpendContext::new();
        let inner_puzzle = StandardLayer::new(pk)
            .construct_puzzle(&mut ctx)
            .expect("standard inner puzzle");
        let asset_id = Bytes32::new([7u8; 32]);
        let outer_puzzle = ctx
            .curry(CatArgs::new(asset_id, inner_puzzle))
            .expect("CAT outer puzzle");
        let coin = Coin {
            parent_coin_info: Bytes32::new([1u8; 32]),
            puzzle_hash: ctx.tree_hash(outer_puzzle).into(),
            amount: cat_mojos,
        };
        // A nil solution — the decoder classifies the CAT by its puzzle and never runs it, so the
        // solution is irrelevant to the assertion (it is only rendered for native-XCH spends).
        let coin_spend = CoinSpend::new(
            coin,
            ctx.serialize(&outer_puzzle).expect("serialize CAT puzzle"),
            ctx.serialize(&NodePtr::NIL)
                .expect("serialize nil solution"),
        );
        SpendBundle::new(vec![coin_spend], Signature::default())
            .to_bytes()
            .expect("streamable CAT spend bundle")
    }

    #[test]
    fn a_cat_spend_is_flagged_non_native_and_never_rendered_as_xch() {
        // 1_000_000 $DIG (1e9 CAT-mojos). As XCH this would read as a reassuring "0.000001 XCH" — the
        // exact blind-sign trap WSEC-B closes. The decoder must NOT claim any XCH output for it.
        let bytes = cat_spend_bundle_bytes(3, 1_000_000_000);
        let decoded =
            decode(SPEND_PAYLOAD_TYPE, &bytes).expect("a CAT bundle decodes structurally");

        assert!(
            !decoded.all_inputs_native_xch,
            "a CAT spend must be flagged as non-native XCH"
        );
        assert!(
            decoded.outputs.is_empty(),
            "no XCH output amount/recipient may be claimed for a CAT spend, got {:?}",
            decoded.outputs
        );
        assert_eq!(
            decoded.fee, 0,
            "the XCH fee is suppressed for a non-native bundle"
        );
        // The raw details name the non-XCH asset instead of a fabricated figure.
        assert!(decoded.summary().contains("non-XCH asset"));
    }

    #[test]
    fn an_unknown_payload_type_is_rejected_as_a_blind_sign() {
        assert_eq!(
            decode("chip35.mystery", b"whatever"),
            Err(DecodeReject::UnknownType)
        );
    }

    #[test]
    fn a_spend_payload_that_is_not_a_bundle_is_bad_payload() {
        assert_eq!(
            decode(SPEND_PAYLOAD_TYPE, b"not a spend bundle"),
            Err(DecodeReject::BadPayload)
        );
    }

    #[test]
    fn a_spend_decodes_to_its_recipient_amount_and_fee() {
        let recipient = recipient_ph(9);
        let bytes = spend_bundle_bytes(3, 1_000, recipient, 800);

        let decoded = decode(SPEND_PAYLOAD_TYPE, &bytes).expect("a real bundle decodes");

        assert!(
            decoded.all_inputs_native_xch,
            "a standard-p2 spend is native XCH"
        );
        assert_eq!(decoded.total_input, 1_000);
        assert_eq!(decoded.fee, 200, "fee is input minus created");
        assert_eq!(decoded.outputs.len(), 1);
        assert_eq!(decoded.outputs[0].amount, 800);
        assert!(
            decoded.outputs[0].recipient.starts_with("xch1"),
            "recipient renders as a bech32m address, got {}",
            decoded.outputs[0].recipient
        );
    }

    #[test]
    fn the_summary_names_the_recipient_amount_and_fee() {
        let bytes = spend_bundle_bytes(4, 500, recipient_ph(7), 500);
        let decoded = decode(SPEND_PAYLOAD_TYPE, &bytes).unwrap();
        let summary = decoded.summary();
        assert!(summary.contains("Send 500 mojos to xch1"));
        assert!(summary.contains("Fee: 0 mojos"));
        assert!(summary.contains("Total spent: 500 mojos"));
    }
}
