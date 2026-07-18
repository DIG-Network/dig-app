//! Plain-language spend summary for the APP-SIGN confirm dialog (WSEC-B, `SPEC.md` §5.6.5,
//! **security-critical / anti-blind-sign**).
//!
//! A user must never approve bytes they cannot read. [`crate::decode`] turns the signed payload into a
//! [`DecodedTx`] — the exact recipients, amounts, and fee carried in the bytes that get signed — but a
//! raw list of mojo amounts and puzzle hashes is still hard to net out at a glance. This module renders
//! that decode as a plain-language sentence ("Send 0.5 XCH to xch1abc…, plus a 0.001 XCH network fee"),
//! shown as the DEFAULT view in the confirm window, with the precise mojo-level decode kept below it as
//! details.
//!
//! # Display binds to what is signed
//!
//! The summary is derived ENTIRELY from the [`DecodedTx`] the policy already produced from the signed
//! bytes ([`crate::decode::decode`]) — there is no second decode source that could disagree. For a pure
//! native-XCH spend it renders EVERY output the decode enumerated (never a lossy subset), so the human
//! sees the full effect they authorize. When the bundle spends any non-XCH asset (a CAT such as $DIG, or
//! an unrecognized puzzle) the summary fails closed WHOLESALE to a single warning — never a fabricated
//! XCH amount, and never a genuine-but-small native line sitting beside the warning to lull the user.
//!
//! # Markup safety
//!
//! The summary is PLAIN text (recipients, decimal amounts, newlines) — it adds no markup. The per-OS
//! confirmers neutralize any markup-significant characters in the displayed text
//! (`confirm::linux::escape_kdialog_plain`, zenity `--no-markup`), so this module never needs to escape.

use crate::decode::{DecodedOutput, DecodedTx};

/// The number of mojos in one XCH (10¹²) — the denomination the confirm window shows amounts in.
const MOJOS_PER_XCH: u64 = 1_000_000_000_000;

/// The fail-closed warning shown when the bundle spends a non-XCH asset (a CAT such as $DIG, or an
/// unrecognized puzzle). We NEVER print a fabricated XCH amount or an `xch1…` recipient for it — a
/// confident-but-wrong number (e.g. a million-$DIG drain reading as dust XCH) is the exact blind-sign
/// trap WSEC-B closes. The full $DIG-aware rendering (real token + 3-decimal amount) is #958's CAT
/// decoder, which will replace this warning for recognized assets.
const NON_XCH_WARNING: &str = "\u{26a0} Non-XCH asset (e.g. a CAT / $DIG token) — its amount and \
     recipient CANNOT be verified in this view. Approve only if you fully trust the requesting dapp.";

/// Render a decoded spend as the confirm window's body: a plain-language summary as the default view,
/// followed by the precise mojo-level decode as details.
///
/// The summary leads with one line per created output ("Send `<amount>` XCH to `<recipient>`") and the
/// network fee, all in human XCH. The details section keeps [`DecodedTx::summary`]'s exact mojo figures
/// so a user who wants the raw numbers can still verify them. Both are derived from the same
/// [`DecodedTx`], so the display can never disagree with what is signed.
pub fn confirm_body(tx: &DecodedTx) -> String {
    format!("{}\n\nDetails:\n{}", plain_language(tx), tx.summary())
}

/// The plain-language, XCH-denominated summary of a decoded spend.
///
/// **Fail closed wholesale.** If the bundle spends ANY non-XCH asset ([`DecodedTx::all_inputs_native_xch`]
/// is `false`), the summary is ONLY [`NON_XCH_WARNING`] — no native-XCH `Send … XCH` lines and no fee
/// line survive beside it, so a genuine-but-small XCH send can never lull a user into approving a
/// larger CAT/$DIG transfer riding along in the same bundle (WSEC-B).
///
/// When every input is native XCH, it lists one line per output ("Send `<amount>` XCH to `<recipient>`",
/// recipients shown in full so the user can verify where funds go) plus the network fee. A native spend
/// with no outputs (a rare fee-burn) still ends with the fee line, so the window is never empty.
fn plain_language(tx: &DecodedTx) -> String {
    // Fail closed WHOLESALE: if ANY spent coin is non-XCH, show ONLY the warning — never a native-XCH
    // `Send … XCH` line beside it. A genuine-but-small XCH line next to the warning would lull a user
    // habituated to "small amount + warning" into approving while a $DIG drain rides along (WSEC-B).
    if !tx.all_inputs_native_xch {
        return NON_XCH_WARNING.to_string();
    }
    let mut lines: Vec<String> = tx.outputs.iter().map(describe_output).collect();
    lines.push(format!("Network fee: {} XCH", format_xch(tx.fee)));
    lines.join("\n")
}

/// One created output as a human sentence: the amount in XCH and its recipient address.
fn describe_output(output: &DecodedOutput) -> String {
    format!(
        "Send {} XCH to {}",
        format_xch(output.amount),
        output.recipient
    )
}

/// Format an amount in mojos as a human XCH string, trimming trailing zeros from the fractional part
/// (e.g. `500_000_000_000` → `"0.5"`, `1_000_000_000_000` → `"1"`, `1` → `"0.000000000001"`).
///
/// The full precision is preserved — an amount is never rounded away — so the summary stays faithful to
/// the signed bytes.
fn format_xch(mojos: u64) -> String {
    let whole = mojos / MOJOS_PER_XCH;
    let fraction = mojos % MOJOS_PER_XCH;
    if fraction == 0 {
        return whole.to_string();
    }
    let fraction = format!("{fraction:012}");
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(recipient: &str, amount: u64) -> DecodedOutput {
        DecodedOutput {
            recipient: recipient.to_string(),
            amount,
        }
    }

    #[test]
    fn whole_xch_amounts_render_without_a_fractional_part() {
        assert_eq!(format_xch(MOJOS_PER_XCH), "1");
        assert_eq!(format_xch(12 * MOJOS_PER_XCH), "12");
        assert_eq!(format_xch(0), "0");
    }

    #[test]
    fn fractional_xch_amounts_trim_trailing_zeros_and_keep_full_precision() {
        assert_eq!(format_xch(500_000_000_000), "0.5");
        assert_eq!(format_xch(1_500_000_000_000), "1.5");
        assert_eq!(format_xch(1), "0.000000000001");
        assert_eq!(format_xch(1_250_000_000_000), "1.25");
    }

    /// A native-XCH decode with the given outputs, total, and fee.
    fn native_tx(outputs: Vec<DecodedOutput>, total_input: u64, fee: u64) -> DecodedTx {
        DecodedTx {
            outputs,
            total_input,
            fee,
            all_inputs_native_xch: true,
        }
    }

    #[test]
    fn a_single_output_spend_reads_as_a_sentence() {
        let tx = native_tx(
            vec![output("xch1recipient", 500_000_000_000)],
            501_000_000_000,
            1_000_000_000,
        );
        let summary = plain_language(&tx);
        assert_eq!(
            summary,
            "Send 0.5 XCH to xch1recipient\nNetwork fee: 0.001 XCH"
        );
    }

    #[test]
    fn every_output_of_a_multi_output_spend_is_listed_never_a_subset() {
        let tx = native_tx(
            vec![
                output("xch1alice", 2_000_000_000_000),
                output("xch1bob", 3_000_000_000_000),
                output("xch1carol", 1),
            ],
            5_000_000_000_002,
            1,
        );
        let summary = plain_language(&tx);
        assert!(summary.contains("Send 2 XCH to xch1alice"));
        assert!(summary.contains("Send 3 XCH to xch1bob"));
        assert!(summary.contains("Send 0.000000000001 XCH to xch1carol"));
        assert!(summary.contains("Network fee: 0.000000000001 XCH"));
        assert_eq!(
            summary.lines().count(),
            4,
            "three outputs plus the fee line, nothing dropped"
        );
    }

    #[test]
    fn a_spend_with_no_outputs_still_names_the_fee() {
        let tx = native_tx(vec![], 1_000_000_000, 1_000_000_000);
        assert_eq!(plain_language(&tx), "Network fee: 0.001 XCH");
    }

    #[test]
    fn a_non_native_spend_warns_and_never_prints_a_fabricated_xch_amount() {
        // A CAT/$DIG (or unrecognized) spend: outputs are empty (decode refuses to claim XCH sends) and
        // the flag is false. The summary MUST show the warning and NO "XCH" figure or xch1 recipient.
        let tx = DecodedTx {
            outputs: vec![],
            total_input: 1_000_000_000,
            fee: 0,
            all_inputs_native_xch: false,
        };
        let summary = plain_language(&tx);
        assert_eq!(summary, NON_XCH_WARNING);
        assert!(
            !summary.contains(" XCH"),
            "never a confident '<amount> XCH' figure"
        );
        assert!(!summary.contains("xch1"), "never a plain-XCH recipient");
    }

    #[test]
    fn a_mixed_native_and_cat_bundle_fails_closed_wholesale() {
        // A bundle with a genuine native-XCH output AND a CAT/$DIG spend (flag false, decode having
        // dropped the CAT outputs). The summary MUST be ONLY the warning — no native `Send … XCH` line
        // may survive to sit reassuringly beside it while the CAT drain rides along (WSEC-B).
        let tx = DecodedTx {
            outputs: vec![output("xch1attacker", 100_000_000)],
            total_input: 100_000_000,
            fee: 0,
            all_inputs_native_xch: false,
        };
        let summary = plain_language(&tx);
        assert_eq!(summary, NON_XCH_WARNING);
        assert!(!summary.contains("Send"), "no native send line survives");
        assert!(
            !summary.contains(" XCH"),
            "no confident XCH figure survives"
        );
        assert!(!summary.contains("xch1"), "no XCH recipient survives");
    }

    #[test]
    fn the_confirm_body_shows_the_summary_first_then_the_raw_decode_as_details() {
        let tx = native_tx(vec![output("xch1recipient", 800)], 1_000, 200);
        let body = confirm_body(&tx);
        let (summary, details) = body
            .split_once("\n\nDetails:\n")
            .expect("the body leads with the summary, then a Details section");
        // Default view: plain-language XCH.
        assert!(summary.contains("Send 0.0000000008 XCH to xch1recipient"));
        assert!(summary.contains("Network fee: 0.0000000002 XCH"));
        // Details: the exact mojo decode is preserved for verification.
        assert_eq!(details, tx.summary());
        assert!(details.contains("800 mojos"));
    }
}
