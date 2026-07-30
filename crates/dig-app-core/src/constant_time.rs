//! One comparison, shared by every place that checks a typed secret.
//!
//! Two-factor codes and pairing codes are both short strings a person types, and both are checked
//! against a value the app holds. A `==` on either would leak, through timing, how many leading
//! characters a guess got right — which turns one search of the whole space into a short sequence of
//! per-character searches. Both therefore need the same comparison, and having it in one place is what
//! stops one of them quietly regressing to `==`.
//!
//! This is the standard accumulate-the-difference comparison, not a new primitive; the RustCrypto
//! `hmac` dependency's own `verify_slice` does exactly this for MAC tags, but it cannot be pointed at
//! a decimal or base32 string.

/// Compare two byte strings without an early exit on the first differing byte.
///
/// Lengths are compared first and IN THE CLEAR, deliberately: the length of both callers' secrets is
/// public and fixed (a TOTP code is always six digits, a pairing code always eight symbols), so a
/// length mismatch reveals only that the caller typed the wrong number of characters — something they
/// can already see on their own screen.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_strings_compare_equal() {
        assert!(constant_time_eq(b"ABCD1234", b"ABCD1234"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn a_difference_anywhere_is_caught() {
        // The first byte, the last byte, and the middle — an accumulator that forgot to fold one
        // position would pass one of these.
        assert!(!constant_time_eq(b"XBCD1234", b"ABCD1234"));
        assert!(!constant_time_eq(b"ABCD123X", b"ABCD1234"));
        assert!(!constant_time_eq(b"ABXD1234", b"ABCD1234"));
    }

    #[test]
    fn a_prefix_is_not_a_match() {
        // A length-blind fold over `zip` would stop at the shorter input and call this equal.
        assert!(!constant_time_eq(b"ABCD", b"ABCD1234"));
        assert!(!constant_time_eq(b"ABCD1234", b"ABCD"));
    }
}
