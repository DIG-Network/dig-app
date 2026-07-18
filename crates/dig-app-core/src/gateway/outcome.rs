//! The gateway's result surface: a dual human/machine [`Outcome`], a catalogued [`GatewayError`],
//! and the `--json` envelope builders.
//!
//! Every gateway command produces the SAME shape for both audiences (§6.2 agent-friendly): a
//! human-prose `summary` (printed to stderr in the default mode) and a machine `result` object
//! (folded into the `--json` success envelope). Failures carry a stable, documented [`ErrorCode`]
//! — a symbolic name AND a numeric process exit code — so a script can branch on either without
//! scraping prose. The envelope shape matches the engine's own `dig-node` CLI so a caller sees ONE
//! consistent surface across the DIG command line.

use serde_json::{json, Value};

/// A documented, stable catalogue of gateway failure classes. Each maps a failure to a distinct
/// process exit code AND a stable UPPER_SNAKE symbolic name. The overlapping codes (`OK`, `USAGE`,
/// `IO_ERROR`) share the engine CLI's numbers so the two command lines agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// 0 — success.
    Ok,
    /// 2 — usage / bad argument error (e.g. an unsupported `open` scheme).
    Usage,
    /// 6 — an I/O error talking to the local channel or the browser opener.
    IoError,
    /// 7 — no identity-authenticated session to the engine (dig-app not attached / engine down).
    NotConnected,
    /// 8 — the engine accepted the request but the proxied `control.*` call returned an error.
    EngineError,
    /// 9 — no unlocked user identity, so a local sign / profile / wallet op cannot be served.
    Locked,
    /// 10 — the referenced object (profile, store) does not exist.
    NotFound,
    /// 11 — the user did not authorize the action at the native confirm (declined, timed out, or no
    /// confirmer is available on a headless host). A `dign sign` that is not human-approved fails here.
    Denied,
}

impl ErrorCode {
    /// The numeric process exit code.
    pub const fn code(self) -> u8 {
        match self {
            ErrorCode::Ok => 0,
            ErrorCode::Usage => 2,
            ErrorCode::IoError => 6,
            ErrorCode::NotConnected => 7,
            ErrorCode::EngineError => 8,
            ErrorCode::Locked => 9,
            ErrorCode::NotFound => 10,
            ErrorCode::Denied => 11,
        }
    }

    /// The stable UPPER_SNAKE symbolic name (the `--json` `error.code`).
    pub const fn name(self) -> &'static str {
        match self {
            ErrorCode::Ok => "OK",
            ErrorCode::Usage => "USAGE",
            ErrorCode::IoError => "IO_ERROR",
            ErrorCode::NotConnected => "NOT_CONNECTED",
            ErrorCode::EngineError => "ENGINE_ERROR",
            ErrorCode::Locked => "LOCKED",
            ErrorCode::NotFound => "NOT_FOUND",
            ErrorCode::Denied => "DENIED",
        }
    }

    /// Every failure code, for the discovery catalogue (`dign --help`-style introspection).
    pub const fn all() -> &'static [ErrorCode] {
        &[
            ErrorCode::Ok,
            ErrorCode::Usage,
            ErrorCode::IoError,
            ErrorCode::NotConnected,
            ErrorCode::EngineError,
            ErrorCode::Locked,
            ErrorCode::NotFound,
            ErrorCode::Denied,
        ]
    }
}

/// A gateway failure: a catalogued [`ErrorCode`], a human message, and an optional actionable hint.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct GatewayError {
    /// The stable failure class.
    pub code: ErrorCode,
    /// A human-readable, single-line description of what went wrong.
    pub message: String,
    /// An optional next-step hint for the user (e.g. "run `dign profiles select`").
    pub hint: Option<String>,
}

impl GatewayError {
    /// Build an error of `code` with `message` and no hint.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        GatewayError {
            code,
            message: message.into(),
            hint: None,
        }
    }

    /// Attach an actionable hint (builder style).
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

/// The successful outcome of a gateway command: a human `summary` and a machine `result` object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Human-readable, possibly multi-line, summary (stderr in the default mode).
    pub summary: String,
    /// Machine-readable result fields (an object), folded into the `--json` success envelope.
    pub result: Value,
}

impl Outcome {
    /// Build an outcome from a summary and a JSON result object.
    pub fn new(summary: impl Into<String>, result: Value) -> Self {
        Outcome {
            summary: summary.into(),
            result,
        }
    }
}

/// The `--json` success envelope: `{ ok:true, action, ...result }`. `action` is the command name;
/// the `result` object's fields are folded in at the top level (mirroring the engine CLI's shape).
pub fn success_envelope(action: &str, result: &Value) -> Value {
    let mut obj = json!({ "ok": true, "action": action });
    fold_fields(&mut obj, result);
    obj
}

/// The `--json` error envelope: `{ ok:false, action, error:{ code, exit_code, message, hint } }`.
pub fn error_envelope(action: &str, error: &GatewayError) -> Value {
    json!({
        "ok": false,
        "action": action,
        "error": {
            "code": error.code.name(),
            "exit_code": error.code.code(),
            "message": error.message,
            "hint": error.hint,
        },
    })
}

/// Fold the fields of a JSON object `result` into `target` at the top level. A non-object result is
/// nested under a `result` key so nothing is silently dropped.
fn fold_fields(target: &mut Value, result: &Value) {
    let (Value::Object(target), Value::Object(fields)) = (&mut *target, result) else {
        target["result"] = result.clone();
        return;
    };
    for (key, value) in fields {
        target.insert(key.clone(), value.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_unique_in_both_name_and_number() {
        let mut numbers = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        for code in ErrorCode::all() {
            assert!(
                numbers.insert(code.code()),
                "duplicate exit code {}",
                code.code()
            );
            assert!(names.insert(code.name()), "duplicate name {}", code.name());
            assert!(
                code.name()
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c == '_'),
                "{} is not UPPER_SNAKE",
                code.name()
            );
        }
    }

    #[test]
    fn overlapping_codes_match_the_engine_cli_numbers() {
        assert_eq!(ErrorCode::Ok.code(), 0);
        assert_eq!(ErrorCode::Usage.code(), 2);
        assert_eq!(ErrorCode::IoError.code(), 6);
    }

    #[test]
    fn success_envelope_folds_result_fields_and_marks_ok() {
        let env = success_envelope("info", &json!({ "serving": true, "peers": 3 }));
        assert_eq!(env["ok"], json!(true));
        assert_eq!(env["action"], json!("info"));
        assert_eq!(env["serving"], json!(true));
        assert_eq!(env["peers"], json!(3));
    }

    #[test]
    fn success_envelope_nests_a_non_object_result_under_result() {
        let env = success_envelope("sign", &json!("deadbeef"));
        assert_eq!(env["ok"], json!(true));
        assert_eq!(env["result"], json!("deadbeef"));
    }

    #[test]
    fn error_envelope_carries_symbolic_and_numeric_code_and_hint() {
        let err = GatewayError::new(ErrorCode::NotConnected, "engine session not attached")
            .with_hint("start dig-app and unlock a profile");
        let env = error_envelope("stores", &err);
        assert_eq!(env["ok"], json!(false));
        assert_eq!(env["error"]["code"], json!("NOT_CONNECTED"));
        assert_eq!(env["error"]["exit_code"], json!(7));
        assert_eq!(
            env["error"]["message"],
            json!("engine session not attached")
        );
        assert_eq!(
            env["error"]["hint"],
            json!("start dig-app and unlock a profile")
        );
    }

    #[test]
    fn error_envelope_hint_is_null_when_absent() {
        let err = GatewayError::new(ErrorCode::Usage, "bad args");
        let env = error_envelope("open", &err);
        assert_eq!(env["error"]["hint"], Value::Null);
    }
}
