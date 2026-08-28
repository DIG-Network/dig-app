//! The minimal JSON-RPC 2.0 envelope the control catalog rides in.
//!
//! Transport-agnostic: a [`JsonRpcRequest`] carries a control method + its typed params, and a
//! [`JsonRpcResponse`] carries either a `result` or an `error` ([`ControlError`]). The catalog does
//! not own the transport (dig-ipc session, loopback-mTLS HTTP/WebSocket) — only these payload
//! shapes that travel over it. The shapes are byte-identical to what dig-node emits so both sides
//! serialize the same bytes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ControlError;

/// A JSON-RPC 2.0 request id: a number, a string, or null. dig-node accepts all three and echoes
/// the id verbatim on the response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// A numeric id (the common case).
    Number(i64),
    /// A string id.
    String(String),
    /// A null id.
    Null,
}

impl From<i64> for RequestId {
    fn from(n: i64) -> Self {
        RequestId::Number(n)
    }
}

impl From<&str> for RequestId {
    fn from(s: &str) -> Self {
        RequestId::String(s.to_string())
    }
}

/// A JSON-RPC 2.0 request: `{jsonrpc:"2.0", id, method, params}`.
///
/// `params` is a raw [`Value`] so the envelope stays method-agnostic; the typed params structs in
/// [`crate::params`] serialize into it via [`crate::traits::build_request`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// The request id, echoed on the response.
    pub id: RequestId,
    /// The control method's wire name (see [`crate::ControlMethod::name`]).
    pub method: String,
    /// The method params object.
    pub params: Value,
}

impl JsonRpcRequest {
    /// Build a request for `method` with `params`, stamping `jsonrpc:"2.0"`.
    pub fn new(id: RequestId, method: impl Into<String>, params: Value) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.into(),
            params,
        }
    }
}

/// A JSON-RPC 2.0 response: exactly one of `result` or `error` is present.
///
/// Modelled as two `Option` fields (matching the wire) rather than an enum, because dig-node emits
/// the flat `{jsonrpc, id, result}` / `{jsonrpc, id, error}` shapes and clients read them directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// The id echoed from the request.
    pub id: RequestId,
    /// The success result (present iff `error` is absent).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result: Option<Value>,
    /// The error (present iff `result` is absent).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<ControlError>,
}

impl JsonRpcResponse {
    /// Build a success response carrying `result`.
    pub fn success(id: RequestId, result: Value) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response carrying `error`.
    pub fn error(id: RequestId, error: ControlError) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    /// The result value if this is a success, else the [`ControlError`].
    pub fn into_result(self) -> Result<Value, ControlError> {
        match (self.result, self.error) {
            (Some(v), _) => Ok(v),
            (None, Some(e)) => Err(e),
            (None, None) => Err(ControlError::of(
                crate::error::ControlErrorCode::ControlError,
                "malformed JSON-RPC response: neither result nor error present",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ControlErrorCode;
    use serde_json::json;

    #[test]
    fn request_serializes_to_the_canonical_shape() {
        let req = JsonRpcRequest::new(1.into(), "control.status", json!({}));
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(
            v,
            json!({"jsonrpc":"2.0","id":1,"method":"control.status","params":{}})
        );
    }

    #[test]
    fn request_id_supports_number_string_and_null() {
        assert_eq!(serde_json::to_value(RequestId::from(7)).unwrap(), json!(7));
        assert_eq!(
            serde_json::to_value(RequestId::from("abc")).unwrap(),
            json!("abc")
        );
        assert_eq!(serde_json::to_value(RequestId::Null).unwrap(), json!(null));
        assert_eq!(
            serde_json::from_value::<RequestId>(json!("z")).unwrap(),
            RequestId::String("z".into())
        );
    }

    #[test]
    fn success_response_omits_the_error_field() {
        let resp = JsonRpcResponse::success(1.into(), json!({"ok":true}));
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v, json!({"jsonrpc":"2.0","id":1,"result":{"ok":true}}));
        assert_eq!(resp.into_result().unwrap(), json!({"ok":true}));
    }

    #[test]
    fn error_response_omits_the_result_field_and_unwraps_to_err() {
        let resp = JsonRpcResponse::error(
            1.into(),
            ControlError::of(ControlErrorCode::Unauthorized, "no token"),
        );
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["error"]["data"]["code"], "UNAUTHORIZED");
        assert!(v.get("result").is_none());
        assert!(resp.into_result().is_err());
    }

    #[test]
    fn a_response_with_neither_field_is_a_control_error() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: RequestId::Number(1),
            result: None,
            error: None,
        };
        let err = resp.into_result().unwrap_err();
        assert_eq!(err.code_enum(), Some(ControlErrorCode::ControlError));
    }
}
