//! The CLI / RPC gateway — the user app is the front door (U7, epic dig_ecosystem#908).
//!
//! `dign` (the DIG user CLI) and RPC clients connect to the user app and hand it a [`Command`]. The
//! gateway is the ONE place that decides, per SPEC §3.5, WHERE each command is served:
//!
//! - **[`Route::UserApp`]** — served locally with the held user identity (sign / profiles / wallet).
//!   These need the in-memory user key or the user's profile state, which never leave the app.
//! - **[`Route::Engine`]** — proxied over the identity-authenticated session to the identity-agnostic
//!   engine (info / config / cache / stores / sync / subscriptions / peers / pair / open).
//!
//! The gateway owns only the routing + dispatch; the work behind each route lives behind four
//! seams so the routing is unit-tested and the subsystems stay independently owned:
//!
//! - [`EngineProxy`] — forwards a `control.*` call over the session (the IPC layer, APP-1).
//! - [`LocalIdentity`] — serves local commands over the U4 keystore + U5 profile store.
//! - [`LinkOpener`] — resolves + opens a validated DIG link (the shared URN resolver).
//! - [`crate::confirm::NativeConfirmer`] — the terminal human gate every local `dign sign` funnels
//!   through, so the custody key never signs without an explicit approval (SPEC §3.5, #959).
//!
//! The `dig-node` binary retains ONLY machine service-lifecycle subcommands
//! (install / start / stop / status / uninstall / run-service); every user/identity subcommand is
//! served here.

mod command;
mod engine;
mod local;
mod outcome;

pub use command::{
    validate_open_link, CacheAction, Command, ConfigAction, PairAction, PeersAction,
    ProfilesAction, Route, StoresAction, SubscriptionsAction, SyncAction, WalletAction,
};
pub use engine::{engine_call, EngineCall, EngineProxy};
pub use local::{handle_local, LocalIdentity, ProfileSummary};
pub use outcome::{error_envelope, success_envelope, ErrorCode, GatewayError, Outcome};

/// Resolves + opens a validated DIG link. The gateway validates the scheme (the security boundary)
/// BEFORE calling this, so `link` is always a `chia://` / `urn:dig:chia:` link; the implementation
/// (the shared fail-closed URN resolver + a browser launch) is wired by the binary.
pub trait LinkOpener {
    /// Resolve `link` and open its content, returning the dual human/machine [`Outcome`].
    fn open(&self, link: &str) -> Result<Outcome, GatewayError>;
}

/// The gateway front door: it routes a [`Command`] to the local identity or the engine and returns
/// a uniform [`Outcome`]. It borrows its four seams, so the binary owns the concrete session,
/// identity, opener, and confirmer and the gateway stays a pure router.
pub struct Gateway<'a> {
    proxy: &'a dyn EngineProxy,
    identity: &'a dyn LocalIdentity,
    opener: &'a dyn LinkOpener,
    confirmer: &'a dyn crate::confirm::NativeConfirmer,
}

impl<'a> Gateway<'a> {
    /// Build a gateway over its four seams. The `confirmer` is the terminal human gate every local
    /// `dign sign` funnels through (the SIGN-1 seam), so the custody key never signs without an
    /// explicit human approval (SPEC §3.5, #959).
    pub fn new(
        proxy: &'a dyn EngineProxy,
        identity: &'a dyn LocalIdentity,
        opener: &'a dyn LinkOpener,
        confirmer: &'a dyn crate::confirm::NativeConfirmer,
    ) -> Self {
        Gateway {
            proxy,
            identity,
            opener,
            confirmer,
        }
    }

    /// Dispatch `command`: serve it locally or proxy it to the engine, per [`Command::route`].
    pub fn dispatch(&self, command: &Command) -> Result<Outcome, GatewayError> {
        let route = command.route();
        tracing::debug!(action = command.action(), route = ?route, "gateway routing decision");
        match route {
            Route::UserApp => handle_local(command, self.identity, self.confirmer),
            Route::Engine => self.dispatch_engine(command),
        }
    }

    /// Serve an engine-routed command: `open` is composed here (validate + delegate to the opener);
    /// every other engine command maps to a canonical `control.*` call forwarded over the session.
    fn dispatch_engine(&self, command: &Command) -> Result<Outcome, GatewayError> {
        if let Command::Open { link } = command {
            validate_open_link(link)?;
            return self.opener.open(link);
        }
        let call = engine_call(command).ok_or_else(|| {
            GatewayError::new(
                ErrorCode::Usage,
                format!("{} cannot be proxied to the engine", command.action()),
            )
        })?;
        let result = self.proxy.call(call.method, call.params).map_err(|e| {
            tracing::warn!(action = command.action(), method = call.method, code = ?e.code, "engine proxy call failed");
            e
        })?;
        Ok(Outcome::new(format!("{}: ok", command.action()), result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::cell::RefCell;

    /// Records every proxied call and returns a canned result, so a test can assert the gateway
    /// forwarded the RIGHT method + params for an engine-routed command.
    #[derive(Default)]
    struct SpyProxy {
        calls: RefCell<Vec<(String, Value)>>,
        result: Value,
    }

    impl EngineProxy for SpyProxy {
        fn call(&self, method: &str, params: Value) -> Result<Value, GatewayError> {
            self.calls.borrow_mut().push((method.into(), params));
            Ok(self.result.clone())
        }
    }

    /// An identity that fails every call — the local seam is not under test in the mod tests.
    struct UnusedIdentity;
    impl LocalIdentity for UnusedIdentity {
        fn profiles(&self) -> Result<Vec<ProfileSummary>, GatewayError> {
            Ok(vec![ProfileSummary {
                did: "did:chia:x".into(),
                name: "x".into(),
                active: true,
            }])
        }
        fn create_profile(&self, _: &str) -> Result<ProfileSummary, GatewayError> {
            unreachable!("not exercised")
        }
        fn select_profile(&self, _: &str) -> Result<(), GatewayError> {
            unreachable!("not exercised")
        }
        fn default_profile(&self) -> Result<Option<String>, GatewayError> {
            unreachable!("not exercised")
        }
        fn set_default_profile(&self, _: &str) -> Result<(), GatewayError> {
            unreachable!("not exercised")
        }
        fn wallet_address(&self) -> Result<String, GatewayError> {
            unreachable!("not exercised")
        }
        fn wallet_balance(&self) -> Result<u64, GatewayError> {
            unreachable!("not exercised")
        }
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, GatewayError> {
            Ok(message.to_vec())
        }
    }

    /// Records the link it was asked to open.
    #[derive(Default)]
    struct SpyOpener {
        opened: RefCell<Option<String>>,
    }
    impl LinkOpener for SpyOpener {
        fn open(&self, link: &str) -> Result<Outcome, GatewayError> {
            *self.opened.borrow_mut() = Some(link.into());
            Ok(Outcome::new("opened", json!({ "opened": link })))
        }
    }

    /// An approving native-confirm double: the gateway's local sign gate is exercised in the
    /// `local.rs` unit tests, so here it simply never blocks the routing under test.
    struct ApprovingConfirmer;
    impl crate::confirm::NativeConfirmer for ApprovingConfirmer {
        fn confirm_pair(
            &self,
            _: &crate::confirm::PairPrompt<'_>,
        ) -> crate::confirm::ConfirmDecision {
            crate::confirm::ConfirmDecision::Approve
        }
        fn confirm_connect(
            &self,
            _: &crate::confirm::ConnectPrompt<'_>,
        ) -> crate::confirm::ConfirmDecision {
            crate::confirm::ConfirmDecision::Approve
        }
        fn confirm_sign(
            &self,
            _: &crate::confirm::SignPrompt<'_>,
        ) -> crate::confirm::ConfirmDecision {
            crate::confirm::ConfirmDecision::Approve
        }
    }

    fn gateway<'a>(
        proxy: &'a SpyProxy,
        identity: &'a UnusedIdentity,
        opener: &'a SpyOpener,
        confirmer: &'a ApprovingConfirmer,
    ) -> Gateway<'a> {
        Gateway::new(proxy, identity, opener, confirmer)
    }

    #[test]
    fn engine_command_is_forwarded_with_its_canonical_method_and_params() {
        let proxy = SpyProxy {
            result: json!({ "cap_bytes": 64 }),
            ..Default::default()
        };
        let (identity, opener, confirmer) =
            (UnusedIdentity, SpyOpener::default(), ApprovingConfirmer);
        let out = gateway(&proxy, &identity, &opener, &confirmer)
            .dispatch(&Command::Cache(CacheAction::SetCap { bytes: 64 }))
            .unwrap();
        assert_eq!(proxy.calls.borrow()[0].0, "control.cache.setCap");
        assert_eq!(proxy.calls.borrow()[0].1, json!({ "cap_bytes": 64 }));
        assert_eq!(out.result, json!({ "cap_bytes": 64 }));
    }

    #[test]
    fn local_command_never_touches_the_engine_proxy() {
        let proxy = SpyProxy::default();
        let (identity, opener, confirmer) =
            (UnusedIdentity, SpyOpener::default(), ApprovingConfirmer);
        gateway(&proxy, &identity, &opener, &confirmer)
            .dispatch(&Command::Sign {
                message: "hi".into(),
            })
            .unwrap();
        assert!(
            proxy.calls.borrow().is_empty(),
            "a local command must not proxy"
        );
    }

    #[test]
    fn open_validates_the_scheme_before_delegating_to_the_opener() {
        let proxy = SpyProxy::default();
        let (identity, opener, confirmer) =
            (UnusedIdentity, SpyOpener::default(), ApprovingConfirmer);
        let gw = gateway(&proxy, &identity, &opener, &confirmer);

        gw.dispatch(&Command::Open {
            link: "chia://store/path".into(),
        })
        .unwrap();
        assert_eq!(opener.opened.borrow().as_deref(), Some("chia://store/path"));

        let err = gw
            .dispatch(&Command::Open {
                link: "https://evil".into(),
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Usage);
    }

    #[test]
    fn a_proxy_error_propagates_with_its_code() {
        struct FailingProxy;
        impl EngineProxy for FailingProxy {
            fn call(&self, _: &str, _: Value) -> Result<Value, GatewayError> {
                Err(GatewayError::new(ErrorCode::NotConnected, "no session"))
            }
        }
        let (identity, opener, confirmer) =
            (UnusedIdentity, SpyOpener::default(), ApprovingConfirmer);
        let err = Gateway::new(&FailingProxy, &identity, &opener, &confirmer)
            .dispatch(&Command::Info)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotConnected);
    }
}
