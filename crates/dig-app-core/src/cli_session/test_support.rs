//! Doubles the CLI-lane tests share: a scripted frame transport and the three gateway seams.
//!
//! Kept out of the individual test modules because the server tests and the client tests must serve
//! the SAME identity — a divergence between them would let one half prove a shape the other does not
//! produce.

use std::cell::RefCell;

use crate::confirm::{ConfirmDecision, ConnectPrompt, NativeConfirmer, PairPrompt, SignPrompt};
use crate::gateway::{
    GatewayError, LinkOpener, LocalIdentity, Outcome, PendingProfileCreation, ProfileSeedRequest,
    ProfileSummary,
};

use super::wire::{Request, Response};

use dig_ipc_protocol::FrameTransport;

/// The balance the stub identity reports, in mojos. A value no other fixture in this crate uses, so
/// an assertion on it cannot pass against some other path's default.
pub const STUB_BALANCE_MOJOS: u64 = 4_200;

/// A [`FrameTransport`] that plays a fixed list of request lines and records every response.
pub struct ScriptedDuplex {
    pending: std::collections::VecDeque<String>,
    sent: Vec<String>,
}

impl ScriptedDuplex {
    /// A transport that will deliver `requests`, in order, then report end-of-stream.
    pub fn of(requests: &[Request]) -> Self {
        Self::of_lines(
            &requests
                .iter()
                .map(|r| serde_json::to_string(r).expect("a request encodes"))
                .collect::<Vec<_>>(),
        )
    }

    /// A transport that will deliver these raw lines — including lines that are not valid frames.
    pub fn of_lines<S: AsRef<str>>(lines: &[S]) -> Self {
        Self {
            pending: lines.iter().map(|l| l.as_ref().to_string()).collect(),
            sent: Vec::new(),
        }
    }

    /// Every response the server wrote, decoded.
    pub fn responses(&self) -> Vec<Response> {
        self.sent
            .iter()
            .map(|line| serde_json::from_str(line).expect("the server writes decodable frames"))
            .collect()
    }
}

impl FrameTransport for ScriptedDuplex {
    fn send_frame(&mut self, frame: &str) -> std::io::Result<()> {
        self.sent.push(frame.to_string());
        Ok(())
    }

    fn recv_frame(&mut self) -> std::io::Result<String> {
        self.pending
            .pop_front()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    }
}

/// A local identity holding two profiles and a known balance.
///
/// TWO profiles, not one: a list surface that returned only the active profile would look correct
/// against a single-profile fixture, and multi-profile is the whole point of the model.
#[derive(Default)]
pub struct StubIdentity {
    /// Every DID the gateway was asked to select, so a test can prove a mutation did NOT run.
    pub selected: RefCell<Vec<String>>,
}

impl LocalIdentity for StubIdentity {
    fn profiles(&self) -> Result<Vec<ProfileSummary>, GatewayError> {
        Ok(vec![
            ProfileSummary {
                did: "did:chia:one".into(),
                name: "home".into(),
                active: true,
            },
            ProfileSummary {
                did: "did:chia:two".into(),
                name: "work".into(),
                active: false,
            },
        ])
    }

    fn begin_profile_creation(
        &self,
        _: ProfileSeedRequest,
    ) -> Result<PendingProfileCreation, GatewayError> {
        unreachable!("profile creation is not exercised by the CLI-lane tests")
    }

    fn select_profile(&self, did: &str) -> Result<(), GatewayError> {
        self.selected.borrow_mut().push(did.to_string());
        Ok(())
    }

    fn default_profile(&self) -> Result<Option<String>, GatewayError> {
        Ok(Some("did:chia:one".into()))
    }

    fn set_default_profile(&self, did: &str) -> Result<(), GatewayError> {
        self.selected.borrow_mut().push(did.to_string());
        Ok(())
    }

    fn wallet_address(&self) -> Result<String, GatewayError> {
        Ok("xch1stub".into())
    }

    fn wallet_balance(&self) -> Result<u64, GatewayError> {
        Ok(STUB_BALANCE_MOJOS)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, GatewayError> {
        Ok(message.to_vec())
    }
}

/// A link opener the CLI-lane tests never reach — `open` is engine-routed and refused before it.
pub struct UnusedOpener;

impl LinkOpener for UnusedOpener {
    fn open(&self, _link: &str) -> Result<Outcome, GatewayError> {
        unreachable!("the CLI-lane tests never open a link")
    }
}

/// A confirmer that approves, so the routing under test is never masked by a declined ceremony.
/// The ceremony's own behaviour is proven in `gateway::local`.
pub struct ApprovingConfirmer;

impl NativeConfirmer for ApprovingConfirmer {
    fn confirm_pair(&self, _: &PairPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }

    fn confirm_connect(&self, _: &ConnectPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }

    fn confirm_sign(&self, _: &SignPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Approve
    }
}
