#![allow(dead_code)]

mod contracts;

use crowsi_control_contracts::{
    CanonicalPayloadV1, ControlAction, CoverageAssertionV1, CoverageLevel, EnforcementReadiness,
    Health, SecurityIntentV1, Verification, VerifiedIdentityContextV1,
};
use crowsi_policy_engine::{
    AuthorityState, EvaluationInput, IncidentInput, IncidentState, ManagementAuthorityInput,
    PipInput, PolicyEvaluation, PolicyInput, PostureInput, PostureState, TrustWindow, evaluate,
};

use contracts::{coverage, identity, intent};

pub struct Fixture {
    pub identity: VerifiedIdentityContextV1,
    pub intent: SecurityIntentV1,
    pub coverage: CoverageAssertionV1,
    pub current_epoch: u64,
    pub device_target: String,
    pub workload_target: String,
    pub device_state: PostureState,
    pub workload_state: PostureState,
    pub device_window: TrustWindow<'static>,
    pub workload_window: TrustWindow<'static>,
    pub incident: IncidentInput<'static>,
    pub authority: ManagementAuthorityInput<'static>,
    pub policy_digest: String,
    pub max_risk: u8,
    pub step_up_risk: u8,
    pub now: String,
    pub risk: u8,
}

impl Fixture {
    pub fn new(action: ControlAction) -> Self {
        Self {
            identity: identity(),
            intent: intent(action),
            coverage: coverage(),
            current_epoch: 7,
            device_target: "device-alpha".into(),
            workload_target: "spiffe://crowsi.local/workload/alpha".into(),
            device_state: PostureState::Trusted,
            workload_state: PostureState::Trusted,
            device_window: window(),
            workload_window: window(),
            incident: IncidentInput {
                incident_id: "incident:alpha",
                resource: "network://estate/alpha",
                state: IncidentState::Contained,
                window: window(),
            },
            authority: ManagementAuthorityInput {
                state: AuthorityState::Authorized,
                identity_context_id: "context:alpha",
                authorization_grant_id: "authorization:alpha",
                revocation_epoch: 7,
                audience: "crowsi-pep",
                resource: "network://estate/alpha",
                action,
                purpose: "incident-containment",
                channel: crowsi_control_contracts::ControlChannel::EmergencyConsole,
                window: window(),
            },
            policy_digest: policy_digest(90, 70),
            max_risk: 90,
            step_up_risk: 70,
            now: "2026-07-29T00:02:00.000Z".into(),
            risk: 10,
        }
    }

    pub fn evaluate(&self) -> PolicyEvaluation {
        let mut identity = self.identity.clone();
        let mut intent = self.intent.clone();
        let mut coverage = self.coverage.clone();
        identity.signed.digest = identity.payload_digest();
        intent.signed.digest = intent.payload_digest();
        coverage.signed.digest = coverage.payload_digest();
        evaluate(&EvaluationInput {
            identity: &identity,
            intent: &intent,
            pip: PipInput {
                current_revocation_epoch: self.current_epoch,
                device_posture: PostureInput {
                    target: &self.device_target,
                    state: self.device_state,
                    window: self.device_window,
                },
                workload_posture: PostureInput {
                    target: &self.workload_target,
                    state: self.workload_state,
                    window: self.workload_window,
                },
                coverage: &coverage,
                incident: self.incident,
                management_authority: self.authority,
                policy: PolicyInput {
                    digest: &self.policy_digest,
                    max_risk_score: self.max_risk,
                    step_up_risk_score: self.step_up_risk,
                },
                now: &self.now,
                risk_score: self.risk,
            },
        })
    }
}

pub fn partial_coverage(fixture: &mut Fixture) {
    fixture.coverage.coverage = CoverageLevel::Partial;
    fixture.coverage.verification = Verification::Unverified;
    fixture.coverage.health = Health::Degraded;
    fixture.coverage.enforcement_readiness = EnforcementReadiness::Degraded;
}

pub fn digest() -> String {
    format!("sha256:{}", "a".repeat(64))
}

fn policy_digest(max_risk_score: u8, step_up_risk_score: u8) -> String {
    PolicyInput {
        digest: "",
        max_risk_score,
        step_up_risk_score,
    }
    .computed_digest()
}

fn window() -> TrustWindow<'static> {
    TrustWindow {
        observed_at: "2026-07-29T00:01:00.000Z",
        valid_until: "2026-07-29T00:05:00.000Z",
    }
}
