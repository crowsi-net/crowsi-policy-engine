use crowsi_control_contracts::{
    ActionBindingV1, AssuranceLevel, ControlAction, ControlChannel, CoverageAssertionV1,
    DecisionEffect, SecurityIntentV1, VerifiedIdentityContextV1,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureState {
    Trusted,
    Untrusted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustWindow<'a> {
    pub observed_at: &'a str,
    pub valid_until: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostureInput<'a> {
    pub target: &'a str,
    pub state: PostureState,
    pub window: TrustWindow<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentState {
    Normal,
    Detected,
    ContainmentRequested,
    Contained,
    RecoveryPending,
    RecoveryAuthorized,
    Restoring,
    Monitoring,
    Closed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncidentInput<'a> {
    pub incident_id: &'a str,
    pub resource: &'a str,
    pub state: IncidentState,
    pub window: TrustWindow<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityState {
    Authorized,
    Denied,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagementAuthorityInput<'a> {
    pub state: AuthorityState,
    pub identity_context_id: &'a str,
    pub authorization_grant_id: &'a str,
    pub revocation_epoch: u64,
    pub audience: &'a str,
    pub resource: &'a str,
    pub action: ControlAction,
    pub purpose: &'a str,
    pub channel: ControlChannel,
    pub window: TrustWindow<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyInput<'a> {
    pub digest: &'a str,
    pub max_risk_score: u8,
    pub step_up_risk_score: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct PipInput<'a> {
    pub current_revocation_epoch: u64,
    pub device_posture: PostureInput<'a>,
    pub workload_posture: PostureInput<'a>,
    pub coverage: &'a CoverageAssertionV1,
    pub incident: IncidentInput<'a>,
    pub management_authority: ManagementAuthorityInput<'a>,
    pub policy: PolicyInput<'a>,
    pub now: &'a str,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct EvaluationInput<'a> {
    pub identity: &'a VerifiedIdentityContextV1,
    pub intent: &'a SecurityIntentV1,
    pub pip: PipInput<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    PolicySatisfied,
    DegradedContainment,
    InvalidNow,
    InvalidIdentityContract,
    InvalidIntentContract,
    InvalidCoverageContract,
    InvalidPolicy,
    UnknownDevicePosture,
    UnknownWorkloadPosture,
    UnknownCoverage,
    UnknownIncidentState,
    UnknownManagementAuthority,
    IdentityExpired,
    IntentExpired,
    DevicePostureExpired,
    WorkloadPostureExpired,
    CoverageExpired,
    IncidentStateExpired,
    ManagementAuthorityExpired,
    Revoked,
    IdentityMismatch,
    PostureTargetMismatch,
    ResourceMismatch,
    IncidentResourceMismatch,
    ManagementAuthorityMismatch,
    DevicePostureUntrusted,
    WorkloadPostureUntrusted,
    ManagementUnauthorized,
    CoverageInsufficient,
    RestoreNotRecoveryAuthorized,
    AssuranceInsufficient,
    RiskTooHigh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Obligation {
    BindExactIdentityAndAction,
    IssueSingleUseGrant,
    PreserveManagementLifeline,
    VerifyEnforcementIndependently,
    DoNotClaimCompleteCoverage,
    StageRestore,
    RefreshCoverage,
    ObtainRecoveryAuthorization,
    PhishingResistantStepUp,
    HardwareBoundStepUp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub identity_context_id: String,
    pub intent_jti: String,
    pub revocation_epoch: u64,
    pub binding: ActionBindingV1,
    pub coverage_assertion_id: String,
    pub incident_id: String,
    pub evaluated_at: String,
    pub effect: DecisionEffect,
    pub reason: ReasonCode,
    pub required_assurance: AssuranceLevel,
    pub policy_digest: String,
    pub obligations: Vec<Obligation>,
}
