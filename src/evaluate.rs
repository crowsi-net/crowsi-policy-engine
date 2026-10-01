use crowsi_control_contracts::{AssuranceLevel, ControlAction, Validate};

use crate::{
    AuthorityState, EvaluationInput, IncidentState, Obligation, PolicyEvaluation, PostureState,
    ReasonCode,
    checks::{
        authority_matches, complete_coverage, coverage_unknown, degraded_containment,
        identity_matches, posture_targets_match, risk_adjusted_assurance, valid_policy,
    },
    freshness::expiry_reason,
    output::{denial, permit},
    time::normalized_utc,
};

/// Returns one deterministic decision without reading or changing external state.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "one linear function makes hard-deny precedence directly reviewable"
)]
pub fn evaluate(input: &EvaluationInput<'_>) -> PolicyEvaluation {
    let action = input.intent.binding.action;
    let baseline = action.required_assurance();
    let pip = &input.pip;
    let deny = |reason, obligations| denial(input, reason, baseline, obligations);
    if !normalized_utc(pip.now) {
        return deny(ReasonCode::InvalidNow, vec![]);
    }
    if input.identity.validate().is_err() {
        return deny(ReasonCode::InvalidIdentityContract, vec![]);
    }
    if input.intent.validate().is_err() {
        return deny(ReasonCode::InvalidIntentContract, vec![]);
    }
    if pip.coverage.validate().is_err() {
        return deny(ReasonCode::InvalidCoverageContract, vec![]);
    }
    if !valid_policy(input) {
        return deny(ReasonCode::InvalidPolicy, vec![]);
    }
    if pip.device_posture.state == PostureState::Unknown {
        return deny(ReasonCode::UnknownDevicePosture, vec![]);
    }
    if pip.workload_posture.state == PostureState::Unknown {
        return deny(ReasonCode::UnknownWorkloadPosture, vec![]);
    }
    if coverage_unknown(input) {
        return deny(
            ReasonCode::UnknownCoverage,
            vec![Obligation::RefreshCoverage],
        );
    }
    if pip.incident.state == IncidentState::Unknown {
        return deny(ReasonCode::UnknownIncidentState, vec![]);
    }
    if pip.management_authority.state == AuthorityState::Unknown {
        return deny(ReasonCode::UnknownManagementAuthority, vec![]);
    }
    if let Some(reason) = expiry_reason(input) {
        let obligations = if reason == ReasonCode::CoverageExpired {
            vec![Obligation::RefreshCoverage]
        } else {
            vec![]
        };
        return deny(reason, obligations);
    }
    if input.identity.revocation_epoch != pip.current_revocation_epoch
        || input.intent.revocation_epoch != pip.current_revocation_epoch
        || pip.management_authority.revocation_epoch != pip.current_revocation_epoch
    {
        return deny(ReasonCode::Revoked, vec![]);
    }
    if !identity_matches(input) {
        return deny(ReasonCode::IdentityMismatch, vec![]);
    }
    if !posture_targets_match(input) {
        return deny(ReasonCode::PostureTargetMismatch, vec![]);
    }
    if pip.coverage.resource != input.intent.binding.resource {
        return deny(ReasonCode::ResourceMismatch, vec![]);
    }
    if pip.incident.resource != input.intent.binding.resource {
        return deny(ReasonCode::IncidentResourceMismatch, vec![]);
    }
    if !authority_matches(input) {
        return deny(ReasonCode::ManagementAuthorityMismatch, vec![]);
    }
    if pip.device_posture.state == PostureState::Untrusted {
        return deny(ReasonCode::DevicePostureUntrusted, vec![]);
    }
    if pip.workload_posture.state == PostureState::Untrusted {
        return deny(ReasonCode::WorkloadPostureUntrusted, vec![]);
    }
    if pip.management_authority.state != AuthorityState::Authorized {
        return deny(ReasonCode::ManagementUnauthorized, vec![]);
    }
    let degraded = degraded_containment(input);
    if !complete_coverage(input) && !degraded {
        return deny(
            ReasonCode::CoverageInsufficient,
            vec![Obligation::RefreshCoverage],
        );
    }
    if action == ControlAction::Restore && pip.incident.state != IncidentState::RecoveryAuthorized {
        return deny(
            ReasonCode::RestoreNotRecoveryAuthorized,
            vec![Obligation::ObtainRecoveryAuthorization],
        );
    }
    let required = risk_adjusted_assurance(input, baseline);
    if !input.identity.assurance.meets(required) {
        let obligation = match required {
            AssuranceLevel::HardwareBoundStepUp => Obligation::HardwareBoundStepUp,
            _ => Obligation::PhishingResistantStepUp,
        };
        return denial(
            input,
            ReasonCode::AssuranceInsufficient,
            required,
            vec![obligation],
        );
    }
    if pip.risk_score > pip.policy.max_risk_score {
        return deny(ReasonCode::RiskTooHigh, vec![]);
    }
    permit(input, required, degraded)
}
