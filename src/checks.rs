use crowsi_control_contracts::{
    AssuranceLevel, CapabilityStatus, ControlAction, CoverageLevel, EnforcementReadiness,
    Freshness, Health, Management, ManagementLifeline, Verification,
};

use crate::{AuthorityState, EvaluationInput};

pub(crate) fn valid_policy(input: &EvaluationInput<'_>) -> bool {
    let policy = input.pip.policy;
    policy.step_up_risk_score <= policy.max_risk_score
        && policy.max_risk_score <= 100
        && policy.digest == policy.computed_digest()
}

pub(crate) fn identity_matches(input: &EvaluationInput<'_>) -> bool {
    let identity = input.identity;
    let intent = input.intent;
    identity.context_id == intent.identity_context_id
        && identity.pairwise_subject == intent.pairwise_subject
        && identity.actor == intent.actor
        && identity.device == intent.device
        && identity.workload == intent.workload
        && identity.profile == intent.profile
        && identity.proof_key_ref == intent.proof_key_ref
        && identity.audience == intent.binding.audience
}

pub(crate) fn posture_targets_match(input: &EvaluationInput<'_>) -> bool {
    input.pip.device_posture.target == input.identity.device
        && input.pip.workload_posture.target == input.identity.workload
}

pub(crate) fn authority_matches(input: &EvaluationInput<'_>) -> bool {
    let authority = input.pip.management_authority;
    let binding = &input.intent.binding;
    authority.identity_context_id == input.identity.context_id
        && authority.authorization_grant_id == input.identity.authorization_grant_id
        && authority.audience == binding.audience
        && authority.resource == binding.resource
        && authority.action == binding.action
        && authority.purpose == binding.purpose
        && authority.channel == binding.channel
}

pub(crate) fn complete_coverage(input: &EvaluationInput<'_>) -> bool {
    let coverage = input.pip.coverage;
    coverage.coverage == CoverageLevel::Complete
        && coverage.freshness == Freshness::Fresh
        && coverage.management == Management::Managed
        && coverage.verification == Verification::Verified
        && coverage.health == Health::Healthy
        && coverage.management_lifeline == ManagementLifeline::Verified
        && coverage.enforcement_readiness == EnforcementReadiness::Ready
        && requested_capability(input) == CapabilityStatus::Ready
        && coverage.action_coverage.verify == CapabilityStatus::Ready
        && (input.intent.binding.action != ControlAction::Restore
            || coverage.action_coverage.all_ready())
}

pub(crate) fn coverage_unknown(input: &EvaluationInput<'_>) -> bool {
    let coverage = input.pip.coverage;
    coverage.coverage == CoverageLevel::Unknown
        || coverage.health == Health::Unknown
        || coverage.enforcement_readiness == EnforcementReadiness::Unknown
        || requested_capability(input) == CapabilityStatus::Unknown
        || coverage.action_coverage.verify == CapabilityStatus::Unknown
}

pub(crate) fn degraded_containment(input: &EvaluationInput<'_>) -> bool {
    let coverage = input.pip.coverage;
    matches!(
        input.intent.binding.action,
        ControlAction::Quarantine | ControlAction::RevokeAccess
    ) && matches!(
        coverage.coverage,
        CoverageLevel::Complete | CoverageLevel::Partial
    ) && coverage.freshness == Freshness::Fresh
        && coverage.management == Management::Managed
        && coverage.health == Health::Degraded
        && coverage.management_lifeline == ManagementLifeline::Verified
        && matches!(
            coverage.enforcement_readiness,
            EnforcementReadiness::Ready | EnforcementReadiness::Degraded
        )
        && requested_capability(input) == CapabilityStatus::Ready
        && input.pip.management_authority.state == AuthorityState::Authorized
}

pub(crate) fn risk_adjusted_assurance(
    input: &EvaluationInput<'_>,
    baseline: AssuranceLevel,
) -> AssuranceLevel {
    if input.pip.risk_score >= input.pip.policy.step_up_risk_score {
        AssuranceLevel::HardwareBoundStepUp
    } else {
        baseline
    }
}

pub(crate) fn requested_capability(input: &EvaluationInput<'_>) -> CapabilityStatus {
    let coverage = &input.pip.coverage.action_coverage;
    match input.intent.binding.action {
        ControlAction::Quarantine => coverage.quarantine,
        ControlAction::RevokeAccess => coverage.revoke,
        ControlAction::Restore => coverage.restore,
        ControlAction::RestrictEgress => CapabilityStatus::Unknown,
    }
}
