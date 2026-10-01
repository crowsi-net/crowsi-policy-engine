use crowsi_control_contracts::{AssuranceLevel, ControlAction, DecisionEffect};

use crate::{EvaluationInput, Obligation, PolicyEvaluation, ReasonCode};

pub(crate) fn denial(
    input: &EvaluationInput<'_>,
    reason: ReasonCode,
    required_assurance: AssuranceLevel,
    obligations: Vec<Obligation>,
) -> PolicyEvaluation {
    decision(
        input,
        DecisionEffect::Deny,
        reason,
        required_assurance,
        obligations,
    )
}

pub(crate) fn permit(
    input: &EvaluationInput<'_>,
    required: AssuranceLevel,
    degraded: bool,
) -> PolicyEvaluation {
    let containment = input.intent.binding.action != ControlAction::Restore;
    let mut obligations = vec![
        Obligation::BindExactIdentityAndAction,
        Obligation::IssueSingleUseGrant,
        Obligation::VerifyEnforcementIndependently,
    ];
    if containment {
        obligations.push(Obligation::PreserveManagementLifeline);
    } else {
        obligations.push(Obligation::StageRestore);
    }
    if degraded {
        obligations.push(Obligation::DoNotClaimCompleteCoverage);
    }
    let reason = if degraded {
        ReasonCode::DegradedContainment
    } else {
        ReasonCode::PolicySatisfied
    };
    decision(input, DecisionEffect::Permit, reason, required, obligations)
}

fn decision(
    input: &EvaluationInput<'_>,
    effect: DecisionEffect,
    reason: ReasonCode,
    required_assurance: AssuranceLevel,
    obligations: Vec<Obligation>,
) -> PolicyEvaluation {
    PolicyEvaluation {
        identity_context_id: input.identity.context_id.clone(),
        intent_jti: input.intent.jti.clone(),
        revocation_epoch: input.pip.current_revocation_epoch,
        binding: input.intent.binding.clone(),
        coverage_assertion_id: input.pip.coverage.assertion_id.clone(),
        incident_id: input.pip.incident.incident_id.to_owned(),
        evaluated_at: input.pip.now.to_owned(),
        effect,
        reason,
        required_assurance,
        policy_digest: input.pip.policy.digest.to_owned(),
        obligations,
    }
}
