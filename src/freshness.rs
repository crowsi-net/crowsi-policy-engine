use crowsi_control_contracts::Freshness;

use crate::{
    EvaluationInput, ReasonCode,
    time::{active, bounded_active},
};

const MAX_PIP_WINDOW_MILLIS: i64 = 300_000;

pub(crate) fn expiry_reason(input: &EvaluationInput<'_>) -> Option<ReasonCode> {
    let pip = &input.pip;
    if !active(
        &input.identity.authenticated_at,
        &input.identity.expires_at,
        pip.now,
    ) {
        return Some(ReasonCode::IdentityExpired);
    }
    if !active(
        &input.intent.requested_at,
        &input.intent.expires_at,
        pip.now,
    ) {
        return Some(ReasonCode::IntentExpired);
    }
    if !window_active(pip.device_posture.window, pip.now) {
        return Some(ReasonCode::DevicePostureExpired);
    }
    if !window_active(pip.workload_posture.window, pip.now) {
        return Some(ReasonCode::WorkloadPostureExpired);
    }
    if pip.coverage.freshness == Freshness::Stale
        || !active(
            &pip.coverage.observed_at,
            &pip.coverage.valid_until,
            pip.now,
        )
    {
        return Some(ReasonCode::CoverageExpired);
    }
    if !window_active(pip.incident.window, pip.now) {
        return Some(ReasonCode::IncidentStateExpired);
    }
    if !window_active(pip.management_authority.window, pip.now) {
        return Some(ReasonCode::ManagementAuthorityExpired);
    }
    None
}

fn window_active(window: crate::TrustWindow<'_>, now: &str) -> bool {
    bounded_active(
        window.observed_at,
        window.valid_until,
        now,
        MAX_PIP_WINDOW_MILLIS,
    )
}
