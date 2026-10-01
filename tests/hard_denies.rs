mod support;

use crowsi_control_contracts::{
    ControlAction, ControlChannel, CoverageLevel, DecisionEffect, Health, Verification,
};
use crowsi_policy_engine::{AuthorityState, PostureState, ReasonCode};

use support::Fixture;

#[test]
fn expired_identity_is_denied_before_risk() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.identity.expires_at = "2026-07-29T00:01:30.000Z".into();
    fixture.risk = 100;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::IdentityExpired);
}

#[test]
fn current_epoch_mismatch_is_revoked() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.current_epoch += 1;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::Revoked);
}

#[test]
fn stale_management_authority_epoch_is_revoked() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.authority.revocation_epoch -= 1;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::Revoked);
}

#[test]
fn every_identity_dimension_is_exact() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.intent.workload = "spiffe://crowsi.local/workload/other".into();
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::IdentityMismatch);
}

#[test]
fn posture_evidence_is_bound_to_the_exact_target() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.device_target = "device-other".into();
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::PostureTargetMismatch);
}

#[test]
fn management_authority_is_bound_to_the_exact_action() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.authority.action = ControlAction::Restore;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::ManagementAuthorityMismatch);
}

#[test]
fn management_authority_is_bound_to_the_exact_channel() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.authority.channel = ControlChannel::ServiceAutomation;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::ManagementAuthorityMismatch);
}

#[test]
fn unknown_management_authority_fails_closed() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.authority.state = AuthorityState::Unknown;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::UnknownManagementAuthority);
}

#[test]
fn expired_management_authority_fails_closed() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.authority.window.valid_until = "2026-07-29T00:01:59.000Z";
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::ManagementAuthorityExpired);
}

#[test]
fn incident_state_is_bound_to_the_exact_resource() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.incident.resource = "network://estate/other";
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::IncidentResourceMismatch);
}

#[test]
fn expired_incident_state_fails_closed() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.incident.window.valid_until = "2026-07-29T00:01:59.000Z";
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::IncidentStateExpired);
}

#[test]
fn future_posture_evidence_fails_closed() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.device_window.observed_at = "2026-07-29T00:02:01.000Z";
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::DevicePostureExpired);
}

#[test]
fn unbounded_posture_window_fails_closed() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.workload_window.observed_at = "2026-07-29T00:00:00.000Z";
    fixture.workload_window.valid_until = "2026-07-29T00:10:00.000Z";
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::WorkloadPostureExpired);
}

#[test]
fn unknown_posture_is_a_hard_deny() {
    let mut fixture = Fixture::new(ControlAction::RevokeAccess);
    fixture.device_state = PostureState::Unknown;
    fixture.risk = 0;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::UnknownDevicePosture);
}

#[test]
fn unknown_coverage_cannot_use_degraded_containment() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.coverage.coverage = CoverageLevel::Unknown;
    fixture.coverage.health = Health::Unknown;
    fixture.coverage.verification = Verification::Unverified;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::UnknownCoverage);
}

#[test]
fn malformed_policy_digest_fails_closed() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.policy_digest = "sha256:not-a-digest".into();
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::InvalidPolicy);
}

#[test]
fn policy_digest_must_cover_risk_restrictions() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.max_risk -= 1;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::InvalidPolicy);
}
