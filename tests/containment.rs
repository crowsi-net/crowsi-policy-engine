mod support;

use crowsi_control_contracts::{
    CanonicalPayloadV1, CapabilityStatus, ControlAction, DecisionEffect, Freshness, Health,
    ManagementLifeline,
};
use crowsi_policy_engine::{AuthorityState, Obligation, ReasonCode};

use support::{Fixture, partial_coverage};

#[test]
fn quarantine_can_reduce_authority_with_partial_coverage() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    partial_coverage(&mut fixture);
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Permit);
    assert_eq!(result.reason, ReasonCode::DegradedContainment);
    assert!(
        result
            .obligations
            .contains(&Obligation::DoNotClaimCompleteCoverage)
    );
    assert!(
        result
            .obligations
            .contains(&Obligation::PreserveManagementLifeline)
    );
    assert_eq!(result.identity_context_id, fixture.identity.context_id);
    assert_eq!(result.intent_jti, fixture.intent.jti);
    assert_eq!(result.binding, fixture.intent.binding);
    assert_eq!(result.incident_id, fixture.incident.incident_id);
}

#[test]
fn revocation_can_reduce_authority_with_partial_coverage() {
    let mut fixture = Fixture::new(ControlAction::RevokeAccess);
    partial_coverage(&mut fixture);
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Permit);
    assert_eq!(result.reason, ReasonCode::DegradedContainment);
}

#[test]
fn complete_observation_can_contain_a_degraded_resource() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.coverage.health = Health::Degraded;
    fixture.coverage.signed.digest = fixture.coverage.payload_digest();
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Permit);
    assert_eq!(result.reason, ReasonCode::DegradedContainment);
}

#[test]
fn uncovered_action_has_no_partial_coverage_exception() {
    let mut fixture = Fixture::new(ControlAction::RestrictEgress);
    partial_coverage(&mut fixture);
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::UnknownCoverage);
}

#[test]
fn degraded_containment_requires_management_authority() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    partial_coverage(&mut fixture);
    fixture.authority.state = AuthorityState::Denied;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::ManagementUnauthorized);
}

#[test]
fn complete_coverage_does_not_replace_management_authority() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.authority.state = AuthorityState::Denied;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::ManagementUnauthorized);
}

#[test]
fn degraded_containment_requires_a_verified_lifeline() {
    let mut fixture = Fixture::new(ControlAction::RevokeAccess);
    partial_coverage(&mut fixture);
    fixture.coverage.management_lifeline = ManagementLifeline::Unverified;
    assert_eq!(fixture.evaluate().reason, ReasonCode::CoverageInsufficient);
}

#[test]
fn degraded_containment_requires_a_ready_action_capability() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    partial_coverage(&mut fixture);
    fixture.coverage.action_coverage.quarantine = CapabilityStatus::Unavailable;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::CoverageInsufficient);
}

#[test]
fn stale_coverage_is_never_an_emergency_allow_reason() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    partial_coverage(&mut fixture);
    fixture.coverage.freshness = Freshness::Stale;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::CoverageExpired);
}
