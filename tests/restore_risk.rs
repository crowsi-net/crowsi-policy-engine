mod support;

use crowsi_control_contracts::{
    AssuranceLevel, CapabilityStatus, ControlAction, DecisionEffect, ManagementLifeline,
};
use crowsi_policy_engine::{IncidentState, Obligation, ReasonCode};

use support::{Fixture, partial_coverage};

#[test]
fn restore_requires_recovery_authorized() {
    let fixture = Fixture::new(ControlAction::Restore);
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::RestoreNotRecoveryAuthorized);
    assert!(
        result
            .obligations
            .contains(&Obligation::ObtainRecoveryAuthorization)
    );
}

#[test]
fn restore_requires_hardware_bound_step_up() {
    let mut fixture = Fixture::new(ControlAction::Restore);
    fixture.incident.state = IncidentState::RecoveryAuthorized;
    fixture.identity.assurance = AssuranceLevel::PhishingResistant;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::AssuranceInsufficient);
    assert!(
        result
            .obligations
            .contains(&Obligation::HardwareBoundStepUp)
    );
}

#[test]
fn authorized_hardware_bound_restore_is_staged() {
    let mut fixture = Fixture::new(ControlAction::Restore);
    fixture.incident.state = IncidentState::RecoveryAuthorized;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Permit);
    assert_eq!(result.reason, ReasonCode::PolicySatisfied);
    assert!(result.obligations.contains(&Obligation::StageRestore));
    assert!(
        result
            .obligations
            .contains(&Obligation::VerifyEnforcementIndependently)
    );
}

#[test]
fn restore_requires_ready_recontainment_capabilities() {
    let mut fixture = Fixture::new(ControlAction::Restore);
    fixture.incident.state = IncidentState::RecoveryAuthorized;
    fixture.coverage.action_coverage.quarantine = CapabilityStatus::Unavailable;
    fixture.coverage.action_coverage.revoke = CapabilityStatus::Unavailable;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::CoverageInsufficient);
}

#[test]
fn risk_can_require_more_assurance_but_never_less() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.identity.assurance = AssuranceLevel::PhishingResistant;
    fixture.risk = fixture.step_up_risk;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::AssuranceInsufficient);
    assert_eq!(
        result.required_assurance,
        AssuranceLevel::HardwareBoundStepUp
    );
}

#[test]
fn risk_above_policy_maximum_is_denied() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    fixture.risk = fixture.max_risk + 1;
    let result = fixture.evaluate();
    assert_eq!(result.effect, DecisionEffect::Deny);
    assert_eq!(result.reason, ReasonCode::RiskTooHigh);
}

#[test]
fn low_risk_cannot_expand_incomplete_coverage() {
    let mut fixture = Fixture::new(ControlAction::Quarantine);
    partial_coverage(&mut fixture);
    fixture.coverage.management_lifeline = ManagementLifeline::Unverified;
    fixture.risk = 0;
    let low = fixture.evaluate();
    fixture.risk = 50;
    let elevated = fixture.evaluate();
    assert_eq!(low.effect, DecisionEffect::Deny);
    assert_eq!(low.reason, ReasonCode::CoverageInsufficient);
    assert_eq!(elevated.reason, ReasonCode::CoverageInsufficient);
}
