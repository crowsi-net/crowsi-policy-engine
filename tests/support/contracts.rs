use crowsi_control_contracts::{
    ActionBindingV1, ActionCoverageV1, AssuranceLevel, COVERAGE_ASSERTION_SCHEMA_V1,
    CapabilityStatus, ControlAction, ControlChannel, CoverageAssertionV1, CoverageLevel,
    EnforcementReadiness, Freshness, Health, Management, ManagementLifeline,
    SECURITY_INTENT_SCHEMA_V1, SecurityIntentV1, SignatureAlgorithm, SignedDigestV1,
    VERIFIED_IDENTITY_CONTEXT_SCHEMA_V1, Verification, VerifiedIdentityContextV1,
};

use super::digest;

pub fn identity() -> VerifiedIdentityContextV1 {
    VerifiedIdentityContextV1 {
        schema: VERIFIED_IDENTITY_CONTEXT_SCHEMA_V1.into(),
        context_id: "context:alpha".into(),
        issuer: "https://identity.example".into(),
        pairwise_subject: "subject-alpha".into(),
        actor: "rescue-console".into(),
        device: "device-alpha".into(),
        workload: "spiffe://crowsi.local/workload/alpha".into(),
        profile: "profile-alpha".into(),
        proof_key_ref: "proof-key-alpha".into(),
        assurance: AssuranceLevel::HardwareBoundStepUp,
        authorization_grant_id: "authorization:alpha".into(),
        revocation_epoch: 7,
        authenticated_at: "2026-07-29T00:00:00.000Z".into(),
        expires_at: "2026-07-29T00:10:00.000Z".into(),
        audience: "crowsi-pep".into(),
        signed: signed(),
    }
}

pub fn intent(action: ControlAction) -> SecurityIntentV1 {
    SecurityIntentV1 {
        schema: SECURITY_INTENT_SCHEMA_V1.into(),
        intent_id: "intent:alpha".into(),
        jti: "intent-jti:alpha".into(),
        identity_context_id: "context:alpha".into(),
        pairwise_subject: "subject-alpha".into(),
        actor: "rescue-console".into(),
        device: "device-alpha".into(),
        workload: "spiffe://crowsi.local/workload/alpha".into(),
        profile: "profile-alpha".into(),
        proof_key_ref: "proof-key-alpha".into(),
        revocation_epoch: 7,
        binding: ActionBindingV1 {
            audience: "crowsi-pep".into(),
            resource: "network://estate/alpha".into(),
            action,
            purpose: "incident-containment".into(),
            channel: ControlChannel::EmergencyConsole,
        },
        requested_at: "2026-07-29T00:01:00.000Z".into(),
        expires_at: "2026-07-29T00:05:00.000Z".into(),
        reason: "contain verified incident".into(),
        signed: signed(),
    }
}

pub fn coverage() -> CoverageAssertionV1 {
    CoverageAssertionV1 {
        schema: COVERAGE_ASSERTION_SCHEMA_V1.into(),
        assertion_id: "coverage:alpha".into(),
        resource: "network://estate/alpha".into(),
        observer_id: "observer:alpha".into(),
        coverage: CoverageLevel::Complete,
        freshness: Freshness::Fresh,
        management: Management::Managed,
        verification: Verification::Verified,
        health: Health::Healthy,
        management_lifeline: ManagementLifeline::Verified,
        enforcement_readiness: EnforcementReadiness::Ready,
        action_coverage: ActionCoverageV1 {
            quarantine: CapabilityStatus::Ready,
            revoke: CapabilityStatus::Ready,
            verify: CapabilityStatus::Ready,
            restore: CapabilityStatus::Ready,
        },
        observed_at: "2026-07-29T00:01:00.000Z".into(),
        valid_until: "2026-07-29T00:05:00.000Z".into(),
        evidence_digest: digest(),
        signed: signed(),
    }
}

fn signed() -> SignedDigestV1 {
    SignedDigestV1 {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: "key:alpha".into(),
        digest: digest(),
        signature: "a".repeat(43),
    }
}
