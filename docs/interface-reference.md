# crowsi-policy-engine interface reference

Use the [usage guide](getting-started.md) for the first steps. This reference preserves the current interface details and operational limits. Run command examples from the repository root, after preparing the exact declared dependencies and registered configuration.

## Trust boundary

The caller supplies:

- identity and intent whose detached signatures and canonical payloads were
  verified against an allowlisted trust anchor;
- the current revocation epoch;
- fresh device and workload posture bound to the exact identity targets;
- an independent `CoverageAssertionV1`;
- incident state bound to the exact resource, a reviewed policy digest, trusted
  time, an exact context/grant/epoch/audience/resource/action/purpose
  management authority, and bounded risk score.

The engine repeats closed-contract validation but does not verify signatures.
It does not read a clock; `now` is explicit input so equal inputs always produce
equal output. The versioned policy digest is recomputed over the risk
restrictions so a reviewed digest cannot be paired with different thresholds.
Posture, incident, and management-authority evidence must be active at `now`
and use a trust window no longer than five minutes.

## Fixed evaluation order

1. malformed contracts, time, or policy;
2. unknown posture, coverage, or incident state;
3. expired identity, intent, posture, or coverage;
4. revocation-epoch mismatch;
5. identity, posture target, incident resource, management authority, audience,
   or resource mismatch;
6. untrusted device or workload;
7. insufficient coverage;
8. restore without `RecoveryAuthorized`;
9. insufficient assurance;
10. risk restrictions.

Risk may require hardware-bound step-up or deny above the policy maximum. It is
never evaluated as an allow reason and cannot reverse any earlier denial.

## Containment and restore

Restore requires complete, fresh, managed, independently verified, healthy
coverage, `RecoveryAuthorized`, and hardware-bound step-up assurance.

Quarantine and access revocation may proceed with fresh partial coverage only
when the caller proves management authority and the fresh signed coverage
assertion reports a verified management lifeline plus a ready requested
capability. The permit is marked `DegradedContainment` and obligates downstream
components not to claim complete isolation. Unknown, stale, unmanaged, or
expired coverage is never accepted by this exception.

`ActionCoverageV1` does not currently expose an exact `RestrictEgress`
capability. This engine therefore denies that action as unknown rather than
silently treating quarantine capability as equivalent.

## Non-capabilities

This crate performs no I/O, signature verification, credential access, policy
administration, grant minting, audit persistence, network operation, or
provider mutation. A separate PA may map an allowed evaluation into a signed
`PolicyDecisionV1`; a resource-local PEP remains responsible for enforcement,
replay prevention, receipts, and independent verification.

The unsigned result echoes the identity context, intent JTI, revocation epoch,
action binding, coverage assertion, incident, and evaluation time. A PA must
reject any attempt to pair the result with different inputs.
