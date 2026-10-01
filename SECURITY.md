# Security policy

## Security boundary

`crowsi-policy-engine` is a pure decision component. Treat identity, intent,
coverage, posture, incident, policy, time, authority, lifeline, and risk inputs
as trusted only after their owning verifier has authenticated source, schema,
freshness, and canonical signed bytes. The Rust contract types alone do not
prove signature validity.

The engine deliberately has no network, filesystem, environment, clock,
credential, process-execution, signing, grant-minting, or enforcement API. It
is not a Policy Administrator or Policy Enforcement Point.

## Fail-closed invariants

- malformed and unknown input is denied;
- expired identity, intent, posture, and coverage is denied;
- future-dated or over-five-minute PIP trust windows are denied;
- any revocation-epoch mismatch is denied;
- subject, actor, device, workload, profile, proof key, posture target,
  incident resource, authority context/grant/epoch, audience, purpose, action,
  and resource bindings are exact;
- every permit requires fresh management authority, even with complete coverage;
- untrusted device or workload posture is denied;
- incomplete coverage is denied except for the bounded containment rule;
- restore requires `RecoveryAuthorized` and hardware-bound step-up;
- risk can only preserve or reduce authority;
- the output remains unsigned and cannot itself authorize enforcement.

The partial-coverage exception applies only to `Quarantine` and `RevokeAccess`.
Coverage must be fresh, partial, managed, and degraded rather than unknown.
The user must have explicit management authority, and the signed fresh coverage
assertion must report a verified management lifeline and a ready requested
capability. Downstream components must preserve that lifeline, verify
enforcement independently, and display the result as incomplete until coverage
is restored.

## Integration requirements

A production caller must:

1. verify every detached signature and canonical digest before evaluation;
2. obtain `now` from a trusted, rollback-resistant time source;
3. protect PIP provenance and freshness;
4. bind a PA-issued decision and single-use grant to the exact evaluation;
5. recheck revocation epoch and bindings at the resource-local PEP;
6. durably consume replay identifiers before mutation;
7. keep execution receipts distinct from independent coverage verification;
8. preserve recovery authority outside Hatter and ordinary workload boundaries.

Do not log raw identity attributes, credentials, signatures, or customer
payloads when recording an evaluation. Stable reason codes and opaque contract
identifiers are sufficient for ordinary audit.

## Reporting

Report suspected decision bypass, ambiguity, nondeterminism, or unsafe
integration privately to the Wonderland security maintainers. Include the
smallest redacted input needed to reproduce the result. Do not include secrets,
tokens, private keys, or personal data.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
