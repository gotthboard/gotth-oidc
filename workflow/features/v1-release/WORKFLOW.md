# v1 Release Preparation

## Status

Candidate implementation, exact-commit verification, deterministic artifacts,
and two cold reviews are complete. Canonical Forgejo publication is authorized;
GitHub hosted publication remains Bryce's separate handoff.

Stabilize the existing advertised `pkg/oidc` package as v1.0.0 without adding
protocol scope.

## Candidate requirements

1. Freeze the exported API in a checked declaration snapshot.
2. Make `AuthorizationError` inspectable and declare all error message text
   noncontractual.
3. Preserve v0.1.0 in-flight `ProtectedAttempt` values and test all persisted
   envelopes from a checked cross-version golden.
4. Reconcile compatibility, support, changelog, release notes, distribution,
   verification, and release policy.
5. Produce deterministic source, checksum, provenance, SPDX SBOM, and license
   evidence for one exact commit.
6. Pass focused local checks, isolated heavy checks, and two cold reviews of the
   exact candidate and evidence.

## Boundaries

This release does not alter providers or migrate a consumer. The historical
`v0.1.0-release` hosted-GitHub closeout remains blocked pending Bryce and is
not the manifest's active feature. It does not block verified v1.0.0 Forgejo
publication. Automatic mirror propagation is allowed; manual GitHub Release and
asset publication remain out of scope.
