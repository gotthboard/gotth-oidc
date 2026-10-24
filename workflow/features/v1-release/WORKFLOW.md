# v1 Release Preparation

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

This preparation does not push, tag, create a hosted Release, alter providers,
or migrate a consumer. The existing `v0.1.0-release` feature remains the
manifest's active feature because its hosted GitHub Release closeout is still
incomplete. This v1 feature may be prepared and reviewed, but canonical release
advancement remains blocked until that workflow-state conflict is resolved by
an authorized closeout decision.
