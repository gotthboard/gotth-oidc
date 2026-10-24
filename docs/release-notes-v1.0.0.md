# gotth-oidc v1.0.0 release candidate

This candidate stabilizes the existing `pkg/oidc` API. It adds no protocol
capability over v0.1.0.

## Compatibility

- The exported Go API recorded in `docs/public-api-v1.txt` becomes the v1
  compatibility baseline.
- `AuthorizationError` is inspectable with `errors.As`; its exported fields are
  contractual. Error strings are diagnostic and noncontractual.
- Persisted v0.1.0 `ProtectedAttempt` values remain readable, including in-flight
  nonce, PKCE verifier, and attempt-context envelopes.
- The excluded application and legacy-flow boundaries remain excluded.

See `docs/compatibility.md` for the complete compatibility and envelope-upgrade
policy.

## Verification and release assets

The exact committed candidate must pass format, API snapshot, vet, race,
coverage, repeated race, fuzz, clean-clone, and external-consumer checks. Two
cold reviews must inspect that same candidate and its sealed evidence.

`scripts/build-release-candidate.sh v1.0.0 OUTPUT_DIR COMMIT` deterministically
produces:

- `gotth-oidc-v1.0.0-source.tar.gz`;
- `gotth-oidc-v1.0.0.spdx.json` (SPDX 2.3 SBOM);
- `gotth-oidc-v1.0.0.LICENSE-EVIDENCE.txt`;
- `gotth-oidc-v1.0.0.provenance.json` (in-toto/SLSA provenance statement); and
- `SHA256SUMS`.

This file is candidate material only. No v1.0.0 tag or hosted Release exists
until the separately authorized publication steps complete.
