# v0.1.0 Release Verification

Status: published GitHub Release absent; draft state unknown without GitHub authentication

Fresh closeout date: 2026-10-21

## Exact release identity

- Admitted runtime source: `1ae119e52f8efc3392fcc9fa716b1b27c9ffce6c`
- Annotated `v0.1.0` tag object:
  `0f357d90b4b64da9ef89f8796a766f284e86ba5e`
- Peeled release commit: `4c22b248b2e7f03c28051aaf3105a0d769690f73`
- Local, canonical Forgejo, and public GitHub refs advertised that exact tag
  object and peeled commit on 2026-10-21. The peeled commit was also `main` at
  both endpoints.
- The release commit changes release documentation and workflow records only;
  `pkg/`, `go.mod`, `go.sum`, `.go-version`, and `Makefile` have no delta
  from the admitted runtime source.

## Historical evidence reused

The dated admission evidence remains historical and was not rerun or relabeled
as fresh:

- the runtime source passed format, vet, race, and 90.1% statement-coverage
  gates;
- 2026-09-21 GOTTH Mail evidence proved a live OIDC Authorization Code login
  with PKCE, exact subject binding, and domain-scoped role enforcement; and
- GOTTH Mail pinned `github.com/gotthboard/gotth-oidc v0.1.0` without a local
  replacement.

## Fresh exact-tag evidence

On 2026-10-21, a clean public GitHub clone detached at the peeled commit passed
`make verify` on the development host with Go 1.26.6: formatting, read-only
module checks, vet, race-enabled tests, and 90.1% statement coverage all
passed.

An initial remote wrapper failed before any test because its shell expansion
targeted nonexistent local paths; that setup log is retained separately. A
clean external module then passed using the exact package import
`github.com/gotthboard/gotth-oidc/pkg/oidc@v0.1.0`. Two further consumer-fixture
setup attempts failed before the successful consumer run: one generated
malformed Go import syntax, and one omitted transitive `go.sum` entries.
Those were harness failures, not product or tag failures; their logs were kept
with the final passing log.

The deterministic source archive was reproduced successfully from the exact
tag. Release-asset checksums are:

- `gotth-oidc-v0.1.0-source.tar.gz`:
  `7aa46b124ee71e7106fd7156c1ef3d8bdaf46ec9a0a4e4c4a1497e352e34b7a0`
- `SHA256SUMS`:
  `0cfad4dc9a7b83d7800d4a2709a48cb8ea2e11850a0a640a717b78fc0fb3e874`

## Publication boundary

The public tag fallback URL exists, but GitHub's authoritative release-by-tag
API returns 404: no published Release is visible. Create or publish a normal Release on
the existing immutable tag using
`docs/release-notes-v0.1.0.md` and the recorded source archive and checksum
manifest.

The release workflow remains active until the normal Release object and two
exact custom assets exist and the closeout check verifies metadata, names,
bytes, internal manifest, and tag identity. Never move or replace
the existing tag; any defect requires a new SemVer version.
