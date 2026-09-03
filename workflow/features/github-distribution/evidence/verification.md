# GitHub Distribution Verification

Status: candidate verification complete

## Identity and scope

- Pinned base: `02a2b869b1331240dc52e23d116e6e1512a4d2ba`
- Publicly verified candidate: `349bf6329edadb9a4346edbbba99426ac85559ed`
- Declared module: `github.com/gotthboard/gotth-oidc`
- Runtime/API behavior: unchanged; this is a module-identity and distribution
  contract migration.

Exact stale-prefix searches found no old module or import identity in Go source,
`go.mod`, examples, or fixtures. Canonical Forgejo URLs remain only where the
development, issue, contribution, and security-reporting endpoints are stated.

## Verification

- Local `go mod tidy` produced no dependency drift.
- Local `go vet -mod=readonly ./...` passed.
- Local `go test -mod=readonly ./...` passed.
- On `development`, `make verify` passed with race coverage 90.1%.
- On `development`, `go test -mod=readonly -race -count=50 ./...` passed.
- No repository-specific verification exception was required.
- A fresh public GitHub clone of `feature/github-distribution` resolved exact
  commit `349bf6329edadb9a4346edbbba99426ac85559ed` and passed `go test -mod=readonly ./...`.
- A fresh external consumer compiled the public package through both direct VCS
  resolution and `https://proxy.golang.org,direct` at
  `v0.0.0-20260903060720-349bf6329eda`.
- Complete Forgejo and GitHub advertised head/tag ref sets matched after the
  candidate push.

The slash-containing feature ref is accepted by direct VCS resolution but is
not a legal version query for the module proxy. The proxy lane therefore used
the exact pseudo-version above. Final `@main` resolution is a promotion gate.

## Impact graph

Graphify recorded 338 nodes / 1,062 edges at implementation commit. Graph SHA-256:
`c3f02fd0e21b386f807d2dbea805637b523fb3410ffff7bf73e91765919dfaa0`. Subsequent commits before this record changed documentation
only. The merged suite graph had 4,116 nodes and 11,415 edges, with no
cross-repository module dependency edge.

## Admission and residual gates

Two cold Judge passes review the completed candidate tree before this evidence
is committed. No performance benchmark applies because executable paths and
data flow are unchanged.

No license was selected. Release tags remain blocked until Danny closes that
decision gate. GitHub metadata mutation lacks authentication. Forgejo is still
private, so unauthenticated public contribution and private vulnerability
reporting remain unresolved. Account conversion and ownership changes were not
performed.
