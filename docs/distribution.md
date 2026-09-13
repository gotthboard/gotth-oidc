# Distribution Contract

## Endpoints

- Canonical development source:
  <https://git.dannyhunn.com/gotthboard/gotth-oidc>
- Public clone, Go import, and future releases:
  <https://github.com/gotthboard/gotth-oidc>
- Public bug tracker:
  <https://github.com/gotthboard/gotth-oidc/issues>
- Private vulnerability reports:
  <https://github.com/gotthboard/gotth-oidc/security/advisories/new>

Forgejo pushes one way to GitHub. GitHub does not feed commits or tags back to
Forgejo. A ref is distributed only when the exact object ID is visible at both
endpoints.

## Maturity and compatibility

Current status: unreleased Go library with an unstable pre-1.0 API.

## Current source use

No post-migration version has been tagged. Until one is admitted, source users
must select the moving `main` branch explicitly:

```sh
go get github.com/gotthboard/gotth-oidc@main
```

```go
import gotthoidc "github.com/gotthboard/gotth-oidc"
```

A Go command records a pseudo-version in the consumer's `go.mod`; review that
exact revision. Do not mistake `@main` for a compatibility promise.

The repository pins Go 1.26.6 where a Go module exists. Supported protocol,
runtime, database, and tool versions remain the ones stated in the README and
project verification documents; this distribution change does not widen those
contracts.

## License

The repository is licensed under the MIT License. The license decision gate is
closed; release publication still requires every verification and distribution
step in `docs/RELEASING.md`.

## Migration traceability

| Requirement | Repository implementation | Verification |
| --- | --- | --- |
| DIST-001 | Existing history, tags, worktrees, and mirror direction remain unchanged | pinned ref and worktree inventory |
| DIST-002 | Module directive, exact self-imports, fixtures, and examples use the GitHub identity | stale-prefix search, tidy, vet, test, and clean public import |
| DIST-003/004 | README, contribution, security, changelog, and release contracts describe public use and support | documentation audit |
| DIST-006 | MIT license is explicit and included in distributed source | license inventory and exact-text audit |
| DIST-008 | Forgejo remains source and GitHub remains the one-way mirror target | push-mirror configuration and exact ref comparison |
