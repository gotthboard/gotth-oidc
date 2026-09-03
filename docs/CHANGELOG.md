# Changelog

This repository records user-visible and compatibility-relevant changes here.
Released sections use Semantic Versioning; unreleased work remains under
`Unreleased` and does not imply a tag.

## Unreleased

### 2026-09-03 00:42 CDT — Establish GitHub public distribution

Commit: current commit; hash assigned by Git after commit

Affected files:

- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `docs/distribution.md`
- `docs/RELEASING.md`
- `go.mod` and repository-owned Go import references
- repository-owned Go source, tests, fixtures, and package documentation
- `workflow.toml` and `workflow/features/github-distribution/`

Explanation:

Declare GitHub as the public distribution endpoint while retaining Forgejo as
canonical development, define maturity and support honestly, and document the
independent release process. The Go module identity and exact self-imports move to the public GitHub path.

Verification:

- exact old-import search
- documentation contract audit
- `go mod tidy` drift check
- `go vet -mod=readonly ./...`
- `go test -mod=readonly ./...`

Risks / non-goals:

- No license is selected.
- No existing tag is changed and no new release is created.
- Mirror direction, repository ownership, and account type are unchanged.
