# Extraction verification

Verified on 2026-09-02 with Go `go1.26.6-X:nodwarf5`:

- `go vet -mod=readonly ./...`
- `go test -mod=readonly -race -cover ./...`
- statement coverage: 94.5%
- complete public `New`/`Begin`/`Complete` flow exercised through a disposable
  discovery, token, and JWKS server
- malicious-provider, tamper, malformed-token, claim, entropy, and redaction
  cases retained from the alpha.2 implementation
- no board database, session, role, route, or cookie package imported

The remaining uncovered lines are defensive crypto/library error branches that
cannot be induced through valid Go standard-library constructions without
replacing the underlying implementations.

Graphify 0.9.32 code-only audit: 135 nodes, 280 directed post-build edges, no
self-loops, exact duplicate edges, or same-endpoint relation groups.
