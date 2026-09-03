# Reusable v0 OIDC admission

Verified implementation commit
`c1d53d553136b933aeaa29e284c626ca7a92913a` on 2026-09-03 UTC.

## Contract evidence

- The exported `New`, `Begin`, and `Complete` API remains storage-neutral and
  is compiled from an external test package.
- The verifier receives only the sorted, deduplicated intersection of the
  provider's advertised algorithms and the asymmetric safe list. A mixed
  ES256/HS256/none fixture accepts ES256 and rejects a validly signed HS256
  token even when the corresponding symmetric JWK is published.
- Issuer, callback, authorization, token, JWKS, and picture URLs require HTTPS.
  Numeric loopback IP HTTP remains available for disposable tests; remote HTTP
  and the `localhost` hostname fail before network access.
- Both confidential `client_secret_basic` and public `none` clients complete
  full authorization-code exchanges with PKCE, state, nonce, ID-token, and
  access-token-hash verification.
- OAuth tokens, application accounts, sessions, roles, routing, attempt
  persistence, attempt expiry, and atomic attempt consumption remain outside
  the module.

## Verification

- Go toolchain: `go1.26.6-X:nodwarf5`.
- `make verify`: pass; formatting, vet, race, and 96.8% statement coverage.
- `go test -mod=readonly -race -count=50 ./...`: pass.
- Clean local clone of the committed feature branch followed by `make verify`:
  pass with no generated worktree changes.
- End-to-end provider fixtures are disposable in-process HTTP servers bound to
  numeric loopback. No live identity provider or consumer application changed.
- The remaining 3.2% consists of defensive outcomes the pinned libraries do
  not expose through their contracts: a nil OAuth token without an error,
  verified-token claim re-decoding failures, provider metadata re-decoding
  failure after successful discovery, standard-library AES/GCM constructor
  failures with fixed valid inputs, and an impossible AEAD envelope length.
  The public security boundary and every newly changed branch are exercised.

## Graph evidence

- Graphify 0.9.32 code-only graph: 146 nodes, 283 directed edges, 15
  communities, no self-loops, exact duplicate edges, or same-endpoint relation
  groups.
- Graph SHA-256:
  `13460921587055e8dca8a78b6f6b9812892c937183ce256444b1ff2bcb6fbcbe`.
- Graph cache:
  `/home/linus/.cache/openclaw-graphify/gotth-oidc-reusable/graphify-out/graph.json`.
  Extraction changed no repository file.

No tag or consumer pin was created. The first compatibility promise belongs to
a real consumer integration.
