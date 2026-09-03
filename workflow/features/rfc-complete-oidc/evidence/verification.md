# RFC-complete OIDC verification evidence

- Rollback head: `d7f8398bffc559de83440e9430421178a4503f40`
- Requirements/architecture commit: `bcc71a6`
- Implementation commit: `11c1d63d6231dd0ce5801b57c68beaf1a4529730`
- Toolchain: Go 1.26.6 (vendor suffix accepted by the repository gate)

## Standards surface

Mandatory and security-relevant repairs cover audience/`azp`, token type,
issuer-bound attempts and RFC 9207 responses, Discovery defaults/required
metadata, root issuers, endpoint query strings, explicit endpoint policy,
profile claim policy, and UserInfo subject binding.

Implemented opt-in profiles cover claims/prompt/max-age/ACR/locales/hints,
query/form-post/JARM callbacks, every standardized client authentication method,
PAR, JAR, signed/encrypted JWT handling, explicit token custody, offline access,
refresh, revocation, WebFinger, Dynamic Registration, RP-Initiated Logout,
Front-Channel Logout, Back-Channel Logout, DPoP including `dpop_jkt`, and mutual
TLS endpoint aliases.

Implicit and Hybrid flows remain excluded under RFC 9700. Product accounts,
sessions, authorization, durable token/replay storage, TLS termination, and
protected-resource business clients remain explicit consumer boundaries.

## Executed gates

- `go mod verify`: pass
- `make verify`: pass
- Statement coverage: 90.1%
- `go test -race ./...` repeated 50 consecutive times: pass
- Fuzz admissions: pass, 250,446 generated inputs total
  - callbacks: 102,110
  - attempt contexts: 86,261
  - JWT headers: 62,075
- External-package public API compilation: pass in the normal suite
- Graphify 0.9.32 code-only graph: 338 nodes, 792 edges, 17 communities
- Graph SHA-256: `c622d9e7e28632adba0f322ae5c0768b8c8cd8e923afa92ee7bff5243abb7b23`
- Graph structural audit: zero self-loops, duplicate relations, or same-endpoint
  relation collisions
- Graphify skipped ten documentation files and five unsupported control files;
  no sensitive file contents were ingested or emitted

## Coverage gaps

The uncovered 9.9% consists of deterministic standard-library URL/JSON/JOSE
construction failures, injected entropy failures, broken custom
transport/signer/decrypter contracts, and defensive branches the pinned
libraries cannot produce after successful validation. They fail closed and do
not remove a protocol capability. No RFC behavior is declared supported solely
by documentation.

## Consumer gates

A real consumer must still prove its provider metadata, redirect and logout URI
registration, client credentials or certificates, key rotation, atomic attempt
consumption, token-at-rest protection, logout-token replay ledger, TLS boundary,
and local identity/session policy before pinning the first tag.
