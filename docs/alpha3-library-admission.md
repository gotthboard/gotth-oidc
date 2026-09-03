# Alpha.3 library admission

## Scope and authority

This pass admits `pkg/oidc` as the canonical package for GOTTH Board alpha.3.
It changes no provider, client registration, key, token, session, user, route,
or authorization state.

## Requirement traceability

| Requirement | Design/specification | Code | Verification |
|---|---|---|---|
| `OIDC-A3-01` | architecture and README layout | `pkg/oidc/` | canonical outside-package test |
| `OIDC-A3-02` | implementation specification | `pkg/oidc/` | package inventory and outside-consumer compile |
| `OIDC-A3-03` | architecture trust boundaries | provider/exchange/JOSE code | hostile and negative tests |
| `OIDC-A3-04` | `docs/conformance.md` and specification | protocol implementation | RFC, boundary, and fuzz tests |
| `OIDC-A3-05` | `docs/verification.md` | tests/workflow evidence | clean clone, graph, two Judge passes |

## Runtime boundary

- Go 1.26.6 and the pinned OAuth/OIDC/JOSE dependencies in `go.mod`/`go.sum`.
- Protocol authorities: OIDC Core and Discovery 1.0 plus the RFCs enumerated in
  `docs/conformance.md`.
- Network responses, callbacks, authorization codes, JWTs, JSON, endpoints,
  scopes, claims, and login material are explicitly bounded by the
  implementation specification and hostile tests.
- Completeness oracles are exact issuer/client/redirect/response-policy binding,
  signature and claim verification, UserInfo subject equality, and explicit
  capability negotiation. Redirects and untrusted endpoint escape fail closed.

## Performance admission

No protocol mechanism, cryptographic operation, network round trip, payload
bound, or allocation strategy changes. The original implementation moved
intact to the canonical package. No speedup is claimed, so benchmark/Amdahl
evidence is N/A for this structural admission. Future performance work must
measure every supported capability and must not weaken cryptographic or
network verification.

## Failure and rollback

Rollback is a revert before the first consumer pin. The pass creates no live
provider mutation and handles no real credentials. Alpha.3 remains responsible
for atomic attempt and token/replay storage, TLS, and product authorization.
