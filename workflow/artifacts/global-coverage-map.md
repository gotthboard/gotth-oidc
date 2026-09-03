# Coverage map

| Surface | Evidence |
|---|---|
| Discovery, defaults, root issuers, endpoint policy | `provider_test.go`, `rfc_negative_test.go` |
| Authorization URL, PKCE, optional request parameters | `authorization_url_test.go`, `rfc_features_test.go`, `rfc_negative_test.go` |
| Callback query/form/JARM and issuer binding | `rfc_features_test.go`, `rfc_negative_test.go`, `fuzz_test.go` |
| Code exchange, token type, audience/`azp`, ID token | `exchange_test.go`, `rfc_features_test.go`, `rfc_negative_test.go` |
| UserInfo, profile policy, encrypted JWTs | `identity_claims_test.go`, `rfc_features_test.go`, `rfc_negative_test.go` |
| PAR, JAR, client authentication | `rfc_features_test.go`, `rfc_negative_test.go` |
| DPoP code binding/proofs/nonce and mutual TLS | `rfc_features_test.go`, `rfc_negative_test.go` |
| Token return, refresh, and revocation | `rfc_features_test.go`, `rfc_negative_test.go` |
| WebFinger and Dynamic Registration | `rfc_features_test.go`, `rfc_negative_test.go` |
| RP, front-channel, and back-channel logout | `rfc_features_test.go`, `rfc_negative_test.go` |
| Attempt generation/protection/context/recovery | `login_*_test.go`, `api_test.go`, `rfc_negative_test.go`, `fuzz_test.go` |
| Public and external-consumer API | `api_test.go`, `public_api_test.go` |

Implementation and hostile tests above now live under `pkg/oidc/`; the root
`public_api_test.go` imports that canonical package.

Statement coverage is 90.1%. Uncovered code is limited to deterministic
standard-library construction/encoding failures, injected entropy failures,
broken custom transport/signer/decrypter implementations, and defensive
branches whose triggering contracts cannot be produced by the pinned
libraries. Those branches still fail closed.
