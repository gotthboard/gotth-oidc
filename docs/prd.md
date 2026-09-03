# Product requirements

Provide Go applications one auditable OpenID Connect relying-party library
without coupling protocol correctness to application storage or product policy.

The default profile is Authorization Code with S256 PKCE, state, nonce, exact
issuer validation, strong ID-token validation, bounded HTTP, no redirects,
provider-neutral identity output, protected attempt state, and redacted
diagnostics. It must interoperate with conformant root issuers, discovery
defaults, split-origin endpoint deployments, and legal endpoint query strings
without silently widening trust.

Every attempt binds the issuer, client identifier, redirect URI, response mode,
requested authentication context, and token handling policy. Multi-audience ID
tokens, authorization-response issuer parameters, token types, UserInfo
subjects, and cross-JWT purposes are validated explicitly.

Optional standardized capabilities are opt-in: UserInfo, claims requests,
prompt/max-age/ACR policy, query/form-post/JARM responses, client-secret and JWT
client authentication, PAR, JAR, encrypted JWTs, refresh/offline access,
WebFinger, dynamic registration, RP-initiated and back-channel logout, DPoP,
and mutual-TLS endpoint aliases. Unsupported provider capabilities fail during
configuration, not halfway through an interactive login.

Non-goals: local users, sessions, cookies, RBAC, application persistence,
provider administration, authorization policy, protected-resource business
clients, and a deployed authentication service. The library may return tokens
only through an explicit opt-in result; the default completion path discards
them.

Admission requires an explicit standards matrix, external-package API
compilation, confidential/public and optional-capability end-to-end flows,
malicious-provider, mix-up, cross-JWT, replay, and cryptographic-tamper tests,
fuzzing, race repetition, clean-clone verification, and recorded coverage gaps.

## Alpha.3 admission requirements

- `OIDC-A3-01`: New consumers import the documented `pkg/oidc` package.
- `OIDC-A3-02`: Exactly one public Go package exists; the module root owns no
  protocol state or Go implementation.
- `OIDC-A3-03`: Package reorganization does not widen endpoint, token, key,
  callback, or identity authority.
- `OIDC-A3-04`: Runtime limits and supported standards remain pinned and
  boundary-tested.
- `OIDC-A3-05`: Clean-clone, race, fuzz, external-consumer, graph, and two
  clean Judge passes gate alpha.3 admission.
