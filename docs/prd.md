# Product requirements

Provide multiple Go applications one small, auditable OIDC relying-party
library without coupling protocol correctness to application storage or policy.

Required behavior: exact issuer validation; same-origin discovery, token, and
JWKS endpoints; bounded HTTP with redirects refused; confidential and public
clients; Authorization Code with S256 PKCE, state, and nonce; ID-token and
access-token-hash verification; provider-neutral identity output; protected
attempt state; redacted diagnostics.

Non-goals: local users, sessions, cookies, RBAC, persistence, provider
provisioning, refresh tokens, OAuth API access, and a deployed auth service.
