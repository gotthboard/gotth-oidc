# gotth-oidc

`gotth-oidc` is a storage-neutral Go relying-party library for hardened OpenID
Connect Authorization Code flows. It provides exact-issuer discovery,
same-origin endpoint enforcement, bounded redirect-refusing HTTP, PKCE, state,
nonce, ID-token verification, safe profile claims, and protected transient
login material.

The admitted provider contract is intentionally narrow: issuer,
authorization, token, and JWKS URLs use HTTPS, except numeric loopback HTTP for
disposable development; all discovered endpoints remain on the exact issuer
origin; signing algorithms are restricted to the package allowlist even when a
provider advertises a mixed list; and token authentication is
`client_secret_basic` or public-client `none`. The flow requests
`openid profile email` and requires a bounded `name` claim. This is a hardened
identity-login client, not a universal OAuth client.

The application must atomically store and consume `ProtectedAttempt`, own the
user and session database, and decide authorization. This library never grants
roles, creates local accounts, issues application sessions, or runs as another
network service. Attempt expiry, callback routing, return-path validation, and
login rate limits also remain application-owned.

Extracted from the protocol engine admitted in GOTTH Board 1.0.0-alpha.2.
