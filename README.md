# gotth-oidc

`gotth-oidc` is a storage-neutral Go relying-party library for hardened OpenID
Connect Authorization Code flows. It provides exact-issuer discovery,
same-origin endpoint enforcement, bounded redirect-refusing HTTP, PKCE, state,
nonce, ID-token verification, safe profile claims, and protected transient
login material.

The application must atomically store and consume `ProtectedAttempt`, own the
user and session database, and decide authorization. This library never grants
roles, creates local accounts, issues application sessions, or runs as another
network service.

Extracted from the protocol engine admitted in GOTTH Board 1.0.0-alpha.2.
