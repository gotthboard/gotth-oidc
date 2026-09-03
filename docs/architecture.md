# Architecture

One in-process client owns validated provider metadata and a hardened HTTP
client. The verifier receives only the safe intersection of provider-advertised
signing algorithms; merely advertising one safe algorithm does not admit its
unsafe neighbors. Network URLs require HTTPS except numeric loopback HTTP used
by disposable development fixtures. `Begin` generates three independent 256-bit secrets, returns the browser
authorization URL, and returns only a hashed/encrypted storage record.
`Complete` accepts a caller-consumed storage record, recovers the nonce and PKCE
verifier, exchanges the code once, verifies the token, and returns identity.

The storage boundary is deliberately caller-owned. A reusable library cannot
pretend every application has the same database, session model, transaction,
return-path policy, or role system.

The package intentionally fixes the `openid profile email` identity profile,
exact-origin endpoints, and supported token-authentication styles. Consumers
needing OAuth API access, refresh tokens, arbitrary scopes, or split-origin
providers need a different contract, not flags that quietly weaken this one.
