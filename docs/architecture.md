# Architecture

One in-process client owns validated provider metadata and a hardened HTTP
client. `Begin` generates three independent 256-bit secrets, returns the browser
authorization URL, and returns only a hashed/encrypted storage record.
`Complete` accepts a caller-consumed storage record, recovers the nonce and PKCE
verifier, exchanges the code once, verifies the token, and returns identity.

The storage boundary is deliberately caller-owned. A reusable library cannot
pretend every application has the same database, session model, transaction,
return-path policy, or role system.
