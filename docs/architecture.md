# Architecture

The canonical public implementation lives in `pkg/oidc`. The module root
contains no Go package; it owns repository governance only.

One in-process client owns validated provider metadata, endpoint policy, client
authentication, JOSE capabilities, and a bounded HTTP client. The verifier
receives only the safe intersection of advertised signing algorithms. Network
URLs require HTTPS except explicitly enabled numeric-loopback fixtures; each
endpoint is independently allowlisted, so standards-compatible split origins
do not become arbitrary outbound access.

`Begin` remains the small local default. `BeginContext` accepts bounded request
options and performs PAR when configured. Both generate independent 256-bit
state, nonce, and PKCE values and return a versioned encrypted attempt context
binding the issuer, client, redirect URI, response mode, requested claims,
maximum age, ACR policy, and token mode.

`ParseCallback` handles query and form-post success/error responses. JARM is
verified as a purpose-bound JWT before its parameters are admitted. `Complete`
preserves the token-discarding identity-only contract; `CompleteResponse`
performs issuer/mix-up checks, code exchange, token-type validation, ID-token
signature/decryption/audience/azp/time/nonce/ACR checks, optional UserInfo with
exact subject equality, and returns identity. `CompleteTokens` is the explicit
opt-in token-bearing variant. Refresh uses the same client authentication,
sender constraint, endpoint policy, and ID-token validation rules.

Optional cryptography is supplied through narrow signer/decrypter/proof
interfaces. Built-in JOSE adapters enforce algorithm allowlists and JWT purpose;
consumer keys remain consumer-owned. PAR, registration, UserInfo, token,
revocation, and logout endpoints never share credentials or trust merely
because their URLs look related.

The storage boundary is deliberately caller-owned. A reusable library cannot
pretend every application has the same database, session model, transaction,
return-path policy, or role system.

The package fixes `openid` as mandatory but makes additional scopes and profile
requirements explicit bounded options. Strict same-origin operation remains an
available policy, not an undocumented conformance restriction. Optional
features are capability objects; absence disables them and discovery claims
cannot enable behavior by themselves.
