# Implementation specification

- Go module: `github.com/gotthboard/gotth-oidc`
- Root package: `oidc`
- Provider discovery timeout: 10 seconds
- Maximum OIDC HTTP response: 512 KiB
- Issuer, callback, and discovered endpoints use HTTPS. Numeric-loopback HTTP
  requires explicit development permission. Root issuers and standards-legal
  endpoint query strings are accepted. Endpoint hosts are individually checked
  by policy; strict same-origin remains available.
- The ID-token verifier receives only unique advertised algorithms from the
  package allowlist: RS256/384/512, ES256/384/512, PS256/384/512, and EdDSA.
- Maximum authorization code: 4096 bytes
- Maximum ID token: 64 KiB
- State, nonce, and PKCE verifier: independent 32-byte values
- Protected attempt: SHA-256 state lookup plus versioned AES-256-GCM envelopes
  for nonce, PKCE verifier, and bounded request-validation context
- ID-token validation: exact issuer, safe algorithm, signature, expiry, nonce,
  audience, authorized party, requested max-age/auth-time, ACR, optional access
  token hash, and explicit JWT purpose
- Token responses require the expected Bearer or DPoP token type; mutual TLS
  uses validated endpoint aliases and the caller's certificate-bearing transport
- Identity minimum: issuer and subject. Name, verified email, safe picture, and
  UserInfo are consumer-configurable; UserInfo subject must equal ID-token subject
- Authorization callbacks support query, form-post, OAuth errors, RFC 9207
  issuer identification, and signed JARM responses
- Client authentication: none, client_secret_basic, client_secret_post,
  client_secret_jwt, private_key_jwt, tls_client_auth, and
  self_signed_tls_client_auth
- Optional direct operations: WebFinger, dynamic registration, PAR, refresh,
  UserInfo, RP-initiated logout, and back-channel logout-token verification
- Optional sender constraints: DPoP authorization-code binding, proof
  generation, nonce retry, and RFC 8705 mutual-TLS endpoint aliases
- Authorization-shaped claims are not decoded into the public result
- Callers must atomically consume attempts before calling `Complete`
- Consumers own attempt expiry/atomic consumption, browser routing, session
  creation, token-at-rest protection, key custody, authorization policy, TLS
  termination, and provider registration policy.
