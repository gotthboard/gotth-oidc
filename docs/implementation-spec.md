# Implementation specification

- Go module: `git.dannyhunn.com/agents/gotth-oidc`
- Root package: `oidc`
- Provider discovery timeout: 10 seconds
- Maximum OIDC HTTP response: 512 KiB
- Maximum authorization code: 4096 bytes
- Maximum ID token: 64 KiB
- State, nonce, and PKCE verifier: independent 32-byte values
- Protected attempt: SHA-256 state lookup and versioned AES-256-GCM envelopes
- Accepted identity claims: issuer, subject, name, verified email, safe picture
- Authorization-shaped claims are not decoded into the public result
- Callers must atomically consume attempts before calling `Complete`
