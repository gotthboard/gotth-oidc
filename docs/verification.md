# Verification

`make verify` is the required local gate. Tests cover malicious discovery
metadata, origin escape, redirects, oversized responses, unsupported signing
and client-auth methods, malformed codes and tokens, nonce mismatch, claim
type and size errors, unverified email, unsafe pictures, entropy failure,
repeated material, ciphertext tampering, and secret-redacted formatting.

Provider integration remains a consumer gate because client registration,
redirect URIs, and tenant policy belong to the consuming application.
