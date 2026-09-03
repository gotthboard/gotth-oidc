# Verification

`make verify` is the required local gate. Tests cover malicious discovery
metadata, origin escape, redirects, oversized responses, unsupported signing
and client-auth methods, malformed codes and tokens, nonce mismatch, claim
type and size errors, unverified email, unsafe pictures, entropy failure,
repeated material, ciphertext tampering, and secret-redacted formatting.

Reusable admission additionally requires a mixed safe/unsafe algorithm fixture,
HTTPS/loopback boundary tests, an external-package public API test, 50
race-enabled repetitions, a clean-clone gate, and a fresh code-graph audit.

Provider integration remains a consumer gate because client registration,
redirect URIs, and tenant policy belong to the consuming application.
