# gotth-oidc

`gotth-oidc` is a storage-neutral Go OpenID Connect relying-party library. Its
small default is Authorization Code with S256 PKCE, state, nonce, exact issuer
validation, bounded redirect-refusing HTTP, verified ID tokens, and protected
one-time attempt state. The default completion API returns identity only; token
custody is opt-in.

The default network policy keeps every discovered endpoint on the issuer
origin. Conformant split-origin deployments can select a broader HTTPS policy
or provide an exact allowlist. HTTPS is mandatory outside explicitly enabled
numeric-loopback development endpoints. Endpoint query strings, root issuers,
and Discovery defaults are supported.

The library validates token type, audience and `azp`, authorization-response
issuer binding, signing-algorithm intersections, callback response mode,
UserInfo subject equality, requested `max_age`/`auth_time` and ACR, and
purpose-specific JWT headers. Login attempts bind the issuer, client ID,
redirect URI, response mode, and requested validation policy.

Optional standards features are explicit capabilities rather than ambient
behavior:

- query, `form_post`, and signed JARM authorization responses;
- claims, prompt, max-age, ACR, locale, login-hint, and ID-token-hint requests;
- UserInfo and consumer-selected profile requirements;
- PAR, JAR request objects, and encrypted JWTs;
- public, client-secret, JWT, and mutual-TLS client authentication;
- explicit token return, offline access, refresh, and revocation;
- WebFinger issuer discovery and Dynamic Client Registration;
- RP-Initiated, Front-Channel, and Back-Channel Logout parsing/verification;
- DPoP authorization-code binding/proofs and mutual-TLS endpoint aliases.

Implicit and Hybrid flows are deliberately absent. RFC 9700 deprecates or
discourages putting tokens in authorization responses; preserving those legacy
flows would enlarge the attack surface without improving the reusable login
boundary.

Consumers must atomically store and consume `ProtectedAttempt`, enforce attempt
expiry and login rate limits, own users and application sessions, protect any
retained tokens and signing/decryption keys, persist logout-token replay state,
and decide authorization. Authentication transport termination, callback
routing, provider registration policy, and protected-resource business clients
also remain consumer responsibilities.

See `docs/conformance.md` for the standards and capability matrix. The module
remains untagged until a real consumer pins its first compatibility contract.
