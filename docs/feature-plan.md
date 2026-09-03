# Feature plan

1. Extract and rename the alpha.2 protocol core.
2. Add a small storage-neutral public API.
3. Preserve adversarial discovery, token, claim, entropy, and tamper tests.
4. Verify format, vet, race, and coverage gates.
5. Publish the private module before changing any consumer.

## Reusable v0 admission

1. Pin verification to the safe intersection of provider-advertised signing
   algorithms.
2. Require HTTPS except numeric loopback fixtures for every network URL.
3. Prove public and confidential flows, mixed-algorithm rejection, external
   package compilation, cancellation, tamper resistance, and redaction.
4. Run race repetition, clean-clone verification, and a fresh code-graph audit.
5. Leave the first tag and application pin to an explicit consumer release.

## RFC-complete OIDC admission

1. Repair root-issuer, discovery-default, required-metadata, endpoint-policy,
   token-type, audience/authorized-party, and mix-up handling.
2. Version and authenticate the authorization-attempt context; add typed query,
   form-post, OAuth-error, issuer, and JARM callback parsing.
3. Add opt-in request/profile capabilities: claims, prompt, max-age, ACR,
   UserInfo, arbitrary bounded scopes, and explicit token return/refresh.
4. Add opt-in protocol capabilities: JWT client authentication, PAR, JAR,
   encrypted JWTs, WebFinger, registration, logout, DPoP, and mTLS aliases.
5. Prove every advertised capability with hostile fixtures, fuzzing,
   external-consumer compilation, race repetition, clean clones, and a graph
   audit. Record any boundary owned by consumers rather than claiming it.
