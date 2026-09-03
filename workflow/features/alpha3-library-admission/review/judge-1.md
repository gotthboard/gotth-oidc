# Judge pass 1 — rejected and repaired

The first cold review rejected a module-root compatibility facade. No released
tag or consumer pin established that import path, so the facade created a
second security-sensitive API for no userspace benefit.

Repair: remove the facade, retain exactly one public relying-party package at
`pkg/oidc`, and keep the module root for governance. Protocol mechanisms and
trust boundaries remain byte-for-byte unchanged.
