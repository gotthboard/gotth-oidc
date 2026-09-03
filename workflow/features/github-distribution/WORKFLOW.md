# GitHub Distribution Migration

This feature implements DIST-001 through DIST-008 from the suite migration
control record. It changes repository identity and documentation, not runtime
behavior.

## Ordered work

1. Preserve the pinned main revision and all existing worktrees.
2. Move the module directive and exact repository-owned imports.
3. Add the public distribution, support, contribution, security, changelog,
   and release contracts.
4. Run local and development-host verification.
5. Pass two cold Judge reviews.
6. Push to Forgejo and prove exact GitHub mirror parity.

License selection, a first post-migration tag, GitHub metadata authentication,
Forgejo visibility, and account conversion remain separate decision gates.
