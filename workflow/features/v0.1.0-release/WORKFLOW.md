# v0.1.0 Release Admission

Publish the first immutable `gotth-oidc` module version for the live GOTTH Mail
consumer. The release contains no API or runtime change over source commit
`1ae119e52f8efc3392fcc9fa716b1b27c9ffce6c`.

## Completed work

1. Recorded the exact compatibility effect and limitations.
2. Ran the complete repository gates on the exact peeled release commit.
3. Admitted the release metadata to canonical `main`.
4. Created the immutable annotated `v0.1.0` tag.
5. Verified exact Forgejo/GitHub tag-object and peeled-commit parity, a clean
   exact-package consumer, and reproducible release assets.

## Remaining work

Create or publish the normal GitHub Release on the existing mirrored tag using
`docs/release-notes-v0.1.0.md`, the deterministic source archive, and
`SHA256SUMS`. Then run the read-only closeout check with
`EXPECT_STATE=complete` before completing this
workflow feature.

The tag is not movable. A defect after publication requires a new SemVer
version.
