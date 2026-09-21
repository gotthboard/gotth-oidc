# v0.1.0 Release Admission

Publish the first immutable `gotth-oidc` module version for the live GOTTH Mail
consumer. The release contains no API or runtime change over source commit
`1ae119e52f8efc3392fcc9fa716b1b27c9ffce6c`.

## Ordered work

1. Record the exact compatibility effect and limitations.
2. Run the complete repository gates on the clean candidate.
3. Admit the release metadata to canonical `main`.
4. Create one immutable annotated `v0.1.0` tag.
5. Verify exact Forgejo/GitHub tag parity and a clean public consumer import.

The tag is not movable. A defect after publication requires a new SemVer
version.
