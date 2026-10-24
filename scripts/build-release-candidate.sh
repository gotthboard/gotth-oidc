#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 VERSION OUTPUT_DIR [REF]" >&2
  exit 2
fi
version=$1
output=$2
ref=HEAD
if [ "$#" -eq 3 ]; then ref=$3; fi
if ! python3 - "$version" <<'PY'
import re, sys
match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", sys.argv[1])
if match is None:
    raise SystemExit(1)
prerelease = match.group(4)
if prerelease and any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in prerelease.split(".")):
    raise SystemExit(1)
PY
then
  echo "VERSION must be valid SemVer with a v prefix" >&2
  exit 2
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
commit=$(git rev-parse --verify "$ref^{commit}")
script_at_ref=$(mktemp)
tmp=$(mktemp -d)
trap 'rm -f "$script_at_ref"; rm -rf "$tmp"' EXIT HUP INT TERM
stem="gotth-oidc-$version"
output=$(readlink -m -- "$output")
case "$output/" in
  "$root/"*) echo "OUTPUT_DIR must be outside the source repository" >&2; exit 2 ;;
esac
mkdir -p "$output"
git show "$commit:scripts/build-release-candidate.sh" >"$script_at_ref"
if ! cmp -s "$script_at_ref" scripts/build-release-candidate.sh; then
  echo "builder differs from the selected commit" >&2
  exit 1
fi
archive="$output/$stem-source.tar.gz"
sbom="$output/$stem.spdx.json"
license_evidence="$output/$stem.LICENSE-EVIDENCE.txt"
provenance="$output/$stem.provenance.json"
checksums="$output/SHA256SUMS"

build_archive() {
  destination=$1
  git archive --format=tar --prefix="$stem/" "$commit" | gzip -n -9 >"$destination"
}
build_archive "$archive"
build_archive "$tmp/rebuilt.tar.gz"
cmp "$archive" "$tmp/rebuilt.tar.gz"

git show "$commit:go.mod" >"$tmp/go.mod"
git show "$commit:go.sum" >"$tmp/go.sum"
git show "$commit:LICENSE" >"$tmp/LICENSE"
(cd "$tmp" && go mod edit -json) >"$tmp/go-mod.json"
commit_epoch=$(git show -s --format=%ct "$commit")
commit_time=$(date -u -d "@$commit_epoch" +%Y-%m-%dT%H:%M:%SZ)
source_sha=$(sha256sum "$archive" | awk '{print $1}')
license_sha=$(sha256sum "$tmp/LICENSE" | awk '{print $1}')
license_copyright=$(sed -n '/^Copyright /{p;q;}' "$tmp/LICENSE")
script_sha=$(sha256sum "$script_at_ref" | awk '{print $1}')
archive_license="$stem/LICENSE"
tar -tzf "$archive" | grep -Fqx "$archive_license"
cat >"$license_evidence" <<EOT
version=$version
commit=$commit
source_archive=$stem-source.tar.gz
source_archive_sha256=$source_sha
declared_license=MIT
repository_license_path=LICENSE
repository_license_sha256=$license_sha
archive_license_path=$archive_license
archive_contains_license=true
EOT
license_evidence_sha=$(sha256sum "$license_evidence" | awk '{print $1}')

python3 - "$version" "$commit" "$commit_time" "$source_sha" "$license_sha" "$license_copyright" "$tmp/go-mod.json" "$sbom" <<'PY'
import json, pathlib, sys
version, commit, created, source_sha, license_sha, copyright_text, gomod_path, output = sys.argv[1:]
data = json.loads(pathlib.Path(gomod_path).read_text())
module = data["Module"]["Path"]
packages = [{
    "SPDXID": "SPDXRef-Package-gotth-oidc",
    "name": module,
    "versionInfo": version,
    "downloadLocation": "NOASSERTION",
    "filesAnalyzed": False,
    "licenseConcluded": "MIT",
    "licenseDeclared": "MIT",
    "copyrightText": copyright_text,
    "checksums": [{"algorithm": "SHA256", "checksumValue": source_sha}],
}]
relationships = []
for index, requirement in enumerate(sorted(data.get("Require") or [], key=lambda item: (item["Path"], item["Version"]))):
    path, dep_version = requirement["Path"], requirement["Version"]
    spdx_id = f"SPDXRef-Dependency-{index + 1}"
    packages.append({
        "SPDXID": spdx_id,
        "name": path,
        "versionInfo": dep_version,
        "downloadLocation": f"https://proxy.golang.org/{path}/@v/{dep_version}.zip",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": f"pkg:golang/{path}@{dep_version}"}],
    })
    relationships.append({"spdxElementId": "SPDXRef-Package-gotth-oidc", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": spdx_id})
document = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": f"gotth-oidc-{version}",
    "documentNamespace": f"https://github.com/gotthboard/gotth-oidc/spdx/{version}/{commit}",
    "creationInfo": {"created": created, "creators": ["Tool: scripts/build-release-candidate.sh"]},
    "documentDescribes": ["SPDXRef-Package-gotth-oidc"],
    "packages": packages,
    "relationships": relationships,
    "annotations": [{"annotationType": "OTHER", "annotator": "Tool: scripts/build-release-candidate.sh", "annotationDate": created, "comment": f"Repository LICENSE SHA-256: {license_sha}"}],
}
pathlib.Path(output).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
PY
sbom_sha=$(sha256sum "$sbom" | awk '{print $1}')

python3 - "$version" "$commit" "$source_sha" "$sbom_sha" "$license_evidence_sha" "$script_sha" "$provenance" <<'PY'
import json, pathlib, sys
version, commit, source_sha, sbom_sha, license_sha, script_sha, output = sys.argv[1:]
stem = f"gotth-oidc-{version}"
statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [
        {"name": f"{stem}-source.tar.gz", "digest": {"sha256": source_sha}},
        {"name": f"{stem}.spdx.json", "digest": {"sha256": sbom_sha}},
        {"name": f"{stem}.LICENSE-EVIDENCE.txt", "digest": {"sha256": license_sha}},
    ],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
        "buildDefinition": {
            "buildType": f"https://github.com/gotthboard/gotth-oidc/blob/{commit}/docs/release-build-type-v1.md#build-type",
            "externalParameters": {"version": version, "ref": commit},
            "internalParameters": {},
            "resolvedDependencies": [{"uri": "git+https://git.dannyhunn.com/gotthboard/gotth-oidc", "digest": {"gitCommit": commit}}],
        },
        "runDetails": {
            "builder": {
                "id": f"https://github.com/gotthboard/gotth-oidc/blob/{commit}/docs/release-build-type-v1.md#local-builder",
                "version": {"scripts/build-release-candidate.sh": script_sha},
            },
        },
    },
}
pathlib.Path(output).write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n")
PY

(
  cd "$output"
  sha256sum "$stem-source.tar.gz" "$stem.spdx.json" "$stem.LICENSE-EVIDENCE.txt" "$stem.provenance.json" >"$(basename "$checksums")"
  sha256sum -c "$(basename "$checksums")"
)
printf '%s\n' "$commit" >"$output/CANDIDATE_COMMIT"
printf 'release candidate built at %s for %s\n' "$output" "$commit"
