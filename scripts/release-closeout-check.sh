#!/bin/sh
set -eu

repo=gotthboard/gotth-oidc
tag=v0.1.0
object_expected=0f357d90b4b64da9ef89f8796a766f284e86ba5e
commit_expected=4c22b248b2e7f03c28051aaf3105a0d769690f73
forgejo_remote=${GOTTH_FORGEJO_REMOTE:-origin}
test_mode=${CLOSEOUT_TEST_MODE:-0}
expected=${EXPECT_STATE:-incomplete}
github_api=${GITHUB_API_ROOT:-https://api.github.com}
github_web=${GITHUB_WEB_ROOT:-https://github.com}
archive=gotth-oidc-v0.1.0-source.tar.gz
archive_sha=7aa46b124ee71e7106fd7156c1ef3d8bdaf46ec9a0a4e4c4a1497e352e34b7a0
sums_sha=0cfad4dc9a7b83d7800d4a2709a48cb8ea2e11850a0a640a717b78fc0fb3e874
case "$expected" in incomplete|complete) ;; *) echo "EXPECT_STATE must be incomplete or complete" >&2; exit 2 ;; esac
if [ "$test_mode" != 1 ]; then [ "$github_api" = https://api.github.com ] && [ "$github_web" = https://github.com ] || { echo "noncanonical GitHub origin rejected" >&2; exit 1; }; fi
if forgejo_url=$(git remote get-url "$forgejo_remote" 2>/dev/null); then :; else forgejo_url=$forgejo_remote; fi
case "$forgejo_url" in forgejo:gotthboard/gotth-oidc.git|ssh://forgejo@git.dannyhunn.com:56087/gotthboard/gotth-oidc.git|https://git.dannyhunn.com/gotthboard/gotth-oidc.git) ;; *) echo "GOTTH_FORGEJO_REMOTE is not canonical Forgejo" >&2; exit 1 ;; esac
[ "$(git cat-file -t "refs/tags/$tag")" = tag ] || { echo "$tag is not annotated" >&2; exit 1; }
object=$(git rev-parse "refs/tags/$tag"); commit=$(git rev-parse "refs/tags/$tag^{}")
[ "$object" = "$object_expected" ] && [ "$commit" = "$commit_expected" ] || { echo "local tag identity mismatch" >&2; exit 1; }
for remote in "$forgejo_remote" "https://github.com/$repo.git"; do refs=$(git ls-remote "$remote" "refs/tags/$tag" "refs/tags/$tag^{}"); [ "$(printf '%s
' "$refs"|awk -v r="refs/tags/$tag" '$2==r{print $1}')" = "$object_expected" ] && [ "$(printf '%s
' "$refs"|awk -v r="refs/tags/$tag^{}" '$2==r{print $1}')" = "$commit_expected" ] || { echo "$remote tag identity mismatch" >&2; exit 1; }; done
root=$(mktemp -d); trap 'rm -rf "$root"' EXIT HUP INT TERM
body="$root/release.json"
code=$(curl -sS -o "$body" -w '%{http_code}' -H 'Accept: application/vnd.github+json' -H 'User-Agent: gotth-release-closeout' "$github_api/repos/$repo/releases/tags/$tag")
if [ "$expected" = incomplete ]; then [ "$code" = 404 ] || { echo "GitHub Release state changed: HTTP $code" >&2; exit 1; }; printf 'tag=%s object=%s commit=%s github_release=not_published draft_state=unknown closeout=blocked
' "$tag" "$object" "$commit"; exit 0; fi
[ "$code" = 200 ] || { echo "GitHub Release missing: HTTP $code" >&2; exit 1; }
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); names=[a.get("name") for a in d.get("assets",[])]; ok=d.get("tag_name")==sys.argv[2] and d.get("draft") is False and d.get("prerelease") is False and len(names)==2 and set(names)=={sys.argv[3],"SHA256SUMS"}; sys.exit(0 if ok else 1)' "$body" "$tag" "$archive"
archive_url=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print({a["name"]:a["browser_download_url"] for a in d["assets"]}[sys.argv[2]])' "$body" "$archive")
sums_url=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print({a["name"]:a["browser_download_url"] for a in d["assets"]}[sys.argv[2]])' "$body" SHA256SUMS)
case "$archive_url" in "$github_web/$repo/releases/download/$tag/$archive") ;; *) echo "unsafe archive URL" >&2; exit 1 ;; esac
case "$sums_url" in "$github_web/$repo/releases/download/$tag/SHA256SUMS") ;; *) echo "unsafe checksum URL" >&2; exit 1 ;; esac
curl -fsSL -o "$root/$archive" "$archive_url"; curl -fsSL -o "$root/SHA256SUMS" "$sums_url"
printf '%s  %s
' "$archive_sha" "$root/$archive"|sha256sum -c -; printf '%s  %s
' "$sums_sha" "$root/SHA256SUMS"|sha256sum -c -; (cd "$root" && sha256sum -c SHA256SUMS)
printf 'tag=%s object=%s commit=%s github_release=present prerelease=false assets=verified closeout=complete
' "$tag" "$object" "$commit"
