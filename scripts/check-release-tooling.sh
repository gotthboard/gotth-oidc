#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
builder="$root/scripts/build-release-candidate.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
sh -n "$builder"

for invalid in v1x.0.0 v1.0.0evil v1.0.0/extra 1.0.0 v01.0.0 v1.0.0-01 v1.0.0-rc.01 v1.0.0+meta v1.0.0+incompatible v2.0.0 v999.0.0; do
  if "$builder" "$invalid" "$tmp/invalid" HEAD >/dev/null 2>&1; then
    echo "release builder accepted invalid version: $invalid" >&2
    exit 1
  fi
done

if "$builder" v1.0.0 "$tmp/bad-ref" refs/heads/does-not-exist >/dev/null 2>&1; then
  echo "release builder accepted an invalid ref" >&2
  exit 1
fi
if [ -e "$tmp/bad-ref" ]; then
  echo "release builder created output before validating its ref" >&2
  exit 1
fi

probe="$root/.release-output-probe"
if [ -e "$probe" ] || [ -L "$probe" ]; then
  echo "release output probe path already exists: $probe" >&2
  exit 1
fi
if output=$("$builder" v1.0.0 "$probe" HEAD 2>&1); then
  echo "release builder accepted an output directory inside the repository" >&2
  exit 1
fi
case "$output" in
  *"OUTPUT_DIR must be outside the source repository"*) ;;
  *) echo "release builder rejected in-tree output for the wrong reason: $output" >&2; exit 1 ;;
esac
if [ -e "$probe" ] || [ -L "$probe" ]; then
  echo "release builder mutated the repository before rejecting its output path" >&2
  exit 1
fi

mkdir "$tmp/existing"
printf 'preserve me\n' >"$tmp/existing/stale"
if "$builder" v1.0.0 "$tmp/existing" HEAD >/dev/null 2>&1; then
  echo "release builder accepted an existing output directory" >&2
  exit 1
fi
test "$(find "$tmp/existing" -mindepth 1 -maxdepth 1 -printf '%f\n')" = stale
ln -s existing "$tmp/symlink"
if "$builder" v1.0.0 "$tmp/symlink" HEAD >/dev/null 2>&1; then
  echo "release builder accepted a symlink output path" >&2
  exit 1
fi

"$builder" v1.0.0 "$tmp/release" HEAD >/dev/null
(
  cd "$tmp/release"
  sha256sum -c SHA256SUMS >/dev/null
)
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=tar.umask GIT_CONFIG_VALUE_0=0077 \
  "$builder" v1.0.0 "$tmp/release-umask" HEAD >/dev/null
if ! diff -qr "$tmp/release" "$tmp/release-umask" >/dev/null; then
  echo "release output inherited tar.umask" >&2
  exit 1
fi
printf 'README.md export-ignore\n' >"$tmp/global-attributes"
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.attributesFile GIT_CONFIG_VALUE_0="$tmp/global-attributes" \
  "$builder" v1.0.0 "$tmp/release-global-attributes" HEAD >/dev/null
if ! diff -qr "$tmp/release" "$tmp/release-global-attributes" >/dev/null; then
  echo "release output inherited core.attributesFile" >&2
  exit 1
fi
git clone --quiet --shared "$root" "$tmp/poisoned-repo"
git -C "$tmp/poisoned-repo" checkout --quiet --detach "$(git -C "$root" rev-parse HEAD)"
poisoned_git_dir=$(git -C "$tmp/poisoned-repo" rev-parse --absolute-git-dir)
printf 'README.md export-ignore\n' >"$poisoned_git_dir/info/attributes"
"$tmp/poisoned-repo/scripts/build-release-candidate.sh" v1.0.0 "$tmp/release-info-attributes" HEAD >/dev/null
if ! diff -qr "$tmp/release" "$tmp/release-info-attributes" >/dev/null; then
  echo "release output inherited info/attributes" >&2
  exit 1
fi
git clone --quiet --shared "$root" "$tmp/replaced-repo"
git -C "$tmp/replaced-repo" checkout --quiet --detach "$(git -C "$root" rev-parse HEAD)"
git -C "$tmp/replaced-repo" config user.name "release-tooling test"
git -C "$tmp/replaced-repo" config user.email "release-tooling@example.invalid"
sed -i 's|^module .*|module example.invalid/replaced|' "$tmp/replaced-repo/go.mod"
git -C "$tmp/replaced-repo" add go.mod
git -C "$tmp/replaced-repo" commit --quiet -m "poison replacement"
replacement=$(git -C "$tmp/replaced-repo" rev-parse HEAD)
candidate=$(git -C "$root" rev-parse HEAD)
git -C "$tmp/replaced-repo" replace "$candidate" "$replacement"
"$tmp/replaced-repo/scripts/build-release-candidate.sh" v1.0.0 "$tmp/release-replacement-ref" "$candidate" >/dev/null
if ! diff -qr "$tmp/release" "$tmp/release-replacement-ref" >/dev/null; then
  echo "release output honored a Git replacement ref" >&2
  exit 1
fi
before=$(find "$tmp/release" -type f -print0 | sort -z | xargs -0 sha256sum)
if "$builder" v1.0.0 "$tmp/release" HEAD >/dev/null 2>&1; then
  echo "release builder overwrote an existing release set" >&2
  exit 1
fi
after=$(find "$tmp/release" -type f -print0 | sort -z | xargs -0 sha256sum)
test "$before" = "$after"
if find "$tmp" -mindepth 1 -maxdepth 1 -name '.gotth-oidc-release.*' | grep -q .; then
  echo "release builder left a staging directory behind" >&2
  exit 1
fi

if grep -R -n -E 'Error[(][)][[:space:]]*(==|!=)' "$root/pkg/oidc" --include='*_test.go'; then
  echo "test makes diagnostic error text contractual" >&2
  exit 1
fi
