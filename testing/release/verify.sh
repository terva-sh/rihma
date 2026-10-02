#!/usr/bin/env bash
# Checks a release archive the way an operator would use it: unpacked, with
# no Go toolchain on PATH, run.sh must run the bundled binary. The binary
# must be cgo-free and built with goolm, and its hello must name rihma at
# connector.json's version, which must equal WANT_VERSION when it is set
# (the release workflow passes the tag without its v).
#
#   testing/release/verify.sh dist/terva-rihma_<version>_linux_amd64.tar.gz
#
# Used by `just release-verify` and the release workflows; the CI
# container has no just, so both call this script.
set -euo pipefail

archive=${1:?usage: verify.sh ARCHIVE}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar -xzf "$archive" -C "$tmp"
dir=$tmp/rihma

for f in terva-rihma connector.json run.sh LICENSE README.md CHANGELOG.md; do
	[ -e "$dir/$f" ] || { echo "verify: $f is missing from $archive" >&2; exit 1; }
done
[ -x "$dir/run.sh" ] || { echo "verify: run.sh is not executable" >&2; exit 1; }

info=$(go version -m "$dir/terva-rihma")
grep -qE 'build\s+CGO_ENABLED=0' <<<"$info" || { echo "verify: the binary was built with cgo" >&2; exit 1; }
grep -qE 'build\s+-tags=.*goolm' <<<"$info" || { echo "verify: the binary was built without goolm" >&2; exit 1; }

version=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$dir/connector.json")
if [ -n "${WANT_VERSION:-}" ] && [ "$version" != "$WANT_VERSION" ]; then
	echo "verify: connector.json says $version, the tag says $WANT_VERSION" >&2
	exit 1
fi

# No Go on PATH: a run.sh that tried to build would fail here. stdin is
# closed, so the connector says hello and exits.
nogo=$tmp/bin
mkdir -p "$nogo"
for tool in bash dirname find mkdir; do ln -s "$(command -v "$tool")" "$nogo/$tool"; done
hello=$(cd "$tmp" && env -i HOME="$tmp" TERVA_HOME="$tmp/home" PATH="$nogo" "$dir/run.sh" run </dev/null 2>"$tmp/stderr" | head -n 1) || true
case "$hello" in
	*'"type":"hello"'*'"name":"rihma"'*'"version":"'"$version"'"'*) ;;
	*)
		echo "verify: run.sh did not say hello as rihma $version; got: $hello" >&2
		cat "$tmp/stderr" >&2
		exit 1
		;;
esac
echo "verify: $(basename "$archive") is rihma $version, cgo-free with goolm, and runs without Go"
