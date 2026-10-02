#!/usr/bin/env bash
# terva's entry point for the rihma connector: connector.json's "exec".
#
# stdout is the protocol wire during `run`, so every byte of build output
# goes to stderr. A release archive ships a prebuilt ./terva-rihma next to
# this script; a checkout builds one into bin/ with Go, cgo-free, whenever
# a source file is newer than the binary.
set -euo pipefail
cd "$(dirname "$0")"

if [ -x ./terva-rihma ]; then
	exec ./terva-rihma "$@"
fi

bin=bin/terva-rihma
needs_build() {
	[ ! -x "$bin" ] && return 0
	[ -n "$(find . -path ./bin -prune -o \( -name '*.go' -o -name go.mod -o -name go.sum \) -newer "$bin" -print -quit)" ]
}

if needs_build; then
	if ! command -v go >/dev/null; then
		echo "terva-rihma: no prebuilt binary and no Go toolchain to build one" >&2
		exit 1
	fi
	mkdir -p bin
	CGO_ENABLED=0 go build -tags goolm -o "$bin" ./cmd/terva-rihma >&2
fi
exec "$bin" "$@"
