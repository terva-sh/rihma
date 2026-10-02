# rihma dev tasks. `just` lists them.
#
# `just ci` runs the same steps as .forgejo/workflows/ci.yml, the gate for
# internal pull requests. That workflow keeps its commands inline because its
# container does not install just, so change both together.

set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Everything is built and tested without cgo and on the pure-Go Olm backend.
# A build without the tag fails on purpose; see guard_nogoolm.go.
export CGO_ENABLED := "0"
tags := "-tags goolm"

# Every GOOS/GOARCH pair that must build without cgo.
targets := "linux/amd64 linux/arm64 darwin/arm64 windows/amd64"

default:
    @just --list

# Build every package for this platform.
build:
    go build {{tags}} ./...

# Run the tests.
test:
    go test {{tags}} ./...
    go test -tags 'goolm dogfood' ./testing/dogfood/

# go vet, including the e2e-tagged live tests, which CI cannot run.
vet:
    go vet {{tags}} ./...
    go vet -tags 'goolm e2e' ./...
    go vet -tags 'goolm dogfood e2e' ./testing/dogfood/

# Rewrite sources with gofmt.
fmt:
    gofmt -w .

# Fail if gofmt would change a file.
fmt-check:
    @diff=$(gofmt -l .); if [ -n "$diff" ]; then echo "gofmt issues in:"; echo "$diff"; exit 1; fi

# Fail if mattn/go-sqlite3 is linked. Without cgo it compiles to a stub that
# fails only at runtime, so a build passing proves nothing about it.
nocgo-check:
    @if go list -deps {{tags}} ./... | grep -qx github.com/mattn/go-sqlite3; then \
        echo "mattn/go-sqlite3 is in the cgo-free build; open the store on the pure-Go driver instead"; \
        go mod why -m github.com/mattn/go-sqlite3; exit 1; \
    fi

# vet, gofmt, and the cgo leak check.
lint: vet fmt-check nocgo-check

# Build every package for every target.
cross:
    for t in {{targets}}; do \
        echo "== $t"; \
        GOOS=${t%/*} GOARCH=${t#*/} go build {{tags}} ./...; \
    done

# Validate the ticket store without writing anything.
tickets:
    git ticket check --fix --dry-run --strict

# Everything CI runs.
ci: lint test cross release-snapshot tickets release-tools

# Validate .goreleaser.yaml without building anything. Needs goreleaser.
release-check:
    goreleaser check

# Build every release archive into dist/ with no tag and no publish, then
# check the linux/amd64 one runs without Go. dist/ is gitignored.
release-snapshot:
    goreleaser release --snapshot --clean --skip=validate
    just release-verify

# Check the built linux/amd64 archive: contents, cgo-free with goolm, and
# run.sh saying hello with no Go toolchain on PATH.
release-verify:
    testing/release/verify.sh dist/terva-rihma_*_linux_amd64.tar.gz

# Start the throwaway local Synapse and a preconfigured Element Web, on
# 127.0.0.1:18108 and :18109 (SYNAPSE_PORT, ELEMENT_PORT). Uses podman, or
# docker via CONTAINER_ENGINE. Never a real account or homeserver.
synapse:
    testing/synapse/harness.sh up

# Stop the throwaway Synapse; its state is kept for the next start.
synapse-down:
    testing/synapse/harness.sh down

# Stop the throwaway Synapse and wipe its state, for a factory-fresh start.
synapse-clean:
    testing/synapse/harness.sh clean

# Show whether the throwaway Synapse is running and healthy.
synapse-status:
    testing/synapse/harness.sh status

# The live suite against the throwaway Synapse. Builds the test binary,
# shows it was built without cgo and with goolm, then runs every TestE2E.
e2e: synapse
    mkdir -p bin
    go test -c -tags 'goolm e2e' -o bin/e2e.test .
    go version -m bin/e2e.test | grep -E 'build\s+(CGO_ENABLED|-tags)='
    RIHMA_E2E_HS="http://127.0.0.1:${SYNAPSE_PORT:-18108}" bin/e2e.test -test.run TestE2E -test.v
    # The connector under a fake host; run.sh builds bin/terva-rihma.
    RIHMA_E2E_HS="http://127.0.0.1:${SYNAPSE_PORT:-18108}" go test -tags 'goolm e2e' -count=1 -timeout 10m -v ./e2e/
    # Real-host warning checks, with RIHMA_E2E_TERVA pointing at terva >=0.139.7.
    RIHMA_E2E_HS="http://127.0.0.1:${SYNAPSE_PORT:-18108}" go test -tags 'goolm dogfood e2e' -count=1 -timeout 10m -v ./testing/dogfood/
    go version -m bin/terva-rihma | grep -E 'build\s+(CGO_ENABLED|-tags)='

# The public release tooling's offline tests, and the leak check over the
# public tree HEAD would publish. Both must pass. release/README.md is
# the procedure.
release-tools:
    cd release && python3 -m unittest -q
    python3 release/publish.py candidate HEAD
