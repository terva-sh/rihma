# 0001: modernc.org/sqlite is the SQLite driver

Status: accepted. Date: 2026-09-30.

Origin: TKT-01M3T4DVMZ2YXBR0WWP0C7T9M4 — P0: choose the pure-Go SQLite
driver (ADR 0001). Handoff §3 decision 4 required a pure-Go driver and
left the choice to evidence.

## Context

mautrix-go's crypto and state stores run on `go.mau.fi/util/dbutil`.
Given a path string, `cryptohelper.NewCryptoHelper` opens the
`sqlite3-fk-wal` driver, which `dbutil/litestream` registers only under
`//go:build cgo` on top of `mattn/go-sqlite3`. A cgo-free build must
open the database itself and pass the `*dbutil.Database`. The candidates
were modernc.org/sqlite (C translated to Go) and
github.com/ncruces/go-sqlite3 (SQLite compiled to Wasm, then to Go).

The cgo driver sets four pragmas on every connection: `foreign_keys =
ON`, `journal_mode = WAL`, `synchronous = NORMAL`, and `busy_timeout =
5000`. The path-string constructor adds `_txlock=immediate`. The handoff
listed all of these except `synchronous`.

## Evidence

Measured on 2026-09-30 with mautrix v0.31.0, `CGO_ENABLED=0 -tags goolm`,
modernc v1.60.1, and ncruces v0.35.6, in throwaway scratch modules.

| | modernc | ncruces | mattn (cgo baseline) |
|---|---|---|---|
| mautrix `crypto` and `crypto/verificationhelper` tests | 102 pass | 102 pass, after the DSN change below | 102 pass |
| mockserver SQL path (`machine_bench_test`, `MemoryStore=false`) | pass, 2.95 s/op | pass, 2.87 s/op | pass, 2.60 s/op |
| All four pragmas on four held pooled connections | yes | yes | |
| Crypto and state store upgrades on a file | v21, v11 | v21, v11 | |
| 800 concurrent read-then-write transactions, immediate | 0 failed | 0 failed | |
| The same without `_txlock=immediate` | 531 failed | 561 failed | |
| Cross-build linux/amd64, linux/arm64, darwin/arm64, windows/amd64 | all build | all build | |
| Size over goolm alone (5.9 MB, linux/amd64, stripped) | +3.8 MB | +4.8 MB | |
| Cold build of the probe | 14 s | 13 s | |
| Modules in the probe's graph | 60 | 50 | |
| Versioning | v1 | v0 | |

The mautrix tests were run by patching a scratch copy of mautrix to open
each candidate in place of mattn. For the mockserver path, a wrapper
registered the name `sqlite3-fk-wal` on the candidate and appended the
pragmas to each DSN.

ncruces first failed `TestStoreDevices` and `TestTrustOtherDevice` with
devices returned under the wrong signing keys. The cause was not data
corruption. mautrix's tests open `:memory:?_busy_timeout=5000`, which
mattn and modernc read as an in-memory database with a parameter.
ncruces parses parameters only after a `file:` prefix, so it created a
file named `:memory:?_busy_timeout=5000` on disk, every test shared it,
and mautrix's upsert kept the stale signing keys. Using
`file::memory:?_pragma=busy_timeout(5000)` made all 102 pass.

## Decision

Use modernc.org/sqlite. `store.go` opens it with the four pragmas and
immediate transactions, and hands mautrix a `*dbutil.Database`.

## Alternatives

- ncruces/go-sqlite3: equal on every functional test. It lost because
  it reads connection strings differently from mattn, and does so
  silently, which is the convention mautrix's own code and tests are
  written in. A mautrix-style DSN turned into a stray file and wrong
  data rather than an error. It is also pre-1.0, and 1 MB larger. Its
  smaller module graph and target-independent translation did not
  outweigh that: all four of rihma's targets build with modernc.
- mattn/go-sqlite3: needs cgo, which decision 2 rules out.

## Consequences

- **Build the DSN as a URL.** With either driver, `"file:" + path + "?"
  + params` breaks on a path containing `?` or `#`: the database opens
  somewhere else, silently, without the pragmas. A `%` in the path fails
  outright. `storeDSN` builds a `file:` URL from the absolute, slashed
  path, and `TestStorePathCharacters` covers each case. The Windows form
  (`/C:/...`) is built but has not been run on Windows.
- **Hermetic tests with mockserver.** mockserver uses in-memory stores by
  default and needs no SQLite. A test that sets `MemoryStore = false`
  needs `sqlite3-fk-wal` registered. A `_test.go` wrapper around the
  modernc driver that appends the pragmas does that, and was proven
  against mautrix's own benchmark. No upstream change is required. Write
  the shim with its first caller.
- **Nothing links mattn.** `just nocgo-check` and CI fail if
  `mattn/go-sqlite3` enters the cgo-free build graph. mautrix's own test
  files import it, but rihma's test graph does not include them.
