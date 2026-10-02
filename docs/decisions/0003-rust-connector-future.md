# 0003: Freeze terva-conn-matrix now, archive it after graduation

Status: accepted. Date: 2026-09-30.

Origin: TKT-01M3T4DXZKXPG4HAV416F4CP1D — Decide: terva-conn-matrix's
future after parity. Drew decided; handoff §10 question 2.

## Context

terva-conn-matrix, the Rust connector, is rihma's specification and
test oracle while rihma is built. It carries a second toolchain (Rust
1.93+), a second SDK (`terva-sdk-rust`) that re-implements the connproto
wire and must track every protocol change by hand, and an exact
`matrix-sdk =0.18.0` pin. Removing those costs is why rihma exists.
[0002](0002-manifest-name.md) keeps the two connectors under separate
names, so any outcome here is possible.

## Decision

Freeze terva-conn-matrix now: security and breakage fixes only, no new
features. It stays the conformance oracle, and the live scenarios are
run against both connectors with frame transcripts compared, while rihma
works through P0 to P8.

Archive it once rihma graduates, meaning P8's operator dogfood from
`testing/DOGFOOD.md` passes against a real homeserver.

## Alternatives

- Keep it as a long-term oracle: parity diffs stay available for future
  features, but the Rust toolchain, `terva-sdk-rust`, and a matrix-sdk
  pin that ages in place remain costs indefinitely. That keeps the
  problem rihma was built to remove.
- Maintain both: every protocol change lands twice, which is the cost
  the handoff names as the reason for rihma.
- Archive immediately: removes the costs soonest, but loses the oracle
  during the phase when it is most useful.

## Consequences

Work on terva-conn-matrix itself, such as a freeze notice, a deprecation
note pointing at rihma's migration steps, and the archive, is tracked in
terva-conn-matrix's own ticket store, not here. Archiving changes a
remote repository's settings, so it needs a ticket there that authorizes
it. Once it is archived, `terva-sdk-rust`'s connector crates
(`terva-connproto`, `terva-connsdk`) lose their only known consumer; the
extension side stays in use by terva-ext-index. What happens to the
connector crates is an organization question, filed in meta as
TKT-01M3T9H3BS17793B96ARW7WZAA.

Correction, 2026-09-30: this section first said `terva-sdk-rust` as a
whole loses its only consumer, which was wrong.
