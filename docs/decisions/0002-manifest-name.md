# 0002: rihma keeps its own manifest name

Status: accepted. Date: 2026-09-30.

Origin: TKT-01M3T4DXQQ7HSRDDCE8YDVK1A6 — Decide: manifest name at
graduation (rihma or matrix). Drew decided; handoff §10 question 1.

Number 0001 is reserved for the SQLite driver choice, which the handoff
names ahead of time.

## Context

The terva manifest name also selects the connector's state directory,
`$TERVA_HOME/connectors/<name>/`, which holds the connector's config and
crypto store alongside the host-owned `pairing.json` and `data/`.
During development rihma runs as `rihma` so it can sit beside the Rust
connector, terva-conn-matrix, which runs as `matrix`. The question was
whether rihma should take over `matrix` once it reaches parity.

## Decision

rihma keeps the manifest name `rihma` permanently. The two connectors
stay separate and can be installed side by side.

## Alternatives

- Take over `matrix`: a drop-in replacement, keeping the host's config
  entry and `pairing.json`. It lost because rihma would inherit a state
  directory holding a matrix-sdk crypto store it cannot read, and would
  have to detect and clear that store without touching host-owned files.
  It would also make the two connectors mutually exclusive, so rolling
  back means reinstalling. The drop-in gain is small: migration already
  needs a new device, fresh verification, and a new state directory,
  because the crypto store cannot be converted.

## Consequences

Migrating from terva-conn-matrix means enabling a different connector
name, and pairings made under `matrix` do not carry over. The README's
migration note must say so. Rollback is switching which connector is
enabled. The manifest, state directory, and `connsdk.StateDir("rihma")`
stay as they are, and `docs/naming.md` records `rihma` as final.
