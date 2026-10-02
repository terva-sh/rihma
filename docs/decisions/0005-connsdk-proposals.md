# 0005: rihma ships on connsdk workarounds and files the proposals as drafts

Status: accepted. Date: 2026-09-30.

Origin: TKT-01M3T4DY9T7MJMQ6JGW8ZZ1PWX — Decide: who files the connsdk
proposals, and does rihma wait. Drew decided; handoff §10 question 4.

## Context

connsdk falls short of what the Rust connector does in three places
(handoff §6), each with a workaround in rihma:

| Gap | Workaround |
|---|---|
| `Serve` always advertises `protocol_min: 1` | reject `Session.Protocol < 2` in `NewTransport` |
| a transport cannot emit `warn` frames | log to stderr, which the host captures |
| `connsdk.Main` has no custom verbs | dispatch `verify` in `main` before `connsdk.Main` |

The warn gap has a real cost: unable-to-decrypt bursts, sync trouble,
and oversized attachments reach the host's log rather than the operator.
The other two cost almost nothing.

## Decision

rihma does not wait for terva. It ships on the workarounds.

The agent working TKT-01M3T4DXJQ6XZMD9W2Q7XXEVJE (Write
docs/connsdk-proposals.md for the three connsdk gaps) files one draft
ticket per proposal in terva's own store, each referencing
`docs/connsdk-proposals.md` in this repository. Drew promotes them in
terva when ready.

When a terva release ships a proposal, the rihma change that bumps the
terva pin removes the matching workaround in the same change and says
so in the CHANGELOG.

## Alternatives

- Wait for terva: ties rihma's phases to terva's release timing for no
  functional gain, since every workaround is cheap enough to ship.
- Drew files them by hand: works, but leaves the filing as a step
  outside the ticket that produces the proposals, where it is easy to
  forget.

## Consequences

The proposals ticket gains an acceptance criterion for the terva
filing. Filing drafts commits terva to nothing; they sit in terva's
draft backlog until promoted. Each workaround stays in rihma, with its
proposal named beside it in the code, until the matching terva release.
