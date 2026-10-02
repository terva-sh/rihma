# 0004: When the library tags v1

Status: accepted. Date: 2026-09-30.

Origin: TKT-01M3T4DY4CKN4A18Q4Y0XPHHAK — Decide: when the library API
is stable enough for v1. Drew decided; handoff §10 question 3.

## Context

`terva.sh/rihma` is extracted from the connector's needs, and its only
planned consumer is `internal/connector`. It deliberately exposes
`*mautrix.Client` and mautrix types rather than wrapping them, so its
API surface inherits mautrix-go's, and mautrix-go is pre-1.0 and reworks
surfaces between minor releases.

## Decision

The library stays on v0 until both hold:

1. A second consumer outside `internal/connector` imports
   `terva.sh/rihma` for real work, such as an ops bot or a notification
   sender.
2. The root package has absorbed at least one mautrix-go minor-version
   upgrade with no breaking change to its own API.

When both hold, tagging v1 is a proposal to Drew, not an automatic step.
The connector's releases follow its manifest version and do not wait on
the library tag.

## Alternatives

- A second consumer alone (the handoff's default): shows which parts of
  the API are general, but not whether the API survives mautrix-go
  changes, which is its most likely source of breakage.
- At graduation, when P8 is done: simple, but freezes an API that only
  one caller has exercised.

## Consequences

Until v1, breaking changes to the root package are allowed but each one
gets a CHANGELOG entry. Each mautrix-go upgrade should record in its
ticket whether the root package's API changed, since that is the
evidence criterion 2 needs.
