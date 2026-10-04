# Appservice bridge groundwork

An appservice bridge is a separate Matrix-side runtime, not another mode of
user-device `Client.Sync`. No public bridge runtime or external-network adapter
is implemented yet. `testing/appservice/receiver_test.go` proves the capture
boundary needed before events can be acknowledged safely.

## Dependency evidence and reuse

Pinned mautrix-go v0.31.0 provides appservice registration, constant-time
homeserver-token validation, transaction types, intent APIs and bridgev2.
An isolated dependency probe built `appservice`, `bridgev2` and
`bridgev2/matrix` with `CGO_ENABLED=0 -tags goolm`. Their combined complete
359-package graph contained no enabled cgo files and no `mattn/go-sqlite3`.
This proves the pinned Matrix-side framework builds; a future network adapter
and media/database choices require their own complete graph check.

Reuse upstream registration, auth, intents and event types. Import rather than
copy MPL implementation files. Only appservice types/auth are imported by the
hermetic prototype; the library and connector do not import bridgev2.
The prototype uses the existing pure-Go SQLite dependency. Its appservice
import also requires the upstream pure-Go websocket module checksum.

The stock `AppService.PutTransaction` reads the body without a size bound,
uses a background context, dispatches to in-memory channels and marks an
in-memory transaction cache before returning success. These are not durable
capture receipts. A wrapper needs to own the transaction route and journal
before replaying; returning success from upstream dispatch alone cannot prove
crash recovery. Some crypto update channels can drop on saturation, so E2EE
also requires an explicit lossless replay/backpressure path.

## Registration, credentials and namespaces

Inject separate `as_token` (outbound homeserver client) and `hs_token` (inbound
transaction authentication) from the operator's protected registration source.
Never include registration contents, authorization headers, event payloads or
private SQL errors in logs. Use IDs/kinds/counts and safe error categories.
Do not reuse a user's login/session or treat an appservice token as a normal
device token. Serve on an operator-selected protected listener with explicit
read/header/body/idle timeouts; terminate TLS or use a protected local socket.

Validate narrow anchored namespaces before startup: e.g. a configured ghost
prefix on `example.org`, with separately scoped aliases and rooms. Reserve only
identities the service owns. Validate every outbound masqueraded user against
the configured namespace, including restored records; query endpoints must
return only registered/eligible identities. Inbound events legitimately include
ordinary users outside the ghost namespace, so sender matching alone is not
an inbound authorization filter. Homeserver authentication and room/adapter
policy are separate boundaries.

## Receipt, replay and shutdown contract

Key receipts by stable registration/service identity and opaque transaction ID.
Bound body bytes, ID length, parsed event count and total outstanding journal
bytes; refuse overload with a retryable error before acknowledgement. Preserve
the entire raw body, including unrecognized extensions, in protected storage.
Commit payload and receipt in one durable transaction before returning `200 {}`.
An authenticated retry of the same payload receives the same receipt after
restart. The prototype rejects reuse of an ID with different raw bytes; a
production policy must specify canonical equivalence or immutable raw identity.

The test-only receiver bounds bodies at 4 KiB and IDs at 128 bytes, uses the
upstream constant-time bearer check and transaction schema, and commits a raw
payload/receipt to modernc SQLite with `synchronous=FULL`. Tests cover missing/
wrong auth, malformed/trailing/null JSON, null timeline events, oversize bodies,
pre-cancelled requests, successful raw capture, duplicate/collision receipts,
closed-store failure and reopening the database before a duplicate retry.
Synthetic credentials exist only in memory and captured contents are not
printed. This is not a production validator, server or quota manager.

A lost HTTP acknowledgement after commit is expected: the homeserver retries
and finds the receipt. A request cancellation that races commit has the same
ambiguity; never delete a committed row because the client disconnected.
Storage failure gets a safe retryable status, not success. A separate bounded
worker consumes committed rows and persists progress; retries must deduplicate
by event and operation IDs, including stable outbound Matrix transaction IDs.
The external network needs its own idempotency/reconciliation contract because
the inbox transaction cannot atomically commit a remote send.

Stop admission, finish or cancel and join HTTP handlers, drain/persist worker
progress, stop crypto/network workers, then close stores. Keep receipts until
the homeserver retry horizon and application replay requirements permit
compaction. Retention and quota cannot discard unprocessed rows. A production
runtime needs explicit concurrency, database permissions/encryption, migration,
replay poisoning and overload tests beyond this proof.

## What complete bridging still requires

Implement the reusable durable runtime first. Network-specific adapters then
define authentication, remote identity mapping, portals/ghosts, messages,
edits/deletes/reactions/media, retry policy and ordering, without coupling the
root library to terva connector policy. Choosing the first external network is
a later product decision; this Matrix-side proof does not require that choice.

Encrypted bridging additionally needs supported appservice-device registration
and server extensions, per-device stores, lossless to-device/device-list/OTK/
fallback-key processing, membership tracking, key sharing/trust, recovery and
joined shutdown. Prove encrypted delivery against disposable Synapse with a
real registration, retries and restart before advertising E2EE bridge support.
No bridge connsdk feature is declared by this groundwork.
