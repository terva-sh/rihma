# Experimental Sliding Sync

Classic crypto-aware `Client.Sync` remains the default. Applications can opt
into a bounded, durable Sliding Sync owner using the server-native experimental
Synapse dialect tested on Synapse **1.162.0**. The connector still uses classic
Sync; this option is intended for library applications.

```go
opts.SyncPolicy = rihma.SyncPolicyFullClient
opts.SlidingSync = &rihma.SlidingSyncOptions{
    Dialect: rihma.SlidingSyncSynapseExperimental,
    Lists: map[string]rihma.SlidingSyncList{
        "recent": {
            Ranges: []rihma.SlidingSyncRange{{0, 19}},
            TimelineLimit: 20,
        },
    },
}
// Open with these options, attach handlers, and call Sync(ctx).
// Cancel ctx and wait for Sync to return before Close or reopening.
```

`Open` copies the configuration. Change windows or explicit room subscriptions
by stopping, closing and reopening with new options. Each subscription maps a
room ID to a timeline limit. Lists are server sorted; ranges are inclusive.
Bounds are 16 lists, 16 ranges per list, indices 0–9999, 256 subscriptions and
100 timeline events per room. A selection must include a list or subscription.
An invalid selection fails before storage or network access.

## Explicit dialect

The pinned mautrix-go v0.31.0 has no dedicated Sliding Sync request/response
API. rihma uses its authenticated generic HTTP through a narrow adapter,
without copying an SDK. The server must advertise
`org.matrix.simplified_msc3575: true` in `/versions` and accept
`/_matrix/client/unstable/org.matrix.simplified_msc3575/sync`.

The [MSC4186 proposal](https://github.com/matrix-org/matrix-spec-proposals/blob/ffc54bc05c827edfb9791cfd7c154837c8487204/proposals/4186-simplified-sliding-sync.md)
was inspected at revision `ffc54bc05c827edfb9791cfd7c154837c8487204`.
The flag and endpoint agree, but the schemas differ:

| Field | Supported Synapse experimental dialect | Pinned proposal |
| --- | --- | --- |
| Position and timeout | Query parameters | Request body |
| List window | `ranges`, array of ranges | `range`, one range |
| Required state | Array of type/state-key pairs | `include`, `exclude`, `lazy_members` |
| List result | `count` and `ops` with `SYNC` | Revised list representation |
| Room state/timeline | `required_state`, `timeline`, `num_live` | Revised metadata |

The selector implements this experimental contract, not current proposal
compatibility or the legacy MSC3575 proxy. It never silently changes transports.
Knock dispatch is unsupported by the pinned upstream syncer and is refused
explicitly rather than acknowledged without delivery.

## Ownership, recovery and journaling

Sliding Sync retains the state-directory owner lock, verification lifecycle,
backup uploader and optional managed crypto shutdown. There is one in-flight
request per connection. Use the `Sync` context to stop it; the embedded mautrix
`StopSync` method controls mautrix's classic loop. A cancelled exchange is
joined and its response discarded before another exchange starts.

A separate pure-Go SQLite `sliding.db`, with FULL synchronous commits, stores
one encrypted recovery record. AES-GCM authenticates its account/device/server/
dialect binding with a domain-separated key derived from the session pickle
key. The record includes the immutable configuration, connection ID, committed
view, membership, independent sliding and to-device cursors, and one pending
complete raw response. Neither cursor is written to the classic sync token slot.
Keep the session and both databases together; protect their backups as account
state. Responses are bounded at 8 MiB and the recovery record at 32 MiB. A bound
violation stops processing instead of dropping data or advancing a cursor.

Each response is validated completely without side effects, then staged durably
before application journaling or state/crypto side effects. Rejected room/list
contents never become a pending recovery response. After normal crypto initialization, a pending response replays locally before
capability discovery or another sliding request,
including when windows changed or the server no longer advertises the dialect.
Upstream crypto initialization still verifies device keys with the server; this
is not an offline crypto initialization API. `SlidingSyncJournal` receives a complete raw
`SlidingSyncBatch` with its dialect, configuration fingerprint and previous/next
cursor tuple. It cannot be combined with classic `SyncJournal`. Copy the raw
bytes you need and return only after your own durable commit; do not retain or
mutate the callback's raw buffer. Unknown wire fields survive capture.

Current state, list deltas and normal crypto/event dispatch follow capture.
Only after synchronous dispatch succeeds are the view and cursor tuple committed
together. Journal, dispatch or checkpoint failure stops the owner with the
pending response intact. Replay can repeat application and crypto side effects:
separate databases do not offer an exactly-once transaction. Applications own
idempotent histories, duplicate reconciliation, retention and ciphertext storage
for delayed-key retries. The internal recovery slot is not timeline storage.

Changed windows/subscriptions start a new connection and empty sliding position/
list view, retaining the to-device acknowledgement and cached room metadata.
`M_UNKNOWN_POS` does the same with bounded retry backoff. Authentication refusal
is fatal; transient transport/server failures retry from the committed tuple.
Other refusals return safe `ErrSlidingUnsupported`, `ErrSlidingProtocol` or
`ErrSlidingStore`; application and dispatch failures use `ErrSyncJournal` and
`ErrSyncDispatch`. Private error bodies are not exposed by this transport.

## State, lists and extensions

`SlidingSyncSnapshot()` returns a detached copy of the currently committed view,
or nil before the owner loads recovery state. It contains list counts, sparse
list positions and merged raw room metadata. An empty position is outside the
known window. Rooms leaving a window are not membership leaves. Initial room
metadata replaces the prior snapshot; deltas patch it. Timeline gaps, pagination
and unread metadata remain in the raw room view and journal. Neither raw view
nor journal payloads are safe to log.

All selected rooms request complete state, including membership and encryption,
without lazy-member inference. Current state is seeded before event handlers
can send encrypted replies. Historical timeline state cannot overwrite current
membership in the state store. Join, invite and leave/ban dispatch retain normal
room IDs and event classes; current leave state follows its timeline under the
leave source because the pinned syncer lacks leave `state_after` handling.
The journal preserves the original wire sections and ordering.

The adapter supplies to-device messages, device-list changes, one-time-key
counts and fallback-key types to the normal crypto pipeline. Global and room
account data, typing and receipts also reach ordinary handlers, including updates
without a room timeline. Lists must contain supported `SYNC` operations within
requested ranges. Missing required crypto inputs or malformed operations stop
before journaling/dispatch. A server may include a newly left room in a list
for the leave exchange; subsequent updates remove it. Membership, not list
presence, determines whether a room is joined.

## Verification

Hermetic tests cover encrypted recovery persistence and authentication, replay
before another sliding request, journal/dispatch/checkpoint failures, independent
cursors, classic cursor isolation, expired positions, changed configuration,
late-success cancellation, owner/verification shutdown, authoritative state,
list bounds and extension-only dispatch.

The `goolm e2e` tests require an explicitly disposable loopback fixture. On pinned
Synapse 1.162.0 they exercise two disposable devices using normal key exchange:
encrypted history/live/offline delivery, raw capture before decrypted events,
encrypted replies from a callback, restart with a server-refused connection,
changed windows, room-list reordering/count changes and invite/join/leave
membership. The older wire probe remains as independent dialect evidence.
The version used for this proof is pinned by digest:
`ghcr.io/element-hq/synapse@sha256:416549f758d394f9600a9e34b9e4d5fb4b763ec83ce86efe57304e362a3b20b5`.
Run against your owned fixture with `RIHMA_E2E_DISPOSABLE=1`,
`RIHMA_E2E_HS=http://127.0.0.1:PORT`, `CGO_ENABLED=0` and `-tags 'goolm e2e'`.
