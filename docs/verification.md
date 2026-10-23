# Verification during sync

`Client.EnableSAS()` opts into to-device emoji verification before the
client's first `Sync`: with this account's other devices in both
directions, and outgoing with another user. `Client.EnableSASWith(opts)`
also admits requests from the users listed in `SASOptions.Peers` (see
[accepting another user's request](#accepting-another-users-request)),
and with `SASOptions.InRoom` runs verification in a room (see [in-room
verification](#in-room-verification)). Neither performs network I/O.
The returned `SASController` shares the existing crypto-aware syncer; it never
starts another sync loop. Clients that do not opt in keep bot behavior.

```go
controller, err := client.EnableSAS()
// Handle err, then start the account's one client.Sync(ctx) owner.
// One adapter consumes Changed(), reads Snapshot(), and fans out view updates.
// To request verification from the account's other devices during Sync:
transactionID, err := controller.Start(commandContext)
// Retain transactionID for later commands; the first eligible reply selects the peer.
// For a requested attempt:
err = controller.Accept(commandContext, snapshot.TransactionID)
// For showing_sas, after comparing all seven emoji on the other device:
err = controller.Confirm(commandContext, snapshot.TransactionID, true)
// Or reject with Confirm(..., false), or Cancel(...).
```

The states are idle, sent, requested, accepted, showing_sas, confirmed, done,
cancelled, failed and stopped. Confirmed means local agreement was sent;
only done means the protocol completed. Query `Client.Verification` to refresh
the device's cross-signing standing after completion. Emoji are cleared after
confirmation/cancellation. Snapshot slices are independent copies. Changed is
a bounded coalescing wakeup for one adapter, not a history stream or a channel
for multiple views to compete over. Snapshot revisions are local to the
controller and do not survive restart.

`Start` returns a transaction ID and publishes sent while waiting for acceptance.
It requests all cached account devices except this device, fetching devices when
the cache is empty. It fails with `ErrSASOperation` if no other device is available.
The first eligible ready event selects the peer and starts SAS automatically;
remaining requested devices receive cancellation. Incoming requests publish
requested and require `Accept`. Device-specific targeting is not exposed.

Commands after `Start` carry the current transaction ID; commands in the wrong state
return `ErrSASStale`. Commands before sync starts or after it stops return
`ErrSASUnavailable`. Backend errors are reduced to `ErrSASOperation`; remote
cancellation reasons never enter snapshots or errors. Caller cancellation may
occur after a request was sent; read the snapshot instead of assuming rollback.
The controller suppresses helper context logging, including ephemeral SAS data.

Only one attempt is active. Busy, same-device, unlisted-user, oversized,
old and excessively future-dated requests are ignored, and so are in-room
requests unless the controller was enabled with `InRoom`. IDs are remembered for the whole controller lifetime: a helper timer may be
delayed beyond its deadline, so elapsed time cannot make ID reuse safe. At most
64 incoming and outgoing attempts are admitted per controller/Sync, bounding
remembered IDs and helper timers. Failed outgoing sends consume the same budget,
because upstream starts expiration before sending. Exhausted `Start` calls return
`ErrSASLimit`. Open a fresh account runtime to reset that budget.
Normal requests expire ten minutes after their request timestamp. Repeated
attempts with fresh IDs are supported during one Sync. Callback overflow fails
and dismisses the current local attempt rather than blocking the syncer.

Sync cancellation quiesces handlers and commands, revokes in-memory
transactions and joins any helper expiration already in flight before Sync
returns. Mautrix's bounded sleeping expiration goroutines can remain until
expiry, but afterwards find no transaction and perform no network or crypto
storage operations. Shutdown can wait for an already-running expiration request;
it never closes stores underneath that request. No pending verification is
restored on restart. Open a fresh Client/controller for the next account runtime.
Local shutdown need not notify the peer; its protocol timeout still applies.

`AwaitSAS(ctx, confirm)` remains the bot convenience API: it auto-accepts one
incoming same-account attempt, calls confirm on its own goroutine, and owns its
own Sync. It continues to reject an already-syncing state directory. Its
confirm callback may block and must arrange its own cancellation if needed.

## Verifying another user

`StartUser(ctx, user)` asks every device `user` publishes to verify this
account, over to-device messages. Naming the user is the consent. Before
it sends anything it checks that this device holds the account's
cross-signing keys and the server still publishes them
(`ErrNoCrossSigningKeys`), that the user publishes a master key
(`ErrNoUserIdentity`, after refreshing their devices), and that none of
their devices has this device's id (`ErrPeerDeviceIDConflict`). This
account's own id returns `ErrOwnUser`. A failed check sends nothing and
leaves the snapshot as it was. Otherwise the attempt runs like `Start`;
snapshots carry `OtherUser`, the user named.

Every follow-up must come from the attempt's user, so neither a third
party nor this account's other devices can steer it. When both people
have confirmed, rihma signs the user's master key with this account's
user-signing key, records it for `Options.OnIdentityChange` as
`SignUserIdentity` does, and publishes done with `MasterKey` set. A peer
whose MAC named no master key ends failed with reason `unsigned`, and a
master key that changed on the server before done ends failed with
`identity_changed`. In both cases the peer's device stays verified,
because a published signature cannot be taken back.

`Client.VerifyUser(ctx, user, confirm)` is the one-shot form for a bot
that is not running, the outgoing counterpart of `AwaitSAS`. It runs its
own Sync, fails with `ErrSyncInProgress` while anything else syncs on the
state directory, sends the request with `StartUser`, calls confirm with
the emoji on its own goroutine, and returns the user's master key once it
is signed and recorded. It never confirms unless confirm returns true,
never accepts an incoming request, and returns `ErrSASMismatch`,
`ErrSASCancelled` (the user cancelled, or the request timed out),
`ErrSASUnsigned` or a wrapped `ErrMasterKeyMismatch`. Element answers the
request only from a user whose devices it already tracks, so the bot and
the user must share an encrypted room, such as their DM, first. Compare the emoji
over a channel the homeserver cannot change, such as the bot's terminal;
see [verifying another user](cross-user-verification.md) for why.
QR is not exposed by this controller. SSO/OIDC login is unrelated and
remains outside this feature.

## Accepting another user's request

A bot that should let its owner start the verification lists the owner
when it enables the controller:

```go
controller, err := client.EnableSASWith(rihma.SASOptions{Peers: []id.UserID{owner}})
```

A to-device request from a listed user then publishes requested, with
`OtherUser` set, under the same bounds as a request from this account's
own devices: one attempt at a time, the same age, size and reuse limits,
and the same 64-attempt budget. A request from any other user is
dropped before mautrix sees it, with no reply, so a stranger cannot make
the bot send anything. Peers compare as a set. A second call with
different options returns `ErrSASUnavailable`, and so do `EnableSAS`,
`AwaitSAS` and `VerifyUser` on a client whose controller lists peers,
because `AwaitSAS` accepts whatever request arrives. A peer equal to
this account returns `ErrOwnUser`, and one that is not a user id
`ErrInvalidSASPeer`. `SASOptions.InRoom` is part of the options too.

`Accept` on a listed user's request makes the checks `StartUser` makes
before replying: `ErrNoCrossSigningKeys` and `ErrNoUserIdentity`. A failed
check sends the user an `m.user` cancellation, ends the attempt
cancelled, and returns the error; nothing else was sent. A caller context
that ends during the check returns its error and leaves the request
pending. The rest of the attempt, including the held MAC, the signature
on the user's master key and the `unsigned` and `identity_changed`
reasons, is as for `StartUser`.

Element verifies another user with an in-room request in their DM, so a
bot that Element users verify needs `InRoom` as well.

mautrix v0.31.0 ignores a request from a device whose id equals this
device's, even when it belongs to another user, so a person verifying
from such a device sees no answer. Comparing the emoji in a chat the
homeserver relays trusts that homeserver; see [two ways to compare the
emoji](cross-user-verification.md#two-ways-to-compare-the-emoji).

## In-room verification

Element verifies another user in a room, normally their DM: the request
is an `m.room.message` with msgtype `m.key.verification.request`, and
each later step is a room event that references it. A controller enabled
with `InRoom` takes part in both directions:

```go
controller, err := client.EnableSASWith(rihma.SASOptions{Peers: []id.UserID{owner}, InRoom: true})
// The owner verifies the bot from Element: the request publishes
// requested with Room set, and Accept answers it as above.
// Or the bot asks:
transactionID, err := controller.StartInRoom(commandContext, dm, owner)
```

An in-room request is admitted when its sender is in `Peers`, it names
this account in `to`, it is in an encrypted room this account has joined,
and it was sent at most ten minutes ago and at most a minute in the
future. A follow-up is admitted only when it is in the attempt's room,
from the attempt's user, and references the attempt's request event.
Either may have arrived unencrypted: Element sends them that way even in
an encrypted DM, as the specification allows, and SAS rests on the MACs
and the emoji rather than on the transport. A peer's
ready is admitted only for a request this controller posted. Everything
else is dropped before mautrix sees it, as are to-device events naming an
in-room transaction. Each event the gate passes over is logged at debug
level with a fixed reason and no content. The bounds shared with
to-device requests apply: one attempt at a time across both routes, and
the same 64-attempt budget.

`StartInRoom(ctx, room, user)` posts the request in `room`, which must be
an encrypted room this account has joined (`ErrSASRoom` otherwise), and
needs `InRoom` (`ErrSASUnavailable`). It makes `StartUser`'s checks except
`ErrPeerDeviceIDConflict`, which concerns to-device requests only, and a
failed check sends nothing. The transaction id is the request event's id.
Snapshots carry `Room`. Cancellation, a mismatch and the timeout are sent
to the room, encrypted; completion is as for `StartUser`.

Two things in mautrix v0.31.0 are worked around. Its helper looks an
in-room follow-up up by the follow-up's own event id instead of the
request it references, so the gate hands it the event with the request's
id. Its `StartInRoomVerification` encrypts the request twice, so no client
can read it; rihma posts the request itself, encrypted once.

A test that needs a peer behaving like Element, which sends its in-room
verification events unencrypted, can use a second rihma client with
encryption switched off for sending. Only mautrix's `SendMessageEvent`
reads the embedded client's `Crypto` field, and the crypto machine keeps
receiving room keys and decrypting incoming events without it, so once
the peer has synced:

```go
// Test code only: from here on every event this client sends is
// plaintext, in every room, not just its verification events.
peer.Client.Crypto = nil
```

rihma offers no option for this, because a switch that sends plaintext
in an encrypted room has no use outside a test.

Comparing the emoji in the room trusts the homeserver; see [two ways to
compare the emoji](cross-user-verification.md#two-ways-to-compare-the-emoji).

Device trust and key recovery use the existing `Verification`,
`RestoreFromRecoveryKey` and `RestoreKeyBackup` operations. A missing identity is
`NoIdentity`; never create a replacement identity to bypass verification.
`CreateRecoveryKey` refuses an existing identity and `EnableKeyBackup` refuses
an existing backup. `ResetCrossSigningIdentity` replaces an identity only when
the person asks, typically after losing the recovery key; see
[identity reset](identity-reset.md). SAS success is not a claim that historical room keys are
available. After it, `RequestKeyBackup` asks the account's other verified
devices for the key backup key, and `RequestCrossSigningKeys` for the
cross-signing keys, which let this device verify the next one. If none
answers, the recovery key restores both instead. Recovery keys are
transient secret command input and must never enter UI snapshots or logs.
