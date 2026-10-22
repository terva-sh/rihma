# Verification during sync

`Client.EnableSAS()` opts into to-device emoji verification before the
client's first `Sync`: with this account's other devices in both
directions, and outgoing with another user. It performs no network I/O.
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

Only one attempt is active. Busy, same-device, incoming cross-user, in-room, oversized,
old and excessively future-dated requests are ignored. IDs are remembered for the whole controller lifetime: a helper timer may be
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
see [verifying another user](cross-user-verification.md) for why, and for
incoming and in-room verification, which are designed but not exposed.
QR is not exposed by this controller. SSO/OIDC login is unrelated and
remains outside this feature.

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
