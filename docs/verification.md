# Verification during sync

`Client.EnableSAS()` opts into incoming same-account, to-device emoji
verification before the client's first `Sync`. It performs no network I/O.
The returned `SASController` shares the existing crypto-aware syncer; it never
starts another sync loop. Clients that do not opt in keep bot behavior.

```go
controller, err := client.EnableSAS()
// Handle err, then start the account's one client.Sync(ctx) owner.
// One adapter consumes Changed(), reads Snapshot(), and fans out view updates.
// For a requested attempt:
err = controller.Accept(commandContext, snapshot.TransactionID)
// For showing_sas, after comparing all seven emoji on the other device:
err = controller.Confirm(commandContext, snapshot.TransactionID, true)
// Or reject with Confirm(..., false), or Cancel(...).
```

The states are idle, requested, accepted, showing_sas, confirmed, done,
cancelled, failed and stopped. Confirmed means local agreement was sent;
only done means the protocol completed. Query `Client.Verification` to refresh
the device's cross-signing standing after completion. Emoji are cleared after
confirmation/cancellation. Snapshot slices are independent copies. Changed is
a bounded coalescing wakeup for one adapter, not a history stream or a channel
for multiple views to compete over. Snapshot revisions are local to the
controller and do not survive restart.

Every command carries the current transaction ID; commands in the wrong state
return `ErrSASStale`. Commands before sync starts or after it stops return
`ErrSASUnavailable`. Backend errors are reduced to `ErrSASOperation`; remote
cancellation reasons never enter snapshots or errors. Caller cancellation may
occur after a request was sent; read the snapshot instead of assuming rollback.
The controller suppresses helper context logging, including ephemeral SAS data.

Only one attempt is active. Busy, same-device, cross-user, in-room, oversized,
old and excessively future-dated requests are ignored. IDs are remembered for the whole controller lifetime: a helper timer may be
delayed beyond its deadline, so elapsed time cannot make ID reuse safe. At most
64 attempts are admitted per controller/Sync, bounding remembered IDs and helper
timers. Open a fresh account runtime to reset that budget.
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

Cross-user/outgoing verification, in-room requests and QR are not exposed by
this controller. Outgoing mautrix verification is used solely by the disposable
live test driver. SSO/OIDC login is unrelated and remains outside this feature.

Device trust and key recovery use the existing `Verification`,
`RestoreFromRecoveryKey` and `RestoreKeyBackup` operations. A missing identity is
`NoIdentity`; never create a replacement identity to bypass verification.
`CreateRecoveryKey` refuses an existing identity and `EnableKeyBackup` refuses
an existing backup. SAS success is not a claim that historical room keys are
available: restore the existing key backup separately. Recovery keys are
transient secret command input and must never enter UI snapshots or logs.
