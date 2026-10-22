# Verifying another user

This is the design for emoji (SAS) verification between this account and
another user. Its first two slices have shipped: `SASController.StartUser`
sends an outgoing to-device request to another user and signs them on
completion, and `Client.VerifyUser` wraps it for a stopped bot (see
[verification during sync](verification.md)). Incoming
requests from other users and in-room verification are not implemented
yet, and the controller still drops them. The sections below say what
each route accepts, what must already be true before it starts, what it
leaves behind, and the public interface and implementation slices that
add it without changing the same-account behavior.

The intended first user is a bot whose operator wants the bot's owner to
see it as verified. After a cross-user SAS, each side signs the other's
master key with its own user-signing key. The owner's clients then trust
every device the bot has cross-signed, and the bot trusts the owner's.

## Two ways to compare the emoji

SAS protects against a homeserver that forges the key exchange only if
the two people compare the emoji over a channel that homeserver cannot
change. Which channel that is decides how much the result is worth, so
rihma supports both and leaves the choice to the application:

- **Outside Matrix.** The bot's operator runs a command on the bot's host,
  which sends the owner a request and prints the emoji on the terminal.
  The owner compares them with their own client, confirms there, and the
  operator confirms at the terminal. Nothing in the comparison crosses the
  homeserver. This is `Client.VerifyUser`.
- **In the chat.** The bot accepts a request from an owner it was
  configured to trust, and shows the emoji in their direct message. That
  message travels through the homeserver, to devices of the owner the bot
  has not verified, so a homeserver that forges the key exchange can
  rewrite it too and the emoji will match. This route trusts the
  homeserver. Offer it only for a homeserver the owner runs and trusts,
  and say so where it is configured.

On either route, the application must not confirm a SAS by itself. A
person compares the emoji and reports the answer; rihma calls back and
waits.

## Targeting

A verification runs either to-device or in a room. Both use the same
`m.key.verification.*` steps and the same transaction lifetime; they
differ in how events are addressed and what identifies the transaction.

| | To-device | In-room |
| --- | --- | --- |
| Request | `m.key.verification.request` to-device, to every device of the peer | `m.room.message` with `msgtype` `m.key.verification.request`, `to` naming the peer |
| Transaction id | `transaction_id` chosen by the requester | The request event's id |
| Follow-ups | To-device, carrying `transaction_id` | Room events with `m.relates_to` `rel_type: m.reference` to the request |
| Who sees it | Only the peer's devices | Everyone in the room |
| Used by | Own devices today; outgoing cross-user | Element's "verify user" in a DM |

The to-device sender is asserted by the homeserver, and `from_device` is
only a claim. The SAS binds the peer's device key and master key in its
MAC, so a forged device cannot complete a verification whose emoji were
compared over a channel the homeserver does not control. It can still
complete one compared in the chat.

### What each route accepts

The gate drops an event that fails any rule before the upstream helper
sees it, so a dropped event creates no transaction, timer, reply or
callback. Every rule below is in addition to today's: one active attempt,
transaction ids and device ids of at most 256 bytes, ids remembered for
the controller's lifetime, and at most 64 attempts per controller.

**Incoming to-device request.** The sender is this account or a user in
`SASOptions.Peers`. `from_device` is present, and is not this device when
the sender is this account. Device ids are scoped to their user, so
another user's device may share this device's id and is still a peer. The
request was sent at most ten minutes ago and at most one minute in the
future; the specification allows five minutes in the future, and rihma
keeps today's tighter bound. A request from any other user is dropped
without a reply, so a stranger cannot make the bot send messages.

**Incoming in-room request.** `SASOptions.InRoom` is set. The sender is in
`Peers`, `to` is this account, and the room is an encrypted room this
account has joined. The event arrived encrypted, because an unencrypted
event in an encrypted room is one the homeserver could have written. The
age bounds use the event's timestamp.

**Follow-ups.** The sender is the transaction's peer user. A to-device
follow-up names the active transaction id. An in-room follow-up is in the
transaction's room, references the request event, and arrived
encrypted. A `ready` names a `from_device`; for an outgoing
to-device request it must be one of the devices the request was sent to.
As with requests, the gate compares a device with this one only when the
sender is this account.
A follow-up from another user that carries the right transaction id is
dropped. Today's gate already enforces this for same-account attempts,
because it admits only this account's own events.

**Outgoing to-device.** `StartUser(ctx, user)` sends the request to every
device the peer publishes, fetching the list when the crypto store has
none, and never to this device. The first eligible `ready` selects the
peer device, and the others receive `m.accepted` cancellations. Naming
the user is the consent, so `Peers` does not need to list them.

**Outgoing in-room.** `StartInRoom(ctx, room, user)` posts the request in
`room`, which must be an encrypted room this account has joined, and
requires `SASOptions.InRoom`. The upstream helper encrypts the request
whatever the room, so rihma checks the room first.

## Prerequisites

Before it sends a request or a `ready`, the controller checks, on its own
goroutine:

- The peer is not this account (`ErrOwnUser`). Same-account verification
  keeps using `Start` and `Accept`.
- This device holds the account's cross-signing keys, and the server
  still publishes them (`ErrNoCrossSigningKeys`, as `OwnMasterKey` checks).
  Without the user-signing key there is nothing to sign the peer with,
  and without this device's own cross-signature the peer's signature on
  the master key would not cover it. Run `RestoreFromRecoveryKey` or a
  same-account verification first.
- The peer publishes a master key (`ErrNoUserIdentity`). The check
  refreshes the peer's keys and devices in the crypto store, as
  `UserIdentity` does, so the MAC is checked against a current key.
- For an outgoing request, none of the peer's devices has this device's
  id (`ErrPeerDeviceIDConflict`). Upstream behavior 4 below would leave
  such a device out of the request, so the person at it would never see
  one; rihma refuses rather than send a request that cannot reach them.

For an incoming request these run at `Accept`. A failed check cancels the
attempt and returns the error; nothing is sent before the check.

## Completion and cross-signing

The MAC step proves that the device the emoji were compared with named
that device key and that master key. On success the upstream helper marks
that device verified and, when the MAC named a master key, signs it with
this account's user-signing key.

The pinned helper has a defect here. When the local side confirms after
the peer's MAC has already arrived, it compares the peer's master key with
this account's own, fails, and never sends `done`. The completion slice
works around it in the gate: while the local person has not confirmed, a
peer `m.key.verification.mac` for the active transaction is held, at most
one per attempt, and released after the local confirmation is sent. The
local MAC check then always runs second, which is the order that signs
the peer. A second held MAC cancels the attempt, and a held MAC is
discarded on mismatch, cancellation, expiry and shutdown.

The upstream signature bypasses rihma's identity records, so a later
change to the peer's master key would go unreported. On `done`, the
controller calls `SignUserIdentity(ctx, peer, key)` with the master key the
peer's MAC named. The key is already signed, so that call only records
it, and it refuses if the server now publishes a different key. Only after
that does the snapshot reach `done`, with `MasterKey` set. A peer whose
MAC named no master key reaches `failed` with reason `unsigned`, and a
refusal from the record step reaches `failed` with reason
`identity_changed`. In both cases the device trust the helper already
stored remains; rihma does not promise to undo a signature already
uploaded.

Whether the peer signed this account cannot be read: servers show a
user-signing key's signatures only to their maker.

## Cancellation, lifetime and shutdown

These are today's rules, applied per attempt whatever its route:

- `Cancel(ctx, txn)` sends `m.user`, and a `Confirm(ctx, txn, false)` sends
  `m.mismatched_sas`. An in-room cancellation goes to the room, a to-device
  one to the selected peer device, or to every requested device before
  one is selected.
- A request expires ten minutes after it was sent, with `m.timeout`.
- A cancellation from the peer user, from any of their devices, ends the
  attempt. Its reason text never reaches a snapshot, an error or a log;
  the snapshot carries only rihma's fixed reasons.
- Stopping `Sync` quiesces handlers, revokes in-memory transactions and
  joins any expiry already in flight, as described for the same-account
  controller. No attempt survives a restart.

## Safe snapshots and logs

`SASSnapshot` gains `OtherUser`, `Room` and `MasterKey`. All three are
public identifiers. For a same-account attempt `OtherUser` is this account
and `Room` is empty. Emoji are cleared after confirmation or cancellation,
as today. Logs carry user ids, device ids, room ids, transaction ids,
event kinds and master keys, never SAS secrets, MAC values, signatures or
message text. The controller keeps passing the helper a silent logger.

## Public interface

Everything here is added; nothing existing changes meaning.

```go
// SASOptions widens what an SASController admits. The zero value is
// today's same-account, to-device controller.
type SASOptions struct {
	// Peers are other users whose verification requests are admitted.
	// Requests from anyone else are dropped without a reply.
	Peers []id.UserID
	// InRoom admits in-room requests from Peers, and lets StartInRoom
	// post one.
	InRoom bool
}

// EnableSASWith is EnableSAS with options. EnableSAS() is
// EnableSASWith(SASOptions{}). A second call returns the same controller
// if the options are equal, and ErrSASUnavailable if they differ.
func (c *Client) EnableSASWith(opts SASOptions) (*SASController, error)

// StartUser asks user's devices, over to-device messages, to verify this
// account. It checks the prerequisites first. Shipped.
func (s *SASController) StartUser(ctx context.Context, user id.UserID) (id.VerificationTransactionID, error)

// StartInRoom asks user to verify this account in room.
func (s *SASController) StartInRoom(ctx context.Context, room id.RoomID, user id.UserID) (id.VerificationTransactionID, error)

// VerifyUser asks user to verify this account with emoji, shows confirm
// the emoji, and returns user's master key once both sides confirmed and
// this account has signed it. Like AwaitSAS it runs its own Sync, fails
// with ErrSyncInProgress while anything else syncs on the state
// directory, and answers one attempt per Client. Shipped, with
// ErrSASUnsigned for a peer whose MAC named no master key.
func (c *Client) VerifyUser(ctx context.Context, user id.UserID, confirm func([]SASEmoji) bool) (id.Ed25519, error)
```

`Accept`, `Confirm`, `Cancel`, `Snapshot` and `Changed` work for every
route. `Accept` runs the prerequisite checks for a cross-user request.
The new snapshot reasons are `unsigned` and `identity_changed`. Errors
reuse `ErrOwnUser`, `ErrNoCrossSigningKeys`, `ErrNoUserIdentity` and
`ErrMasterKeyMismatch` from [signing another user's
identity](user-identity.md).

## Cross-user QR

QR verification between users is out of scope for this work. It needs
its own design, because its trust rests on different keys than the
same-account modes do. The displaying side encodes its own master key
and the master key it believes the peer has, so it needs this account's
master key held and trusted and a fresh copy of the peer's. Scanning
signs the peer's master key before the displaying side confirms. It
depends on the same-account QR controller, which is not public yet
(see [QR verification groundwork](qr-verification.md)).

## Upstream behavior this design works around

Tests in `sas_cross_user_test.go` pin four behaviors of mautrix v0.31.0's
`verificationhelper`. A dependency upgrade that changes any of them fails
there, so the workaround can be revisited:

1. Follow-ups are routed to a transaction by id alone, without checking
   that the sender is the transaction's user. The gate's sender binding is
   what stops a third party cancelling or steering an attempt.
2. An in-room follow-up is looked up by its own event id, not the request
   it references, so an in-room transaction never advances. The in-room
   slice routes by the reference itself.
3. Cross-user SAS fails to sign the peer when the local side confirms
   after the peer's MAC has arrived. The completion slice holds that MAC.
4. A device is compared with this one by id alone, without its user. The
   helper ignores a request from another user's device that shares this
   device's id, and leaves such a device out of its own requests. rihma
   cannot work around this one from the gate. Until upstream fixes it, a
   peer can verify this account only from a device whose id differs from
   this device's, and `StartUser` returns `ErrPeerDeviceIDConflict` when
   the peer publishes a device with this device's id. Callers should match
   that error rather than compare ids themselves, so their check goes
   away with the defect.

Each should also be reported upstream; an upstream fix replaces the
matching workaround rather than adding to it.

## Implementation slices

Each slice is a separate change with its own tests. None touches an
account or server outside the throwaway Synapse in `testing/synapse/`.

1. **Shipped: outgoing to-device SAS with another user, signed at completion.**
   `StartUser`, the prerequisite checks, follow-up binding to the
   transaction's user, the held MAC, the completion record through
   `SignUserIdentity`, and the new snapshot fields and reasons. Tests: a
   hermetic run against an upstream helper acting as the peer, in both
   confirmation orders, ending with each side's signature on the other's
   master key and the peer recorded for change reports; a third user's
   follow-ups carrying the transaction id are dropped; a `ready` from an
   unrequested device is dropped; each prerequisite failure sends nothing;
   a peer MAC without a master key ends `unsigned`; a key swapped on the
   server before `done` ends `identity_changed`; a second held MAC
   cancels; remote reasons stay out of snapshots; a live test on two
   throwaway Synapse accounts.
2. **Shipped: `VerifyUser`, the one-shot terminal wrapper.** Depends on slice 1.
   Tests: it refuses a running sync; it returns the signed master key on
   success, `ErrSASMismatch` when confirm says no, and `ErrSASCancelled`
   when the peer cancels; it follows only its first transaction; a live
   test on throwaway Synapse accounts.
3. **Incoming to-device SAS from listed users.** `EnableSASWith` with
   `Peers`. Depends on slice 1. Tests: a listed user's request is
   admitted and completes with signatures; an unlisted user's request
   leaves no transaction, timer or reply; a listed user's request while
   busy is dropped; prerequisite failures at `Accept`; options differing
   on a second call are refused; the zero options keep today's behavior,
   including every existing test.
4. **In-room SAS with another user, both directions.** `SASOptions.InRoom`
   and `StartInRoom`, routing in-room follow-ups by their reference, and
   the room and encryption binding. Depends on slice 3. Tests: an in-room
   request from a listed user in an encrypted DM completes; requests in a
   room this account has not joined, in an unencrypted room, with `to`
   naming someone else, or unencrypted in an encrypted room are dropped;
   `StartInRoom` refuses an unencrypted or unjoined room before sending; follow-ups from the right
   user in another room, or referencing another request, are dropped;
   cancellation goes to the room; a live test in an encrypted DM.

The terminal flow needs slices 1 and 2. The in-chat flow also needs
slices 3 and 4, since Element verifies another user in the DM.

## Element and to-device requests

Element Web 1.12.30, the version the throwaway harness serves, answers a
to-device request from another user, but only if it already tracks that
user's devices. Its crypto (matrix-rust-sdk) tracks the members of
encrypted rooms it is in, so the bot and the person must share an
encrypted room, such as their direct message, before `VerifyUser` runs.
Without one, Element drops the request without a reply ("could not
retrieve the device data") and `VerifyUser` waits until the request
times out with `ErrSASCancelled`.

With a shared encrypted DM, the full flow was checked by hand against
Element: the request showed as "Verification requested", both sides
showed the same emoji, the person confirmed in Element first, so its MAC
reached the bot before the bot's operator answered and was held, and the
bot then confirmed. `VerifyUser` returned the person's master key, and
Element showed the bot as verified. The request therefore stays
to-device, and `VerifyUser` does not need an in-room fallback. Only the
request travels through the homeserver; the emoji are compared on the
bot's terminal.
