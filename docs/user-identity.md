# Signing another user's identity

A client vouches for another user by signing their cross-signing master
key with its account's user-signing key. Afterwards it treats that user's
cross-signed devices as verified. rihma signs a key only when the caller
names it, and only when the homeserver still publishes that key at the
moment of signing.

```go
own, err := client.OwnMasterKey(ctx)                  // put own in a proof
ident, err := client.UserIdentity(ctx, sibling)       // ident.MasterKey, ident.SignedByUs
err = client.SignUserIdentity(ctx, sibling, provenKey) // provenKey from the caller's proof
```

Master keys are `id.Ed25519` values. Each is the unpadded base64 public
key as the homeserver publishes it. Compare them as strings. They are public
and safe to log. Formatting for display is the caller's job.

## Reading

`OwnMasterKey` returns the public half of the master key this device
holds, and only after a fresh `/keys/query` shows the server still
publishes the same identity. It never returns a key that only the server
vouches for, so a proof built on it cannot name a key the server swapped
in. It returns `ErrNoCrossSigningKeys` when the device does not hold the
keys (`HasCrossSigningKeys`), and `ErrMasterKeyMismatch` when the server
publishes another identity.

`UserIdentity` asks the homeserver, not the crypto store, for the user's
master key. `SignedByUs` reports whether this account's user-signing key
has a valid signature on it. rihma checks the signature itself rather
than taking the server's word. A device without the cross-signing keys
checks against the account identity the server publishes. The call also
refreshes the user's devices in the crypto store.

Whether the other user has signed this account cannot be read. The
Matrix specification lets a server show a user-signing key's signatures
only to the user who made them, and `/keys/query` returns another user's
user-signing key to no one.

## Signing

`SignUserIdentity(ctx, user, expected)` queries the server, and signs the
published master key only if it equals `expected`. The signature covers
exactly that key, so a key swapped in after the query is not vouched for.
A key this account has already signed is not signed or uploaded again.
After signing, the user's keys, devices and the new signature are stored
where mautrix's trust checks read them.

Each refusal is a sentinel that `errors.Is` matches through rihma's
wrapping:

| Error | Meaning |
| --- | --- |
| `ErrOwnUser` | The user is this account. |
| `ErrNoCrossSigningKeys` | This device does not hold the user-signing key, or the keys it holds are no longer the identity the server publishes. |
| `ErrNoUserIdentity` | The user publishes no master key. |
| `ErrMasterKeyMismatch` | The published key is not `expected`. The message names both keys. |

If the call fails after the upload, the key stays signed. Calling it
again finishes the work without signing twice. Recording the signature for
change reports is part of that work: if the store refuses the record,
`SignUserIdentity` returns an error rather than success without the
reports.

## Identity changes

rihma records, in its store, each user whose master key this account
signed. It also records a user whose key `UserIdentity` found signed by
this account. When a recorded user publishes a different master key,
`Options.OnIdentityChange` receives an `IdentityChange{UserID, Signed,
Published}`, and rihma logs a warning that names the user and both keys.
rihma never signs the new key on its own. A caller that has checked the
new key signs it with `SignUserIdentity`, and that makes it the recorded
key.

Each new key is reported once, even across restarts, and a server that
alternates between keys, including the signed one, cannot repeat a
report. Signing another key starts the reports afresh. If the store
refuses to record a report, rihma delivers it anyway and does not repeat it
in that process; after a restart it may be reported once more. A lost
warning would cost more than a repeated one. A change is
noticed when sync reports that the user's devices changed, which needs
a shared room with the user. It is also noticed by `UserIdentity` and by a
refused `SignUserIdentity`. A new key that another device of this account
has already signed is recorded without a report. The handler runs on the
goroutine that noticed the change, usually the sync goroutine, and must
not block.

## Logs

mautrix logs the signatures it makes and checks, at debug and trace
level. rihma drops those lines from the logger it hands to mautrix. A
test fails if a mautrix upgrade adds a signature log line that rihma does
not drop. User ids and master keys are logged; signatures and private
keys are not.
