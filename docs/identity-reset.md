# Cross-signing identity reset

An account's cross-signing identity is the master key and its two subordinate
keys. Other devices and users verify against it. Its private keys live in secret
storage, encrypted under the recovery key. When the recovery key is lost and no
verified device remains, the only way back to a verified state is a new
identity. Every device and user that verified the old one then has to verify
the account again.

```go
key, err := client.CreateRecoveryKey(ctx, password) // first identity; "" is fine on current servers
key, err := client.ResetCrossSigningIdentity(ctx, rihma.CrossSigningAuth{
    Password: password, // empty for an account without one
    Approve: func(ctx context.Context, a rihma.CrossSigningApproval) error {
        // Show or open a.URL, then wait for the person to approve there.
        // Return nil to retry the upload, or an error to abandon the reset.
        return waitForPerson(ctx, a.URL, a.Attempt)
    },
})
```

`CreateRecoveryKey` does not replace an identity. It returns
`ErrIdentityExists`, including when another device creates one while it runs.
A challenge from the server during create makes rihma check for an identity
again before it answers, and an approval challenge is always refused. A server
from before Matrix v1.11 asks for the password even for a first identity. On
such a server, an identity created in the moment between that second check and
the upload can still be replaced. `ResetCrossSigningIdentity` replaces an
identity only when called. On an account with
no identity it creates one, the same way. Both functions return a new recovery
key: show it to the person once and never log it. Warn the person before calling
reset. It cannot be undone, and the old recovery key stops working.

## What the server asks for

A server accepts an account's first identity without user-interactive auth
(Matrix v1.11), and re-uploading the same keys is idempotent. Replacing an
identity needs authentication, and `CrossSigningAuth` answers one of two
stages:

- `m.login.password`, for an account with a homeserver password. `Password` is
  sent only when the server asks for it. A missing password fails with
  `ErrPasswordRequired`. A rejected one surfaces as `mautrix.MForbidden`.
- `m.oauth` (Matrix v1.17), or its unstable MSC4312 name
  `org.matrix.cross_signing_reset`, for a homeserver that delegates accounts to
  an OAuth 2.0 server such as the Matrix Authentication Service. Synapse offers
  both names. Its URL leads to the account management page with
  `action=org.matrix.cross_signing_reset`. Approving there lets the account
  replace its master key for a limited time. A missing `Approve` fails with
  `ErrApprovalRequired`.

Other stages, and flows with more than one stage, fail with
`ErrAuthUnsupported`. The error names the stages the server offered. That
includes the classic SSO stage, which completes through a fallback web page
that rihma does not drive.

## The approval loop

`Approve` receives the page URL and an `Attempt` count. The application owns
the pacing. It can show the page and block until the person presses "continue",
or open the page and sleep between returns to poll. When `Approve` returns nil,
rihma retries the upload at once. The retry carries the auth dict of Matrix
v1.17, which holds only the session.

If the server has not seen the approval, rihma calls `Approve` again with the
next `Attempt`. From attempt 2, tell the person the approval has not arrived
yet. An error from `Approve` abandons the reset. The returned error wraps it,
so `errors.Is` and `errors.As` still find it, but its text is not repeated,
because an error from opening or polling the page can contain the URL.
`Approve` must return when `ctx` is done. If it returns nil after that, rihma
still stops.

The URL must be an absolute `http` or `https` URL without userinfo. Anything
else, including a missing URL, fails with `ErrApprovalURL` and `Approve` is not
called. Open the page in the system browser. Do not log it or persist it.

## What a failure leaves

rihma generates the new keys locally. It writes nothing to the account until
the server has accepted them. The following failures therefore leave the old
identity, its secret storage and this device's keys as they were:

- `ErrPasswordRequired`, `ErrApprovalRequired`, `ErrAuthUnsupported` and
  `ErrApprovalURL`;
- a rejected password;
- an error from `Approve`;
- cancellation while `Approve` waits.

The old recovery key keeps working after any of them, and the call can simply
be repeated.

Once the server has accepted the keys, rihma does the following:

1. It stores the new secret storage key.
2. It stores the three private keys, encrypted under that secret storage key.
3. It makes the new key the default.
4. It signs this device and the master key.

A failure in any of those steps returns `ErrIdentityIncomplete` and no recovery
key. The old identity is gone at that point, so run `ResetCrossSigningIdentity`
again. On a delegated server, an approval that has not expired yet covers the
second run. If cancellation lands while the final upload is in flight, the
outcome is unknown. Run the reset again to settle it.

`mautrix.Client` retries a 401 only once and discards the retry's response. To
start a fresh challenge, rihma therefore publishes again on every attempt. Each
attempt costs one unauthenticated request and one authenticated one.

## The key backup after a reset

A reset leaves the account's key backup as it was, and that state is a problem.
The backup's key is still in secret storage, but under the old recovery key, so
`RestoreKeyBackup` with the new key fails. The old master key signed the
backup's auth data, so a client that knows only the new identity does not trust
it. A device that already uploads to the backup carries on, because mautrix
trusts a backup whose public key matches the key the device holds.

rihma repairs the backup only when the application asks. Call one of two
functions with the new recovery key:

```go
key, err := client.ResetCrossSigningIdentity(ctx, auth)
// Show key to the person, then:
err = client.CarryKeyBackup(ctx, key)
if errors.Is(err, rihma.ErrBackupKeyUnavailable) {
    // Ask the person first: this drops the room keys only the old backup held.
    err = client.ReplaceKeyBackup(ctx, key)
}
```

- `CarryKeyBackup` keeps the backup's version and key, so every room key in it
  stays readable. It stores the key under the new recovery key and signs the
  auth data again with the new master key. It needs the backup's key. Either
  this device uploads to the backup, or secret storage under the new recovery
  key already holds the key, from an earlier carry that was interrupted. If
  neither holds, it returns `ErrBackupKeyUnavailable`. On an account without a
  backup it returns `ErrNoKeyBackup`.
- `ReplaceKeyBackup` deletes the backup and creates a new one with a new key,
  as matrix-js-sdk does when it resets encryption. It always works, but every
  room key that only the old backup held is lost. This device then uploads
  every room key it holds to the new backup. On an account without a backup it
  creates one, as `EnableKeyBackup` does.

Both need this device to hold the cross-signing identity that the server
publishes, and right after a reset it does. Otherwise they return
`ErrNoCrossSigningKeys`. A recovery key that does not open the account's
secret storage fails too. All of these refusals happen before anything is
written.

Carry signs the auth data as the server holds it. It keeps every field and
replaces this account's signatures with the new master key's. The old
signatures came from the old identity and from devices trusted through it, and
clients no longer trust either.

After a carry, other devices keep uploading to the same backup. After a
replace, they stop. Each one adopts the new backup with `RestoreKeyBackup` and
the new recovery key, or with `RequestKeyBackup` once it is verified again.

### What an interruption leaves

The steps are ordered so that at every point some recovery key can read the
latest backup, or the latest backup is still empty. No room key goes into a
backup whose key no recovery key can read. Every failure returns an error, and
running the same call again finishes the work.

An error does not always mean the server refused a write. A write can land and
its answer can still be lost. The states below allow for that.

`CarryKeyBackup`:

1. It stores the backup's key under the new recovery key. If this fails, the
   backup is as it was, or the key is stored and the state is as at step 2.
2. It signs the auth data with the new master key and stores it on the server.
   If this fails, the new recovery key already restores the backup, because
   `RestoreKeyBackup` trusts a backup whose public key matches the key it
   reads. A client that checks the signature does not trust the backup yet.
   Run `CarryKeyBackup` again, on this device or on any device that holds the
   new identity.
3. This device keeps uploading to the backup.

`ReplaceKeyBackup`:

1. It creates the new backup, signed by the new master key. From here the new
   backup is the latest one, but it stays empty until step 4. If this fails,
   nothing has changed, unless the server created the backup and only the
   answer was lost. That case leaves the state of a stop between steps 1 and 2,
   described next.
2. It stores the new key under the new recovery key. If this fails, rihma reads
   secret storage back. If the key is there, the write landed and rihma carries
   on with step 3. If the key is not there, rihma deletes the new backup again,
   so the old one is the latest once more and is unchanged. If rihma cannot
   read secret storage, it deletes nothing, and the state is either this one or
   the state after step 2. If the cleanup fails, or the process stops between
   steps 1 and 2, the empty new backup stays the latest. The old backup and its
   key in secret storage are untouched, and nothing is uploaded to the new
   backup. Uploads to the old backup stop, and a rihma device that saw that
   happen resumes them after a restart.
3. It deletes the old backup. If an earlier replace was interrupted, it also
   deletes the backup this device was still uploading to. If this fails, the
   new backup works and the new recovery key restores it, but the old one is
   still on the server.
4. This device starts uploading to the new backup. If this fails, the state is
   as after a failure at step 3.

A second replace deletes the backups the first one left behind, so it ends
with a single backup. There is one exception. Suppose the device never uploaded
to the old backup, and the first run stopped between steps 1 and 2 or could not
tell whether step 2 landed. The second run then knows only the new backup, and
the old one stays on the server. It is no longer the
latest backup, so no client restores it or uploads to it.

## Logs and errors

rihma logs the stage name and attempt number at debug level. Errors carry
sentinels, HTTP statuses, Matrix error codes and stage names. A stage name or
error code that is not a protocol identifier is replaced or left out.

A failed upload reports its status and code, and never the server's error text.
Before Synapse adopted the approval stage, it returned the reset demand as an
error whose text held the approval URL. The cause stays available to
`errors.Is` and `errors.As`, for example `mautrix.MForbidden` for a rejected
password. The same holds for an error from `Approve`.

The password, the approval URL, the server's `msg` and error text, and the
recovery key never reach a log, or an error from the upload or the approval.
Request bodies are omitted from request logs at every level, as for all rihma
requests. The backup repairs log backup version numbers at debug level, and
never the backup key or the recovery key.

## Limits

- A reset does not repair the key backup on its own. The application calls
  `CarryKeyBackup` or `ReplaceKeyBackup` afterwards, as described above. Until
  it does, `RestoreKeyBackup` with the new recovery key fails.
- mautrix checks a backup's signature over only the auth data fields it
  models: the public key and the signatures. If a backup's auth data has other
  fields, such as the passphrase salt that older clients added, a
  mautrix-based client cannot trust it by signature, whoever signed it. Carry
  signs the whole auth data, as the specification says, so other clients
  trust it. A mautrix-based client that holds the backup key trusts the
  backup without the signature.
- Delegated login itself, through OAuth 2.0 or OIDC, is a separate capability.
  The approval URL arrives in the upload's challenge, so a reset needs no OAuth
  client or token.
- The hermetic tests run the password and approval stages against a fake server
  that answers the way Synapse does. The live suite runs the password reset on
  a disposable Synapse. It has no Matrix Authentication Service, so the
  delegated stage is not proven against a real one.
- The live suite carries and then replaces a backup after a password reset on
  the disposable Synapse, and reads old history with the new recovery key.
  Interruptions are tested only against the fake server, which fails one
  chosen step at a time.
