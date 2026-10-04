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
requests.

## Limits

- The key backup is not touched. Its key stays in secret storage under the old
  recovery key, which the new recovery key cannot read. `RestoreKeyBackup` with
  the new key therefore fails until the backup has been replaced. Deciding
  whether to carry the backup over or replace it is follow-up work.
- Delegated login itself, through OAuth 2.0 or OIDC, is a separate capability.
  The approval URL arrives in the upload's challenge, so a reset needs no OAuth
  client or token.
- The hermetic tests run the password and approval stages against a fake server
  that answers the way Synapse does. The live suite runs the password reset on
  a disposable Synapse. It has no Matrix Authentication Service, so the
  delegated stage is not proven against a real one.
