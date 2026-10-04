# Browser SSO

Classic Matrix SSO uses `m.login.sso` to authenticate in a browser, then returns
a short-lived, single-use `loginToken` to a callback. Exchange it with
`m.login.token` to create the account device and persist its session. This is
separate from SAS/QR verification, cross-signing and recovery.

`DiscoverLoginFlows(ctx, homeserver)` queries the unauthenticated login endpoint
before opening an account runtime. `LoginCapabilities.SSORedirectURL(callback)`
requires both SSO and token flows and builds a redirect on that same homeserver.
HTTPS is required except for HTTP loopback fixtures; loopback HTTP URLs require
an explicit port. Homeserver base paths and callback query escaping are preserved.
Returned capability flags cover classic login only. Missing classic flows return
`ErrSSOUnsupported`; discovery failures return `ErrLoginDiscovery` without remote
reason text. Cancellation returns the caller's context error.

The application owns browser launch and callback handling. Before constructing
the URL, start a listener on a specific loopback address and an OS-assigned port,
or use an HTTPS callback controlled by the application. Generate an unpredictable
nonce, bind it to the pending attempt and expected homeserver, and include it in
the callback path or query. Accept only that exact endpoint, expected method and
nonce, with exactly one nonempty `loginToken`. Do not accept a callback arriving
without a pending attempt or from another attempt. Close the listener after one
accepted callback, cancellation or a bounded deadline. Suppress callback request
logging and keep callback queries out of diagnostics and persistent UI state.
The redirect URL itself may contain the application's binding nonce; treat it as
transient and do not log it.

After validating the callback, use the existing initialization path:

```go
opts.Login = &mautrix.ReqLogin{
    Type:  mautrix.AuthTypeToken,
    Token: loginToken,
}
client, err := rihma.Open(ctx, opts)
// Discard loginToken and opts.Login after this attempt, including on failure.
```

`Open` uses `Options.Login` only when there is no stored session. An existing
session is restored without exchanging the token or replacing its device. Check
the session before launching SSO, and coordinate login ownership in the application
to avoid competing attempts. Use a separate state directory/session store for a
deliberately different account. This API does not provide a session replacement
operation or a callback listener. Empty/expired/consumed tokens fail at the
homeserver; request a fresh browser authentication rather than reuse them.

Once token exchange succeeds, `Open` initializes crypto and saves the access
token, device ID and pickle key through `Options.Sessions` before returning.
A failed session save uses the existing cleanup path. Cancellation after the
server has consumed the token may still have created a device; it cannot be
treated as rollback. Never include the token, callback query, session or raw
authentication errors in logs. Rihma suppresses HTTP request bodies; applications
must also protect their browser and callback diagnostics. SSO authenticates the
account and does not recover cross-signing secrets or historical room keys.

Delegated OAuth is a separate flow, for homeservers that hand authentication to
an OAuth issuer such as the Matrix Authentication Service. It follows the same
ownership rules, with the application holding the browser and callback, and is
described in [delegated OAuth login](oauth-login.md). QR device authorization
for signing in on another device is distinct from interactive Matrix QR
verification, and is not implemented.
