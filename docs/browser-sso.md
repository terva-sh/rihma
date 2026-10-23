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

There are two ways to receive the token. A desktop or command-line application
can let rihma own a loopback callback for one attempt. Any application can
instead own the callback itself, which is the only choice for an HTTPS callback,
a callback on `localhost`, or one listener shared between attempts.

## Loopback callback owned by rihma

`LoginCapabilities.ReceiveSSOLogin` runs one whole attempt and returns the token
as an `SSOLogin` for `Open`:

```go
caps, err := rihma.DiscoverLoginFlows(ctx, homeserver)
login, err := caps.ReceiveSSOLogin(ctx, rihma.SSOLoopback{
    Sessions: sessions,
    Launch: func(ctx context.Context, url string) error {
        return openBrowser(ctx, url) // the application's own launcher
    },
})
opts.SSOLogin = login
client, err := rihma.Open(ctx, opts)
```

The call refuses to start with `ErrSessionStored` when `Sessions` already holds
a session, because `Open` would restore that session and never use the token.
It then listens on `127.0.0.1`, or on `::1` when `Address` says so, with a port
the operating system assigns. The callback path carries a 256-bit random nonce
made for this attempt. The application's `Launch` function receives the
homeserver's SSO page; the listener is already accepting when it is called.
`Launch` should return once the browser has been asked to open the page. Its
context ends with the attempt.

The listener accepts one callback and refuses everything else with a fixed page,
without ending the attempt:

- a Host header other than the bound address and port, which stops DNS
  rebinding, and any path other than the attempt's exact path;
- any method other than GET;
- a request body, meaning any `Content-Length` other than 0 or any
  `Transfer-Encoding`;
- a request line and header fields over 16 KiB (16384 bytes) as sent, counted
  through the blank line that ends them. These are answered with 431;
- a raw query over 4 KiB (4096 bytes), answered with 414;
- a `loginToken` over 2 KiB (2048 bytes) after percent-decoding;
- anything but exactly one nonempty `loginToken`. Other query parameters are
  ignored.

A request at exactly one of these sizes is accepted. The server reads at most
16 KiB of request line and headers before it answers 431, and the handler
checks the size again before it looks at the token.

The first acceptable callback ends the attempt. Any request after that, whether
a duplicate, a racing request or one with a different token, receives a page
saying the link has expired or was already used. A callback that carries an
`error` parameter instead of a token ends the attempt with `ErrSSODenied`.
Synapse does not redirect with an error; it shows its own error page and leaves
the attempt to time out. Other homeservers may redirect with one, and the
person then sees a failure page at once instead of waiting.

Other endings return their own errors. Every ending is classified in the same
order:

1. When the caller's context has ended, the result is that context's error.
   This holds even if `Launch` failed, the homeserver returned an error, or a
   callback was already accepted.
2. Otherwise, when the attempt's `Timeout` has passed, the result is
   `ErrSSOTimeout`. The timeout defaults to five minutes. This also applies
   when `Launch` returns an error because its context ended.
3. Otherwise, a `Launch` failure returns `ErrSSOBrowser`. That error also
   matches the launcher's error, but its message is fixed, so a launcher error
   that quotes the URL does not carry the nonce further.

The one exception is a callback accepted just as the attempt times out. The
person was told sign-in completed, so its token is returned rather than
`ErrSSOTimeout`.

A token that was accepted but then dropped because the caller cancelled is not
exchanged. No `SSOLogin` is made for it and nothing in rihma keeps it, so it
cannot be used later. The browser still shows the success page. Matrix has no
request that revokes an unused login token, so the token stays valid at the
homeserver until it expires; Synapse's lifetime for it is two minutes. Before
`ReceiveSSOLogin` returns, it shuts the server down and waits for it. A client
that holds a request open delays the return by at most two seconds.

The pages are plain text, with nothing from the request echoed. Success shows
"Sign-in complete. You can close this window and return to the application."
Failures say the sign-in did not complete, or that the response or link is not
valid, and to return to the application and try again. Every response sets
`Cache-Control: no-store`, `Referrer-Policy: no-referrer`,
`X-Content-Type-Options: nosniff` and a `default-src 'none'` content security
policy. The token stays in the browser's history for the callback URL. It is
single-use, and `Open` exchanges it straight away.

The listener logs nothing. Its HTTP server's error log is discarded, and rihma
never prints the query. An `SSOLogin` marshals to an empty JSON object. Every
`fmt` verb prints it as a fixed placeholder, whether it is a value or a pointer.
Its token sits two pointers deep, so fmt reaches only an address even when the
`SSOLogin` is held in another struct's unexported field, where fmt cannot call
its formatter. `OAuthLogin`, `OAuthAuthorization`, `Options`, `Session`,
`OAuthSession` and `Client` also format without their secrets. A `Client` no
longer keeps the login options it was opened with.

`Options.SSOLogin` cannot be combined with `Login` or `OAuthLogin`. When there is
no stored session, `Open` checks that the `SSOLogin` came from discovery on
`Options.Homeserver` before any request and returns `ErrSSOLogin` otherwise, so
the token never reaches another server. It takes the token once. A second `Open`
with the same `SSOLogin` returns `ErrSSOLogin`, whether the first exchange
succeeded or failed. After that check, the exchange and session save are the same
as for `Options.Login`, described below.

### Why an IP literal and not localhost

The listener binds an IP literal, as RFC 8252 section 8.3 recommends for native
applications. The name `localhost` can resolve to the other address family,
where another process may hold the same port, so `ReceiveSSOLogin` refuses it.
Synapse needs no allowlist entry for a loopback callback. Without one, it asks
the person to confirm on its own page before it redirects to the callback. A
deployment that wants to skip that page can add `http://127.0.0.1:` (or
`http://[::1]:`) to `sso.client_whitelist`; the entry is a prefix, so it covers
every port. If a homeserver accepts only `localhost`, own the callback as
described below.

## Callback owned by the application

The application can own browser launch and callback handling. Before
constructing the URL, start a listener on a specific loopback address and an
OS-assigned port, or use an HTTPS callback controlled by the application.
Generate an unpredictable nonce, bind it to the pending attempt and expected
homeserver, and include it in the callback path or query. Accept only that exact
endpoint, expected method and nonce, with exactly one nonempty `loginToken`. Do
not accept a callback arriving without a pending attempt or from another
attempt. Close the listener after one accepted callback, cancellation or a
bounded deadline. Suppress callback request logging and keep callback queries
out of diagnostics and persistent UI state. The redirect URL itself may contain
the application's binding nonce; treat it as transient and do not log it.

After validating the callback, use the existing initialization path:

```go
opts.Login = &mautrix.ReqLogin{
    Type:  mautrix.AuthTypeToken,
    Token: loginToken,
}
client, err := rihma.Open(ctx, opts)
// Discard loginToken and opts.Login after this attempt, including on failure.
```

## Token exchange and the stored session

`Open` uses `Options.Login` or `Options.SSOLogin` only when there is no stored
session. An existing session is restored without exchanging the token or
replacing its device. Check the session before launching SSO, as
`ReceiveSSOLogin` does, and coordinate login ownership in the application to
avoid competing attempts. Use a separate state directory/session store for a
deliberately different account. This API does not provide a session replacement
operation. Empty/expired/consumed tokens fail at the homeserver; request a fresh
browser authentication rather than reuse them.

Once token exchange succeeds, `Open` initializes crypto and saves the access
token, device ID and pickle key through `Options.Sessions` before returning.
A failed session save uses the existing cleanup path. Cancellation after the
server has consumed the token may still have created a device; it cannot be
treated as rollback. Never include the token, callback query, session or raw
authentication errors in logs. Rihma suppresses HTTP request bodies; applications
must also protect their browser and callback diagnostics. SSO authenticates the
account and does not recover cross-signing secrets or historical room keys.

Delegated OAuth is a separate flow, for homeservers that hand authentication to
an OAuth issuer such as the Matrix Authentication Service. The application holds
the browser and the callback there, and the flow is described in
[delegated OAuth login](oauth-login.md). QR device authorization for signing in
on another device is distinct from interactive Matrix QR verification, and is
not implemented.
