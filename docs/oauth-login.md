# Delegated OAuth login

Homeservers that delegate authentication to an OAuth 2.0 authorization server,
such as the Matrix Authentication Service, offer the Matrix OAuth API instead
of classic password or SSO login. The user signs in on the issuer's web page,
the application receives an authorization code at its callback, and rihma
exchanges that code for a short-lived access token and a refresh token. This
is a different flow from [browser SSO](browser-sso.md), which returns a classic
`m.login.token`. It is also separate from SAS or QR verification,
cross-signing and recovery.

rihma uses the OAuth client in mautrix for the token requests and for the
refresh that runs before each request. rihma adds the parts that decide whether
a login is safe: metadata validation, the attempt's secrets, callback checks,
and the order in which tokens are stored and used.

## Sign in

The application owns the browser and the callback, as it does for browser SSO.

1. Discover the issuer:

   ```go
   server, err := rihma.DiscoverOAuth(ctx, "https://matrix.example.org")
   ```

   `ErrOAuthUnsupported` means the homeserver has no OAuth API. Use
   `DiscoverLoginFlows` and classic login instead. `ErrOAuthDiscovery` means
   the metadata was unreachable or unsafe, and carries no remote text. The
   call opens no store and creates no device.

2. Start a listener on a loopback address with an OS-assigned port, then begin
   the attempt with its exact URL:

   ```go
   attempt, err := server.BeginLogin(ctx, rihma.OAuthClientMetadata{
       ClientName: "Example Chat",
       ClientURI:  "https://chat.example.org/",
   }, "http://127.0.0.1:53211/callback")
   ```

   `BeginLogin` registers a native public client for this attempt and builds
   the authorization URL with a random state, a PKCE S256 challenge and a new
   device ID. Every attempt registers again, as the Matrix specification
   requires, so there is no client ID to cache.

3. Open `attempt.URL` in the user's browser. The URL carries the attempt's
   state, so do not log it.

4. When a request arrives at the callback, pass the full callback URL,
   including its query, to `Accept`:

   ```go
   login, err := attempt.Accept("http://127.0.0.1:53211/callback?" + r.URL.RawQuery)
   ```

   If `Accept` returns `ErrOAuthCallback`, the request does not belong to this
   attempt. Reject it and keep listening. The attempt stays pending, so a stray
   request cannot end it. `ErrOAuthDenied` means the user or the issuer refused.
   That ends the attempt.

5. Close the listener, then open the account:

   ```go
   opts.OAuthLogin = login
   client, err := rihma.Open(ctx, opts)
   ```

   `Open` exchanges the code, checks with the homeserver that the token
   belongs to the device it requested, and saves the session through
   `Options.Sessions` before it returns. The client is not connected yet, like
   a restored one. `Sync` connects it, or call `Connect` to send encrypted
   messages first.

## Redirect and callback rules

`BeginLogin` accepts two kinds of redirect URI, the native-client forms from
the Matrix specification:

| Redirect | Example | Registered as |
|---|---|---|
| Loopback HTTP on `127.0.0.1`, `[::1]` or `localhost`, with an explicit port | `http://127.0.0.1:53211/callback` | the same URI without the port |
| Private-use scheme: `ClientURI`'s host in reverse-DNS order, with no authority | `org.example.chat:/callback` | the same URI |

The issuer accepts any port on a loopback redirect, which is why the
registration leaves it out. Queries, fragments and user info are refused, and
so is an HTTPS redirect, which would need the fragment response mode. Logo,
policy and terms URIs must use HTTPS on `ClientURI`'s host or a subdomain.

`Accept` takes a callback only when all of these hold:

- Its scheme, host, port and path match the redirect URI.
- It carries exactly one `state`, equal to the attempt's.
- It carries the issuer's `iss` when the issuer includes it, or when the
  metadata promises it (RFC 9207). This stops a code from another issuer
  being redeemed here.
- It carries exactly one non-empty `code`, or an `error`.

The request does not ask for the `openid` scope, so the issuer returns no ID
token and an OIDC nonce would have nothing to bind. The state binds the
callback to the attempt, and PKCE binds the code to it.

An `OAuthAuthorization` lives in memory only and cannot be resumed after a
restart. To cancel, drop it and close the listener. Bound the wait with a
deadline. Suppress request logging on the listener and keep the callback query
out of diagnostics and UI state.

## Session and refresh

`Open` uses `Options.OAuthLogin` only when `Options.Sessions` holds no session,
exactly like `Options.Login`, and the two cannot be combined. A stored session
always wins. `Open` then restores it, exchanges nothing and replaces no device,
so check for a session before you start a browser attempt. A login that `Open`
uses must come from `DiscoverOAuth` on the same `Options.Homeserver`, because
an access token sent to another homeserver is a leaked token. `Open` checks
that before any request and otherwise returns `ErrOAuthLogin`. Each `OAuthLogin` is single-use,
whether the exchange succeeds or fails.

The saved `Session` carries an `OAuth` field with the issuer, the client ID,
the token and revocation endpoints, the refresh token and the access token's
expiry. The refresh token is a secret, like the access token. Sessions from
classic login have no `OAuth` field and keep the same JSON shape, so existing
session stores need no change. A program that reads a session with an older
rihma ignores the field and loses the ability to refresh.

Restoring an OAuth session makes no request. rihma installs the token endpoint
validated at login, so the refresh token is sent only to that endpoint.
If the issuer later moves its token endpoint, refresh fails and the user signs
in again.

mautrix refreshes the access token shortly before it expires. Most requests
refresh 10 seconds early and sync refreshes 60 seconds early. The issuer
rotates the refresh token on each use. rihma saves the new pair through
`SessionStore.Save` before mautrix uses it. If the save fails, the client keeps
the old pair, and the next request refreshes again from it. The save ignores
the cancellation of the request that triggered it, because the issuer has
already rotated the pair and an abandoned save would throw the new one away. rihma serializes these saves with the
key-backup save, so neither can overwrite the other with an older session.

`Save` must replace the whole session atomically, as `FileSessionStore` does,
and must not make requests through the `Client`. Requests wait while a refresh
saves.

## Failure and cancellation

- **Before the exchange.** Cancellation returns the context error. Nothing
  exists on the server.
- **During the exchange.** Cancellation returns the context error. The issuer
  may already have redeemed the code and created a device whose tokens never
  reached the application. rihma cannot revoke tokens it never received, so
  treat a cancelled exchange as possibly having created a device, which the
  user can remove from the issuer's account page.
- **After the exchange.** If the account check or the first save fails, or the
  login is cancelled, rihma revokes the new tokens at the issuer. It does this
  even when the context is cancelled, and gives up after 10 seconds. `Open`
  then returns the error and stores nothing.

`ErrOAuthLogin` covers a refused code, an unusable token response and a device
mismatch. Its message names at most an HTTP status and an OAuth error code,
never the issuer's description text.

## End a session

`Client.Logout` revokes the refresh token at the issuer's revocation endpoint,
which ends the access token and the device. It does not call `/logout`, which
the Matrix OAuth API does not use. If revocation fails, `Logout` returns
`ErrOAuthRevoke` and keeps the session and state directory, so the device is
not orphaned and you can retry. If it succeeds, `Logout` clears the session and removes the state
directory, as it does for classic sessions.

When the issuer refuses a refresh with HTTP 400, 401 or 403, the session has
ended. It was revoked, expired or replaced elsewhere. `Sync` then returns an
error that matches `ErrOAuthSessionEnded` and also `mautrix.MUnknownToken`, so
code that already stops on an invalid token handles it unchanged. Rate limits,
timeouts and server errors stay retryable. If the homeserver rejects an access
token that has not expired, the request fails with `M_UNKNOWN_TOKEN` at once.
rihma sets an idle mautrix `RequestRetryTrigger` on OAuth clients, because
without one mautrix v0.31.0 retries that rejection until the token expires.

In both cases, start a new browser attempt to sign in again. A stored session
always wins, so log out first or use a new state directory.

## Logs and errors

The client that `Open` builds omits every HTTP request body from logs, which
covers codes, verifiers and refresh tokens in token requests.
`DiscoverOAuth` and `BeginLogin` log nothing. The errors from `DiscoverOAuth`,
`BeginLogin`, `Accept`, an OAuth login in `Open`, and `Logout` carry no tokens,
codes, verifiers, state or issuer description text. A failed revocation
returns `ErrOAuthRevoke` with at most an HTTP status and an OAuth error code.
A request that fails because a refresh failed for another reason, such as an
issuer outage, returns the mautrix error, which can include the issuer's
description text. The application must keep the authorization URL, the
callback query and its own listener diagnostics out of its logs.

## Not covered yet

- A listener owned by rihma. The callback stays with the application, as for
  browser SSO.
- The device authorization grant, used for QR login on another device.
- HTTPS redirects that need the fragment response mode.
- `prompt=create` for account registration, and login hints.
- Account-management actions such as approving a cross-signing reset. The
  issuer's page is available as `OAuthServer.AccountManagementURI`.
- The connector. `terva-rihma` logs in with a password, and its session store
  refuses an OAuth session rather than dropping the refresh token.
