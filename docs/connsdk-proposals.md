# connsdk: three proposals, now adopted

rihma's connector, `terva-rihma`, is built on terva's Go connector SDK,
`packages/agent/connsdk`. Three SDK gaps found while matching
terva-conn-matrix led to the proposals below
([decision 0005](decisions/0005-connsdk-proposals.md)). All three shipped
in terva and are available in rihma's pinned terva v0.139.7 SDK. Rihma
now adopts them without a dependency change:

| SDK hook | rihma behavior |
|---|---|
| `Session.Warn(message)` | decryption failures, sync retries, and media drops reach the operator |
| `Config.ProtocolMin` | protocol 2 is required at the hello handshake |
| `Config.Verbs` | `verify` is dispatched by the SDK and listed in usage |

Warnings contain fixed guidance, IDs and counts or limits, never raw
error text, message content or attachment names. Decryption reports use
the library's per-room UTD window; sync retries and media drops each
emit at most once per minute, across rooms, while stderr keeps diagnostics.

The historical claims below were checked against terva v0.139.5, where
connsdk and connproto were unchanged since v0.139.3. Line numbers are in
`packages/agent/connsdk/connsdk.go` unless another file is named. Trunk
shas are provenance for the maintainers and will not resolve on terva's
public mirror.

The terva tickets carrying these were filed from rihma
TKT-01M3T4DXJQ6XZMD9W2Q7XXEVJE and are now done. The implementation
uses a nil-safe `Session.Warn` method instead of the proposed func field.

---

## 1. Let a transport send `warn` *(one field on `Session`)*

**The gap.** `warn` is the frame for a line the operator should see. The
host routes it to the proxy's `Warn` func
(`packages/agent/chat/external/proxy.go:62-64`), alongside its own crash
and restart notices. connsdk writes `warn` itself in three places: a fatal
receive error (`:579`), and the ends of the chat-event and membership
streams (`:686`, `:707`). A transport has no way to write one. `Session`
(`:244`) carries the data directory, the host version, the protocol, and
the host's features, and nothing else. The frame writer is private.

**Why it matters for Matrix.** terva-conn-matrix sends `warn` for exactly
the things an operator has to act on:

- the bot cannot decrypt a room, which means it needs verifying or its
  recovery key restored (`src/matrix/inbound.rs:313`, rate-limited per
  room);
- a sync failure that is being retried (`src/matrix/mod.rs:439`);
- a dropped attachment or sticker (`src/matrix/media.rs:151`, `:203`).

rihma writes these to stderr. The host sends a child's stderr to
`$TERVA_HOME/logs/connector-<name>.log` (`proxy.go:166`, `:280`), which
is the right place for diagnostics. It is the wrong place for "your bot
can no longer read this room", which nobody reads until something is
already wrong.

**Proposal.** Add a field, filled in by `Serve` before `NewTransport` is
called (`:526`, used at `:606`):

```go
type Session struct {
	// ...
	// Warn sends an operational line to the host as a warn frame. Safe
	// from any goroutine; the host surfaces it beside its own notices.
	// Rate-limit anything a remote party can trigger.
	Warn func(message string)
}
```

The body is
`func(m string) { _ = w.write(connproto.WarnFromConn{Type: "warn", Message: m}) }`.
`frameWriter.write` already holds a mutex (`:971-981`), so it is safe to
call concurrently. No wire change, no host change, and an existing
transport ignores the field.

**Alternative considered.** An optional interface the transport implements
to receive a warn func, like `MessageIDSender`. It costs a type assertion
and a second way to learn about the session, for no gain over a field.

**Previous rihma workaround.** Operator-facing lines went only to the
stderr logger (`internal/connector/config.go`, `logger`). Now the UTD
limiter's report, sync retry notices, and media drops also go to
`Session.Warn`, and stderr keeps diagnostics. The library's
`OnSyncRetry` callback covers transient Connect and `/sync` failures.

## 2. Let a connector declare a protocol floor *(one field on `Config`)*

**The gap.** `Serve` sends `hello` with
`ProtocolMin: connproto.ProtocolVersion` (`:488`), which is 1, whatever
the connector supports. It accepts any `hello_ack` from 1 to
`ProtocolMax` (`:517`). A connector that is only correct at protocol 2
cannot say so.

**Why it matters for Matrix.** At protocol 1 connsdk downgrades an
inbound message by putting its own id in `reply_to` (`:651`), so what it
replies to is lost; `chat_kind` and `ts` are dropped (`:635-645`); and
the chat-event and membership streams do not run
(`:659`, `:691`). Edits, reactions, and asks all
need the real mapping between a Matrix event id and a host message id.
rihma declares `message_ids` and depends on it from P2 onward, so a
protocol-1 session would be quietly wrong rather than degraded.

**Proposal.**

```go
type Config struct {
	// ...
	// ProtocolMin is the oldest protocol this connector speaks correctly.
	// Zero means connproto.ProtocolVersion. Serve advertises it in hello
	// and refuses a hello_ack below it.
	ProtocolMin int
}
```

`Serve` advertises `max(cfg.ProtocolMin, connproto.ProtocolVersion)` at
`:488` and checks against it at `:517`. Because the floor goes out in
`hello`, a host older than the floor refuses the spawn during negotiation
(`connproto/connproto.go:19`), and says why, instead of reaching
`connect`.

**Previous rihma workaround.** `NewTransport` returned an error when
`Session.Protocol < 2` (`internal/connector/transport.go`, `minProtocol`).
connsdk reports that as a permanent `connect_error`. The outcome is
right, since the bridge does not start, but it arrives after a handshake
that claimed protocol 1 was fine. The message is rihma's, not a
negotiation failure the host can name. Now `Config.ProtocolMin: 2`
requires the floor during hello, before constructing a transport.

## 3. Let a connector add verbs to `Main` *(one field on `Config`)*

**The gap.** `Main` dispatches on the last argument: `run`, `setup`,
`status`, `reset`, and `configured` (`:416-455`). Anything else prints
usage and exits 2 (`:456-458`, usage at `:462-464`). The usage line is fixed to those five.

**Why it matters for Matrix.** An E2EE connector has operator tasks
outside those five. rihma has `verify`, which reports whether the bot's
device is cross-signed. P3 adds the recovery-key and verification flows.
terva-conn-matrix has the same shape. `terva bot` will not invoke these,
so an operator runs the connector binary directly, and the binary's own
usage line ought to list them.

**Proposal.**

```go
type Config struct {
	// ...
	// Verbs are extra operator verbs, dispatched by Main like the
	// built-in ones and listed in its usage. A name that collides with
	// a built-in verb is a programming error and Main panics on it.
	Verbs map[string]func() error
}
```

**Previous rihma workaround.** `cmd/terva-rihma/main.go` checked for `verify`
before calling `connsdk.Main`, reading the last argument the same way.
It works. The only costs are that the usage line omits `verify` and that
the two dispatchers must agree on argument handling. Now `Config.Verbs`
registers `verify`, and main delegates every verb to the SDK.

---

## Considered and not proposed

- **An exported fake host for tests.** connsdk exports no test harness,
  so rihma's live suite has its own (`e2e/host_test.go`): it spawns
  `run.sh` and speaks connproto over stdio. That copy is about 200 lines
  and tests the real process boundary, which an in-process harness would
  not. Worth raising only if a second Go connector wants the same thing.
- **A logger or state directory on `Session`.** rihma does not need
  either. `SealedState.Dir` gives the state directory, and stderr is the
  log.
