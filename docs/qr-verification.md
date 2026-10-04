# QR verification groundwork

QR verification is not yet exposed by the production controller. The dependency
proof uses mautrix's helpers on two disposable devices through ordinary rihma
`Sync`, without a second sync loop or any copied protocol implementation.
It proves a trusted device displaying a code, an untrusted device scanning it,
wrong-master-key rejection without trust changes, reciprocation, display-side
confirmation and completed device trust. This is interactive Matrix verification,
separate from QR device authorization/login.

## Upstream APIs and trust

Pinned mautrix v0.31.0 enables QR show/scan through `NewVerificationHelper` options
and QR callbacks. `VerificationReady` reports scan support and a generated code;
`HandleScannedQRData` parses a scanned code and sends reciprocation/done;
`QRCodeScanned` requests display-side confirmation; `ConfirmQRCodeScanned` sends
the display-side done. Callbacks can run before a transaction save while holding
the helper lock, so they must enqueue without re-entering it.

Both peers must advertise reciprocation. A display requires the other peer's scan
support and cached master public identity. Same-account modes depend on whether
the displaying device trusts that master. A trusted display encodes the master
and scanner device keys; an untrusted display encodes its own device and master
keys. Scanning verifies the relevant keys; scanning an untrusted display also
requires the scanner to trust the master and possess the self-signing key when
cross-signing the displayed device. Cross-user codes require a trusted own master
and both users' cached identities, and remain outside the first increment.

Scanning a valid trusted-display code signs the master before the display side
confirms completion. The live proof measures this local master-trust signature;
it does not confuse it with `Client.Verification == Verified`, which additionally
needs the device's cross-signature. Errors or cancellation after signing cannot
be promised to undo an already-published signature. The wrong-key regression
fails before that signing step. Wrong shared secrets and send-failure timing need
their own failure characterization before a public QR completion contract is set.

The upstream QR decoder has a reproduced malformed-length panic: transaction
length arithmetic remains `uint16` and can wrap before its slice bounds check.
No public controller currently accepts scanned QR data. A private scan adapter
now rejects malformed input before invoking the helper: at most 2953 payload
bytes (the maximum binary QR capacity), a nonempty transaction ID of at most
256 bytes, version 2, modes 0–2, both keys and at least eight secret bytes.
These size bounds are admission policy, not Matrix protocol limits. Lengths are
converted to `int` before checking remaining space, and the encoded transaction
must match the caller-selected active transaction exactly. The caller must keep
input stable throughout admission and helper use. Helper errors become a fixed error without private details. The live dependency
proof uses this boundary; fuzz tests exercise it with the upstream decoder.

Retain the guard while the pinned v0.31.0 decoder remains vulnerable. No upstream
fix or dependency upgrade is included here. The dependency should still use
checked integer arithmetic; importing the parser does not validate untrusted
scan input. The future controller must serialize admission and supply its current
active transaction and manage private buffer lifetimes with the transaction store:
upstream retains the parsed shared-secret slice in its start-event state. Clearing
it immediately after a scan would corrupt retained protocol state. This guard
does not promise to clear retained secrets or undo admitted trust/network effects.

## Proposed compatible controller

Introduce an opt-in `EnableVerification(VerificationOptions)` before first Sync,
with SAS, QR show and QR scan capabilities configured once. Keep `EnableSAS` and
its return/snapshot types compatible through aliases or a shared implementation;
its default remains SAS-only with automatic outgoing SAS startup. The bot
`AwaitSAS` wrapper retains its SAS-only contract. General verification uses the
same helper, event gate, one active transaction, attempt budget and command owner.

General readiness publishes only capability flags and peer/transaction metadata.
It does not start SAS automatically when the application has enabled QR method
choice. Proposed operations are explicit `ChooseSAS`, `ShowQR`, `ScanQR` and
`ConfirmQRScanned`, alongside existing request/accept/cancel commands. A ready
state precedes method choice, showing_qr allows display, and qr_scanned requires
explicit display-side confirmation. Only protocol done means completion.

`ShowQR(ctx, txn, consume)` hands a private byte copy to an explicit transient
consumer on the caller's goroutine, then clears that owned copy. It must not run
the consumer on the syncer or command owner. `ScanQR(ctx, txn, data)` copies a
bounded input, validates format/size/transaction binding before any helper call,
and clears its owned copy on success, failure, cancelled admission and shutdown.
The application must not retain, persist or log either payload. These operations
are proposed interfaces, not APIs available in this release.

Snapshots, Changed notifications, errors and logs contain no QR bytes, shared
secrets or signing keys. Private command results must be drained/cleared when a
caller abandons them. Start/scan/display commands carry current transaction IDs;
stale IDs or wrong method states fail before network/crypto changes. Payloads from
another transaction cannot select it implicitly. Cancellation and overflow clear
pending adapter data and dismiss transactions; shutdown quiesces handlers and
commands before clearing private buffers and closing stores. Caller or controller
cancellation is not a guarantee that earlier protocol/trust effects were undone.

## Remaining implementation

The public controller adapter, upstream parser fix,
trust timing on failed sends/wrong secrets, the reverse same-account trust mode,
cross-user verification and QR device authorization/login have separate follow-ups.
QR images/cameras, browser/device authorization and recovery are application
integrations with distinct consent and secret lifetimes. This proof does not
advertise them as implemented library capabilities.
