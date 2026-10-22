# QR verification trust on failure

Same-account QR verification changes trust before it finishes. The
device that scans a code signs as soon as the code's keys match, and the
displaying device signs when its person confirms the scan. A wrong
shared secret, a failed send or a cancellation after either step leaves
those signatures where they are, on the device and on the server. This
page records what the pinned mautrix v0.31.0 `verificationhelper` leaves
behind in each case, why most of it is what the Matrix specification
asks for, and the contract the QR controller in
[QR verification groundwork](qr-verification.md) must publish so that an
application never reads `cancelled` as "nothing happened".

`qr_reciprocation_test.go` pins every outcome below on mautrix's mock
server, with fresh devices and in-memory stores, scanning through
rihma's private `scanQR` admission. A mautrix upgrade that changes one
fails there. `qr_reciprocation_e2e_test.go` repeats the cases whose
published result matters on the disposable Synapse in
`testing/synapse/`, and reads the signatures back with `keys/query`.
Neither records a QR payload, a shared secret or a signature value; the
tests compare key ids only.

## The two same-account modes

The displaying device chooses the mode from whether it trusts the
account's master key.

| | Trusted display (mode 1) | Untrusted display, "reverse" (mode 2) |
| --- | --- | --- |
| Code carries | The master key, and the scanner's device key as the display knows it | The display's device key, and the master key as the display knows it |
| Scanner needs | The cached master public key | Its own signature on the master key, and the self-signing private key |
| Scanner, once the keys match | Signs the master key with its device key and uploads it | Marks the display's device verified, then cross-signs it with the self-signing key and uploads it |
| Display, at confirmation | Marks the scanner verified, then cross-signs it if it holds the self-signing key | Marks the scanner verified and signs the master key with its device key |
| Display needs | Its own signature on the master key; the self-signing private key, see below | Nothing beyond the cached master public key |

"Local" trust below is what a device's crypto store holds: its own
signature on the master key, a peer device marked verified, and a
self-signing signature on a peer device. A device marked verified is
trusted by that device for encryption whatever its signatures say.
"Published" trust is what the server lists for other devices to read.
Upstream uploads a signature before it stores it locally, so a signature
is published at least as soon as it is local.

## Measured outcomes

Each row starts from a code the display showed for an active
transaction, scanned through `scanQR`.

| Outcome | Scanner, local | Published | Display, local | Protocol result |
| --- | --- | --- | --- | --- |
| Success, mode 1 | Master signed at scan | Master signature at scan; scanner cross-signed at confirmation | Scanner verified and cross-signed at confirmation | Both `done` |
| Success, mode 2 | Display verified and cross-signed at scan | Display cross-signed at scan; master signature by the display at confirmation | Master signed, scanner verified, at confirmation | Both `done` |
| Wrong shared secret, mode 1 | Master signed | Master signature | Nothing | Display cancels `m.key_mismatch`; never offers confirmation |
| Wrong shared secret, mode 2 | Display verified and cross-signed | Display cross-signed | Nothing | Display cancels `m.key_mismatch` |
| Reciprocation send fails | Master signed | Master signature | Nothing | Scanner's call errors, nothing is cancelled, the transaction stays ready; scanning the same code again signs again and completes |
| Scanner's `done` send fails | Master signed | Master signature; scanner cross-signed if the display confirms | Scanner verified and cross-signed if the display confirms | The scanner rejects the display's `done` as unexpected; both end cancelled holding full trust |
| Display's `done` send fails | Unchanged | Scanner cross-signed | Scanner verified and cross-signed | Display's call errors and stays in the scanned state; confirming again signs again and completes |
| Scanner's signature upload refused | Nothing | Nothing | Nothing | Scanner cancels with an internal error |
| Upload accepted, response lost | Nothing | Master signature | Nothing | Scanner cancels; the server keeps a signature the scanner does not know about |
| Display cancels after the scan | Master signed | Master signature | Nothing | Both cancelled |
| Scanner cancels before scanning | Nothing | Nothing | Nothing | Scanning the stale code finds no transaction and changes nothing |
| Mode 2, scanner trusts the master but lacks the self-signing key | Display marked verified | Nothing | Nothing | Scanner cancels with an internal error after marking the device |
| Mode 2, scanner does not trust the master | Nothing | Nothing | Nothing | Scanner cancels `com.beeper.master_key_not_trusted` |
| Mode 1, display trusts the master but lacks the self-signing key | Master signed | Master signature by both devices; the scanner is never cross-signed | Scanner verified | Both `done`; the scanner's verdict stays `Unverified` |

The live suite confirms on Synapse that the scanner's master signature
is published after a wrong secret, after a display cancellation and
before a failed reciprocation is retried; that mode 2 publishes the
display's cross-signature before the display confirms, also after a
wrong secret; and that a trusted display without the self-signing key
finishes with the scanner `Unverified`. The refused, missing-trust and
missing-key cases publish nothing because the client never sends an
upload; the hermetic recorder shows no request leaving the device.

## What is expected and what is not

Signing at scan time is the protocol, not a race. The specification's
QR flow says that once the scanning device has checked the keys in the
code it "has now verified" the other device's key, and that a shared
secret that does not match "does not affect" that verification. The
secret proves to the displaying device that its own code was scanned;
it protects the display's trust, not the scanner's. So the wrong-secret,
cancellation and send-failure rows are expected protocol trust
ordering. The scanner's trust rests on the person scanning the right
screen, exactly as it does on success, and none of these rows is a
security defect.

Three behaviors are not ordering, and rihma must work around them:

1. **A trusted display without the self-signing key finishes without
   signing the scanner.** `ConfirmQRCodeScanned` chooses what to sign by
   whether the device holds private cross-signing keys, not by the code's
   mode. A mode 1 display without them signs the master key again
   instead of the scanner's device, then sends `done`, and
   `generateQRCode` offers mode 1 without checking for the key. A device
   is in exactly this state after it is verified by QR or SAS and before
   it fetches the cross-signing keys, so this is the common case for a
   second verification, not a corner. The result under-trusts rather
   than over-trusts: the scanner trusts the master and is trusted by the
   display, but no other device trusts it.
2. **Mode 2 marks the device before checking it can sign.**
   `HandleScannedQRData` stores the display's device as verified, then
   calls `SignOwnDevice`, which fails without the self-signing key. The
   helper cancels the attempt, and the mark stays in the scanner's store. The
   scanner did verify the key, so the mark is not wrong, but the
   verification reports failure while leaving trust behind.
3. **A failed send leaves the transaction ready.** Neither
   `HandleScannedQRData` nor `ConfirmQRCodeScanned` saves its new state
   before sending. On the display that makes confirmation retryable. On
   the scanner, a retry after a failed `done` sends a second
   reciprocation, which the display cancels, and an arriving `done`
   cancels a verification whose signatures both sides have already
   published.

None needs an upstream change before rihma can ship QR. The contract
below avoids each by checking before it calls the helper. They
are worth reporting upstream with the other `verificationhelper`
findings, and when a fix lands the matching test fails so that the
workaround can be removed in the same change.

## Production contract

This is the state and error contract for the opt-in QR controller. It
extends the proposal in [QR verification groundwork](qr-verification.md)
and keeps the existing SAS states, reasons and errors.

### Preflight before the helper

The controller checks these on its own goroutine, from public keys only,
and returns the error without calling the helper or sending anything:

- **`ShowQR` in mode 1** requires this device to hold the self-signing
  private key. Without it the controller does not offer a code:
  readiness reports QR display unavailable, and `ShowQR` returns
  `ErrNoCrossSigningKeys`. Offer SAS or scanning instead, or run
  `RequestCrossSigningKeys` or `RestoreFromRecoveryKey` first. Mode 2
  display needs no private key.
- **`ScanQR`** runs today's `scanQR` admission, then compares the code's
  keys with what this device expects, as upstream would. A code with
  wrong keys returns `ErrQRKeyMismatch` with no trust changed, and the
  controller cancels the attempt with `m.key_mismatch`, as the
  specification asks. Mode 0 codes are cross-user and return
  `ErrQRInvalid` until cross-user QR is designed.
- **`ScanQR` of a mode 2 code** requires this device's own signature on
  the master key and the self-signing private key. Without the signature
  it returns `ErrMasterKeyNotTrusted`; without the key it returns
  `ErrNoCrossSigningKeys`. Neither leaves the local mark of outcome 2.

`ErrQRInvalid` is today's private `errInvalidQRScan`, made public, for
malformed codes and codes naming another transaction.
`ErrQRKeyMismatch` and `ErrMasterKeyNotTrusted` are new. The preflight cannot see the shared
secret; only the display can check it.

### States

QR adds `showing_qr` and `qr_scanned` to the existing states and reuses
`confirmed`, which already means "local agreement was sent; only done
means the protocol completed".

| State | Side | Meaning |
| --- | --- | --- |
| `showing_qr` | Display | `ShowQR` may hand the code to the application |
| `confirmed` | Scanner | The keys matched, this device signed, and the reciprocation and `done` were sent |
| `qr_scanned` | Display | The peer sent the right secret; the person must confirm with `ConfirmQRScanned` or `Cancel` |
| `confirmed` | Display | This device signed the peer and sent `done` |
| `done` | Both | Both `done` messages were exchanged |

### Trust is reported apart from the result

The general verification snapshot gains `TrustChanged bool`. The
controller sets it when it calls the helper for a scan that passed
preflight, and when `ConfirmQRScanned` reaches the helper. It stays set through `cancelled`
and `failed` for that transaction. It means "this device may have signed
or marked keys, and may have published signatures, during this
attempt". It is a conservative flag rather than a measurement, because
a lost upload response can publish a signature the device never stores.

- `cancelled` or `failed` with `TrustChanged` false: no trust changed.
- `cancelled` or `failed` with `TrustChanged` true: trust may have
  changed and nothing undoes it. Read `Client.Verification` and the
  account's devices to see where it landed.
- `done`: the protocol completed. It is not by itself a claim that this
  device is cross-signed. Query `Client.Verification`, as for SAS.

A wrong secret reaches the scanner as the peer's `m.key_mismatch`
cancellation, so the scanner shows `cancelled` with reason `mismatch`
and `TrustChanged` true. On the display it is `cancelled`, reason
`mismatch`, `TrustChanged` false.

### Failed sends

- **`ScanQR` fails after the helper ran** (a failed upload or send): the
  controller returns `ErrSASOperation`, cancels the attempt, dismisses
  the helper's transaction, and publishes `failed` with reason
  `operation_failed` and `TrustChanged` true. It does not offer a rescan.
  Whether a rescan is safe depends on which send failed (outcome 3), and
  only upstream's error text says which.
- **`ConfirmQRScanned` fails:** it returns `ErrSASOperation`, the state
  stays `qr_scanned` with `TrustChanged` true, and the application may
  call `ConfirmQRScanned` again or `Cancel`. A retry repeats the same
  signature on the same key, and the measured retry completes.

### Cancellation

`Cancel` in `showing_qr`, or before `ScanQR`, changes no trust. After a
scan or a confirmation it cancels the protocol and leaves every
signature already made. rihma does not promise to roll back a published
signature. The client-server API has no call that withdraws one; only
replacing the cross-signing identity discards it.

### Secrets

Snapshots, errors, logs and `Changed` notifications carry no QR bytes,
shared secrets, signatures or private keys, as the groundwork requires.
The preflight reads public keys from the parsed code and the crypto
store, and logs at most the transaction id, the mode and the fixed
error.

## Implementation order

The groundwork planned to add reverse mode only after its key and trust
prerequisites were proved. `TestUpstreamQRReverseModeCompletes` and
`TestE2EQRReverseModeVerifiesDisplay` prove them, and the mode 2 scan
preflight above enforces them, so the controller can ship both
same-account modes in one change. Mode 1 needs its display preflight
in that change too, because without it a second verification finishes
with the scanner unverified.
