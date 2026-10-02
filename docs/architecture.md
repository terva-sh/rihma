# Architecture

rihma is a library, `terva.sh/rihma`, and a terva connector built on it
in `internal/connector` (from P2). This document records the library as
settled in P1. The reasoning for each departure from the implementation
handoff's §5 sketch is in TKT-01M3T4DW4JXKTYHKH5B7G28BCP.

## The dependency rule

The root package imports mautrix-go and the SQLite driver, and nothing
from terva. `TestRootPackageKnowsNothingOfTerva` fails the build if it
ever does. Only `internal/connector` imports both rihma and connsdk.

## The API

```go
func Open(ctx context.Context, opts Options) (*Client, error)

type Options struct {
    Homeserver string
    StateDir   string            // rihma's alone: Logout removes it
    Sessions   SessionStore      // access token and pickle key
    Login      *mautrix.ReqLogin // used only when Sessions is empty
    DeviceName string
    Logger     zerolog.Logger
    OnUTD      func(roomID id.RoomID, count int)
    UTDWindow  time.Duration     // default one minute
}

type Client struct{ *mautrix.Client /* ... */ }

func (c *Client) Connect(ctx context.Context) error
func (c *Client) Sync(ctx context.Context) error
func (c *Client) Handlers() *mautrix.DefaultSyncer
func (c *Client) Close() error
func (c *Client) Logout(ctx context.Context) error

func (c *Client) CreateRecoveryKey(ctx context.Context, password string) (string, error)
func (c *Client) RestoreFromRecoveryKey(ctx context.Context, recoveryKey string) error
func (c *Client) HasCrossSigningIdentity(ctx context.Context) (bool, error)
func (c *Client) DeviceVerified(ctx context.Context) (bool, error)
func (c *Client) Verification(ctx context.Context) (Verdict, error) // Verified, Unverified, NoIdentity
func (c *Client) AwaitSAS(ctx context.Context, confirm func([]SASEmoji) bool) error
func (c *Client) OlmMachine() *crypto.OlmMachine
func (c *Client) DownloadMedia(ctx context.Context, msg *event.MessageEventContent, limit int64, w io.Writer) (int64, error)
func (c *Client) SendMedia(ctx context.Context, room id.RoomID, m Media) (id.EventID, error)

type SessionStore interface {
    Load(ctx context.Context) (*Session, error) // nil, nil when absent
    Save(ctx context.Context, s *Session) error
    Clear(ctx context.Context) error
}
type FileSessionStore struct{ Path string }
```

`*mautrix.Client` is embedded on purpose: callers send, join, and query
with mautrix directly. rihma adds setup and discipline, not a second API
over events.

## Lifecycle

1. **Open** loads the session. With one, it configures the client and
   opens the store, and makes no request, so a restart during a
   homeserver outage does not fail here. Without one it logs in with
   `Options.Login`, initializes encryption, and saves the session before
   returning; if the save fails it logs the new device out again.
2. **Connect** initializes end-to-end encryption. mautrix's cryptohelper
   always queries the server for this device's keys at this point, which
   is why it is not part of Open. It is idempotent, and Sync calls it.
3. **Register handlers** on `Handlers()` after Connect or before Sync.
   Encryption's own handlers are installed by Connect; application
   handlers see decrypted events.
4. **Sync** blocks until its context ends or a fatal error. Transient
   failures, in Connect or in `/sync`, back off from 1 s doubling to 60 s
   and reset on success. `M_UNKNOWN_TOKEN` is fatal and returned, so a
   supervisor's restart budget applies.
5. **Close** only after Sync has returned. Closing the store under a
   running sync fails with "database is closed".
6. **Logout** logs out on the server first. If the server cannot be
   reached it changes nothing locally, so the device is not orphaned.
   Then it clears the session and removes `StateDir`.

## Sync discipline

- **History is discarded once.** A sync with no `since` token has its
  non-state timeline events removed before any handler sees them. That
  happens only when no `next_batch` was ever stored: the first connect,
  or a lost store. The handoff proposed a marker file for the first
  connect; the token is the same signal without a second source of
  truth, and it also covers a lost store, where a marker would replay
  up to 50 delivered events per room.
- **State is always kept.** State events stay in the timeline, and to-
  device and invite events are untouched, so the state store and the
  crypto machine's membership tracking stay correct.
- **Downtime is recovered.** cryptohelper persists `next_batch` in the
  crypto store, so a restart resumes where it stopped.
- **Echoes are dropped.** Our own non-state timeline events never reach
  handlers.
- **One sync per device.** `Sync` holds an OS lock on
  `StateDir/sync.lock` and a second one, in any process, fails with
  `ErrSyncInProgress`. The server hands each to-device message to
  whichever sync asks first, so two syncs on one device split the room
  keys between them and both lose some.
- **Unable-to-decrypt is bounded.** `OnUTD` hears about the first
  failure in a room at once, then at most once per window, with a count.

## State on disk

| Path | What |
|---|---|
| `StateDir/rihma.db` | SQLite (modernc; ADR 0001): crypto store, state store, sync token |
| `StateDir/sync.lock` | held by the running `Sync`; empty |
| `SessionStore` (backup) | the key backup's private key and version, when this device has one |
| `SessionStore` | user id, device id, access token, pickle key; the connector seals it in `config.json` |

The pickle key encrypts the crypto store's secrets, so the database is
unreadable without the session store, and the session store is useless
without the database.

## Verification

`CreateRecoveryKey` refuses an account that already has a cross-signing
identity (`ErrIdentityExists`): replacing one breaks every existing
trust relationship. It creates secret storage and the cross-signing
keys, then signs this device. `RestoreFromRecoveryKey` fetches the keys
with the recovery key and signs this device.

`Verification` reads the verdict from the server. `NoIdentity` is kept
apart from `Unverified` because they want opposite fixes: an account
with no identity needs one created, and no emoji verification can help.

`AwaitSAS` answers one emoji verification started by another device of
the same account, through mautrix's `verificationhelper`. A request from
another user is declined. It runs its own sync, so it fails with
`ErrSyncInProgress` beside a running connector rather than splitting the
device's to-device traffic. The helper fires some callbacks while
holding its own lock, so the callbacks only post to a channel and one
goroutine makes every call back into it.

**Megolm key backup.** mautrix can read a key backup but has no
uploader, so rihma has one (`backup.go`), for parity with
terva-conn-matrix, whose matrix-sdk enables a backup together with
recovery.
- `EnableKeyBackup`, called after `CreateRecoveryKey`:
  - creates a backup version whose auth data is signed by the master key;
  - stores the backup's private key in secret storage as
    `m.megolm_backup.v1`, where Element looks for it;
  - keeps the key in the `Session`, so it survives restarts.

  It never replaces an existing backup (`ErrBackupExists`): that would
  orphan every key in it.
- `RestoreKeyBackup`, called after `RestoreFromRecoveryKey`:
  - reads the key back from secret storage;
  - verifies the latest version against it;
  - imports every key, then keeps uploading to that version.
- The uploader runs inside `Sync`. It wakes after each sync response and
  every 30 s, and uploads every stored room key not yet in the current
  version, 100 per request. That includes the inbound copies of the
  bot's own outbound sessions. It marks each key in the SQL store's
  backup-version column alone, so it cannot clobber a ratchet the sync
  loop moved meanwhile.
- If the server reports that the version changed, uploads stop with a
  warning. Adopting the new backup is the operator's call, through setup.

## Media

- **Download.** `DownloadMedia` streams a message's file into a writer,
  decrypting it when encrypted. It refuses a declared size over the
  limit before downloading, and stops with `ErrTooLarge` one byte past
  it, so an oversized file is never held whole. An encrypted file's hash
  is checked at the end; on any error the caller discards what it got.
- **Upload.** `SendMedia` encrypts the file when the room is encrypted
  and sends it with Matrix v1.10 captions: with a caption, `body` is the
  caption and `filename` the name.
- **The connector** downloads into the host's `data_dir` under a
  temporary name and renames it into place only when complete, because
  the host reads the path as soon as the frame arrives. A file that
  fails, for size, hash, or network, drops its message and leaves
  nothing behind. Names follow terva-conn-matrix: the event id, a dash,
  and the sanitized name's last 80 characters.

## Tests

| Level | Where | Runs |
|---|---|---|
| Unit | `*_test.go` | session store, UTD limiter, backoff, store pragmas, the goolm guard, the dependency rule |
| Hermetic | `client_test.go`, `verify_test.go` | mautrix's mockserver plus `/sync`, filter, logout, and account-data handlers: restore without network, discard, echo, warm resume, retries, fatal token, recovery create and restore |
| Live | `e2e_test.go` (tag `e2e`, `just e2e`) | the throwaway Synapse: encrypted round trip with ciphertext checked on the wire, discard then live then downtime, recovery key across two devices |
| Live, connector | `e2e/` (tag `e2e`, `just e2e`) | `terva-rihma` under a fake host, spawned through `run.sh`: group admission, mentions, and removal (plain, encrypted, and kicked while down), the DM round trip, the encrypted round trip with ciphertext on the wire and downtime recovery, setup never replacing an identity, restore by recovery key, emoji verification against another device (and a stranger's request declined), verify refusing to sync beside the connector, reset killing the token, edits, reactions, and deletes both ways (also across a restart), attachments both ways byte-exact, attachments refused for declared size, actual size, and altered ciphertext, the ask widget: seeds, attested answers, close with outcome, expiry, and threads: anchored and anchorless starts, sends, asks, and attachments into threads, inbound routing with root titles, and edits, reactions, and deletes carrying the thread id across a restart, and speaker profiles: nothing declared or sent while off, then name_only and full with an mxc avatar |
| Release | `testing/release/verify.sh` (`just release-snapshot`, CI) | the linux/amd64 archive: its contents, a cgo-free goolm binary, and run.sh saying hello at connector.json's version with no Go on PATH |
