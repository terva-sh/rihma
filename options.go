package rihma

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

// SyncPolicy selects which timeline events reach handlers. It is fixed when
// Open constructs the Client; it does not change sync or crypto ownership.
type SyncPolicy uint8

const (
	// SyncPolicyBot is the zero value. It drops initial non-state history
	// and self-sent non-state events, preserving connector behavior.
	SyncPolicyBot SyncPolicy = iota
	// SyncPolicyFullClient preserves initial history and self-sent events,
	// including another device on the same account, in joined/left timelines.
	// Applications reconcile their own send echoes by transaction/event ID.
	SyncPolicyFullClient
)

// ErrInvalidSyncPolicy is returned before Open accesses storage or the network.
var ErrInvalidSyncPolicy = errors.New("rihma: unsupported sync policy")

// ErrManagedCryptoUnavailable means the selected mautrix module lacks the
// optional managed worker API. Open refuses opt-in before storage or network use.
var ErrManagedCryptoUnavailable = errors.New("rihma: managed crypto background unavailable in dependency")

// Options configures Open.
type Options struct {
	// ManagedCryptoBackground opts into cancellation and joining of dependency
	// crypto workers before Sync returns. It requires managed-background support
	// in mautrix and makes the Client/Sync single-use. Restore a fresh Client
	// after stopping. Open returns ErrManagedCryptoUnavailable on an unpatched
	// dependency. The application must select the public fork replacement in its
	// root go.mod; dependency replacements are not inherited by consumers.
	// The default retains existing bot background behavior.
	ManagedCryptoBackground bool
	// SyncPolicy controls timeline filtering. The default is SyncPolicyBot.
	// Both policies retain state/to-device processing and crypto-aware sync.
	SyncPolicy SyncPolicy
	// SlidingSync selects an explicit opt-in transport; nil retains classic Sync.
	SlidingSync *SlidingSyncOptions
	// SlidingSyncJournal captures full raw sliding responses before dispatch.
	// It cannot be combined with the classic SyncJournal.
	SlidingSyncJournal SlidingSyncJournal
	// SyncJournal, when set, durably captures each raw response before timeline
	// filtering/crypto dispatch and before its cursor is committed. The callback
	// runs on the sync owner and must honor cancellation, bound writes, and return
	// only after its durable commit. It must not mutate or retain the response;
	// copy/encode required fields synchronously. Responses may contain secrets.
	// The caller owns journal protection, replay and idempotent materialization.
	// Failure stops Sync with ErrSyncJournal without advancing the cursor.
	// Nil preserves the native early-cursor bot behavior.
	SyncJournal func(context.Context, *mautrix.RespSync, string) error
	// Homeserver is the client-server API base URL.
	Homeserver string
	// StateDir holds the SQLite store. It must belong to rihma alone:
	// Logout removes it.
	StateDir string
	// Sessions persists the access token and pickle key.
	Sessions SessionStore
	// Login is used only when Sessions holds no session. Open then logs
	// in, which touches the network, and saves the new session.
	Login *mautrix.ReqLogin
	// OAuthLogin is an accepted delegated OAuth authorization. Like Login,
	// it is used only when Sessions holds no session; Open then exchanges
	// its code, confirms the device and saves the session, including the
	// refresh token, before returning. It cannot be combined with Login. When
	// it is used, it must come from DiscoverOAuth on this Homeserver; Open
	// checks that before any request. It is single-use.
	OAuthLogin *OAuthLogin
	// DeviceName is the display name given to a new device at classic
	// login. An OAuth device is named by the issuer, usually after the
	// registered client name.
	DeviceName string
	// Logger receives rihma's and mautrix's logs. It never receives
	// tokens, keys, or message content from rihma. HTTP diagnostic request
	// bodies are omitted at every log level, including sensitive-log overrides.
	Logger zerolog.Logger
	// OnUTD, if set, is told about events that could not be decrypted,
	// at most once per room per UTDWindow; count is how many failed.
	OnUTD func(roomID id.RoomID, count int)
	// UTDWindow is the burst window for OnUTD. Zero means one minute.
	UTDWindow time.Duration
	// OnSyncRetry, if set, is called before retrying a transient Connect,
	// filter creation, or /sync failure. It runs on the sync goroutine and
	// must not block.
	// A persistent outage may call it repeatedly; callers should rate-limit
	// operator notices. Fatal errors and cancellation do not call it.
	OnSyncRetry func()
}

// ErrNoSession is returned by Open when there is no stored session and
// Options.Login is nil.
var ErrNoSession = errors.New("rihma: no stored session and no login given")

func (o *Options) validate() error {
	if o.SlidingSync != nil {
		if o.SyncJournal != nil {
			return ErrSlidingUnsupported
		}
		copy, err := o.SlidingSync.copied()
		if err != nil {
			return err
		}
		o.SlidingSync = copy
	} else if o.SlidingSyncJournal != nil {
		return ErrSlidingUnsupported
	}
	if o.SyncPolicy != SyncPolicyBot && o.SyncPolicy != SyncPolicyFullClient {
		return ErrInvalidSyncPolicy
	}
	switch {
	case o.Homeserver == "":
		return errors.New("rihma: Options.Homeserver is required")
	case o.StateDir == "":
		return errors.New("rihma: Options.StateDir is required")
	case o.Sessions == nil:
		return errors.New("rihma: Options.Sessions is required")
	case o.Login != nil && o.OAuthLogin != nil:
		return errors.New("rihma: Options.Login and Options.OAuthLogin are exclusive")
	}
	if o.UTDWindow == 0 {
		o.UTDWindow = time.Minute
	}
	return nil
}
