package rihma

import (
	"errors"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

// Options configures Open.
type Options struct {
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
	// DeviceName is the display name given to a new device at login.
	DeviceName string
	// Logger receives rihma's and mautrix's logs. It never receives
	// tokens, keys, or message content from rihma.
	Logger zerolog.Logger
	// OnUTD, if set, is told about events that could not be decrypted,
	// at most once per room per UTDWindow; count is how many failed.
	OnUTD func(roomID id.RoomID, count int)
	// UTDWindow is the burst window for OnUTD. Zero means one minute.
	UTDWindow time.Duration
	// OnSyncRetry, if set, is called before retrying a transient Connect
	// or /sync failure. It runs on the sync goroutine and must not block.
	// A persistent outage may call it repeatedly; callers should rate-limit
	// operator notices. Fatal errors and cancellation do not call it.
	OnSyncRetry func()
}

// ErrNoSession is returned by Open when there is no stored session and
// Options.Login is nil.
var ErrNoSession = errors.New("rihma: no stored session and no login given")

func (o *Options) validate() error {
	switch {
	case o.Homeserver == "":
		return errors.New("rihma: Options.Homeserver is required")
	case o.StateDir == "":
		return errors.New("rihma: Options.StateDir is required")
	case o.Sessions == nil:
		return errors.New("rihma: Options.Sessions is required")
	}
	if o.UTDWindow == 0 {
		o.UTDWindow = time.Minute
	}
	return nil
}
