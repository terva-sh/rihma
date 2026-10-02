package rihma

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/event"
)

// Client is a mautrix client with E2EE, a pure-Go store, and rihma's
// sync discipline. The embedded *mautrix.Client is deliberately exposed:
// send, join, and query with it directly. Register event handlers on
// Handlers(), not by replacing Syncer.
type Client struct {
	*mautrix.Client

	opts    Options
	session Session // as last saved
	backup  backupState
	db      *dbutil.Database
	helper  *cryptohelper.CryptoHelper
	syncer  *syncer
	utd     *utdLimiter

	connectOnce sync.Mutex
	connected   bool
}

const storeFile = "rihma.db"

// Open returns a client for the stored session, or logs in with
// Options.Login when there is none. Restoring a session touches no
// network; the first network use is Connect, which Sync calls.
func Open(ctx context.Context, opts Options) (*Client, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if err := requireGoolm(); err != nil {
		return nil, err
	}
	sess, err := opts.Sessions.Load(ctx)
	if err != nil {
		return nil, err
	}
	if sess == nil && opts.Login == nil {
		return nil, ErrNoSession
	}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("rihma: state dir: %w", err)
	}

	cli, err := mautrix.NewClient(opts.Homeserver, "", "")
	if err != nil {
		return nil, fmt.Errorf("rihma: %w", err)
	}
	cli.Log = opts.Logger
	s := newSyncer()
	s.onRetry = opts.OnSyncRetry
	cli.Syncer = s

	var pickleKey []byte
	if sess != nil {
		cli.UserID, cli.DeviceID, cli.AccessToken = sess.UserID, sess.DeviceID, sess.AccessToken
		pickleKey = sess.PickleKey
	} else {
		pickleKey = make([]byte, 32)
		if _, err := rand.Read(pickleKey); err != nil {
			return nil, fmt.Errorf("rihma: pickle key: %w", err)
		}
	}

	db, err := openStore(ctx, filepath.Join(opts.StateDir, storeFile))
	if err != nil {
		return nil, err
	}
	helper, err := cryptohelper.NewCryptoHelper(cli, pickleKey, db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("rihma: crypto: %w", err)
	}
	c := &Client{Client: cli, opts: opts, db: db, helper: helper, syncer: s}
	c.backup.wake = make(chan struct{}, 1)
	c.utd = newUTDLimiter(opts.UTDWindow, opts.OnUTD)
	helper.DecryptErrorCallback = func(evt *event.Event, _ error) { c.utd.report(evt.RoomID) }

	if sess != nil {
		c.session = *sess
		if err := c.loadBackupKey(); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}

	// No session: log in now, then save before returning, so a crash
	// cannot leave a server-side device with no local record of it.
	login := *opts.Login
	if login.InitialDeviceDisplayName == "" {
		login.InitialDeviceDisplayName = opts.DeviceName
	}
	helper.LoginAs = &login
	if err := c.Connect(ctx); err != nil {
		c.Close()
		return nil, err
	}
	helper.LoginAs = nil
	c.session = Session{UserID: cli.UserID, DeviceID: cli.DeviceID, AccessToken: cli.AccessToken, PickleKey: pickleKey}
	if err := opts.Sessions.Save(ctx, &c.session); err != nil {
		// Without a saved session the new device is unreachable; remove it.
		_, _ = cli.Logout(ctx)
		c.Close()
		return nil, err
	}
	return c, nil
}

// Connect initializes end-to-end encryption, which queries the server
// for this device's keys (and logs in, on Open's fresh-login path). It
// is idempotent. Sync calls it, retrying transient failures, so callers
// only need it to send encrypted messages before syncing.
func (c *Client) Connect(ctx context.Context) error {
	c.connectOnce.Lock()
	defer c.connectOnce.Unlock()
	if c.connected {
		return nil
	}
	if err := c.helper.Init(ctx); err != nil {
		return fmt.Errorf("rihma: crypto init: %w", err)
	}
	c.Crypto = c.helper
	c.syncer.installHooks(c)
	c.connected = true
	return nil
}

// Handlers is where callers register sync handlers. It is the embedded
// mautrix DefaultSyncer, so handlers take mautrix types.
func (c *Client) Handlers() *mautrix.DefaultSyncer { return c.syncer.DefaultSyncer }

// Close releases the store. Call it only after Sync has returned.
func (c *Client) Close() error {
	c.utd.stop()
	return c.helper.Close()
}

// Logout ends the session: server-side logout first, then the stored
// session, then the state directory. If the server cannot be reached it
// returns the error and changes nothing locally, so the device is not
// orphaned. An already-invalid token counts as logged out.
func (c *Client) Logout(ctx context.Context) error {
	if _, err := c.Client.Logout(ctx); err != nil && !errors.Is(err, mautrix.MUnknownToken) {
		return fmt.Errorf("rihma: logout: %w", err)
	}
	if err := c.opts.Sessions.Clear(ctx); err != nil {
		return err
	}
	closeErr := c.Close()
	if err := os.RemoveAll(c.opts.StateDir); err != nil {
		return fmt.Errorf("rihma: remove state dir: %w", err)
	}
	return closeErr
}
