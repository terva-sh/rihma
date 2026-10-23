package rihma

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/event"
)

// Client is a mautrix client with E2EE, a pure-Go store, and rihma's
// sync discipline. The embedded *mautrix.Client is deliberately exposed:
// send, join, and query with it directly. Register event handlers on
// Handlers(), not by replacing Syncer. Preserve the installed RequestHook
// when adding HTTP instrumentation so request payloads stay out of logs, and
// do not replace SaveNewToken, which persists rotated OAuth tokens.
type Client struct {
	*mautrix.Client

	opts Options
	// sessionMu serializes every session write after Open, so a key-backup
	// save and an OAuth token rotation cannot overwrite each other.
	sessionMu sync.Mutex
	// session is as last saved; reads also take backup.mu. It is replaced,
	// never edited in place, and sits behind a pointer so that fmt, which
	// dereferences one pointer for a verb such as %s, cannot reach it from
	// a struct holding a *Client.
	session      *Session
	sessionSaved bool
	backup       backupState
	xsign        crossSigningState
	signed       signedIdentities
	db           *dbutil.Database
	helper       *cryptohelper.CryptoHelper
	managed      managedCryptoBackground
	syncer       *syncer
	utd          *utdLimiter

	connectOnce sync.Mutex
	connected   bool
	cryptoReady bool
	syncStarted bool
	sas         *SASController
	slidingMu   sync.RWMutex
	slidingView *SlidingSyncView
	asksOnce    sync.Once
	asks        *Asks
}

const storeFile = "rihma.db"

// Format prints the user and device, for every verb. Without it fmt would
// print the stored session, access token included, from the unexported
// fields.
func (c *Client) Format(f fmt.State, _ rune) {
	if c == nil || c.Client == nil {
		io.WriteString(f, "rihma.Client{}")
		return
	}
	fmt.Fprintf(f, "rihma.Client{UserID:%s DeviceID:%s}", c.UserID, c.DeviceID)
}

// Open returns a client for the stored session, or logs in with
// Options.Login, Options.OAuthLogin or Options.SSOLogin when there is none.
// Restoring a session touches no network; the first network use is Connect,
// which Sync calls. A stored session always wins: Open then ignores every
// login option, exchanges nothing and replaces no device.
func Open(ctx context.Context, opts Options) (*Client, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if opts.ManagedCryptoBackground && !supportsManagedCryptoBackground() {
		return nil, ErrManagedCryptoUnavailable
	}
	if err := requireGoolm(); err != nil {
		return nil, err
	}
	sess, err := opts.Sessions.Load(ctx)
	if err != nil {
		return nil, err
	}
	if sess == nil && opts.Login == nil && opts.OAuthLogin == nil && opts.SSOLogin == nil {
		return nil, ErrNoSession
	}
	// Check the binding only for a login that will be used: a stored session
	// wins, but an access token must never reach another homeserver.
	if sess == nil && opts.OAuthLogin != nil && !opts.OAuthLogin.boundTo(opts.Homeserver) {
		return nil, fmt.Errorf("%w: authorization belongs to another homeserver", ErrOAuthLogin)
	}
	login := opts.Login
	if sess == nil && opts.SSOLogin != nil {
		if !opts.SSOLogin.boundTo(opts.Homeserver) {
			return nil, fmt.Errorf("%w: token belongs to another homeserver", ErrSSOLogin)
		}
		token, ok := opts.SSOLogin.take()
		if !ok {
			return nil, fmt.Errorf("%w: token already used", ErrSSOLogin)
		}
		login = &mautrix.ReqLogin{Type: mautrix.AuthTypeToken, Token: token}
	}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("rihma: state dir: %w", err)
	}

	cli, err := mautrix.NewClient(opts.Homeserver, "", "")
	if err != nil {
		return nil, fmt.Errorf("rihma: %w", err)
	}
	// mautrix logs the signatures it makes and checks; drop those lines.
	cli.Log = opts.Logger.Hook(signatureLogFilter{})
	// mautrix can log ordinary message bodies, and its environment override
	// also enables sensitive request bodies. Omit diagnostic payloads before
	// each attempt without changing the request sent to the server.
	cli.RequestHook = func(req *http.Request) {
		*req = *req.WithContext(context.WithValue(req.Context(), mautrix.LogBodyContextKey, "<request content omitted>"))
	}
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
	c := &Client{Client: cli, opts: opts, db: db, helper: helper, syncer: s, session: &Session{}}
	cli.SaveNewToken = c.saveRefreshedTokens
	// The client keeps its own copy of Options; it needs no login option
	// after Open, so it keeps no password or token either.
	c.opts.Login, c.opts.OAuthLogin, c.opts.SSOLogin = nil, nil, nil
	c.backup.wake = make(chan struct{}, 1)
	c.utd = newUTDLimiter(opts.UTDWindow, opts.OnUTD)
	helper.DecryptErrorCallback = func(evt *event.Event, _ error) { c.utd.report(evt.RoomID) }

	if sess != nil {
		restored := sess.clone()
		c.session, c.sessionSaved = &restored, true
		if c.session.OAuth != nil {
			if err := c.restoreOAuth(); err != nil {
				c.Close()
				return nil, err
			}
		}
		if err := c.loadBackupKey(); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}

	// OAuth login saves the session as soon as the homeserver confirms the
	// device, then leaves crypto initialization to Connect, as for a
	// restored session, so a transient key query cannot orphan the device.
	if opts.OAuthLogin != nil {
		if err := c.loginOAuth(ctx, opts.OAuthLogin, pickleKey); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}

	// No session: log in now, then save before returning, so a crash
	// cannot leave a server-side device with no local record of it.
	req := *login
	if req.InitialDeviceDisplayName == "" {
		req.InitialDeviceDisplayName = opts.DeviceName
	}
	helper.LoginAs = &req
	if err := c.Connect(ctx); err != nil {
		c.Close()
		return nil, err
	}
	helper.LoginAs = nil
	err = c.writeSession(ctx, true, func(s *Session) error {
		*s = Session{UserID: cli.UserID, DeviceID: cli.DeviceID, AccessToken: cli.AccessToken, PickleKey: pickleKey}
		return nil
	})
	if err != nil {
		// Without a saved session the new device is unreachable; remove it.
		_, _ = cli.Logout(ctx)
		c.Close()
		return nil, err
	}
	return c, nil
}

// writeSession serializes an edit of the session. It saves the edited copy
// when the session is already stored, or when commit asks for the first
// save, and publishes it in memory only after the save succeeds.
func (c *Client) writeSession(ctx context.Context, commit bool, edit func(*Session) error) error {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	c.backup.mu.Lock()
	next := c.session.clone()
	c.backup.mu.Unlock()
	if err := edit(&next); err != nil {
		return err
	}
	if commit || c.sessionSaved {
		if err := c.opts.Sessions.Save(ctx, &next); err != nil {
			return err
		}
		c.sessionSaved = true
	}
	c.backup.mu.Lock()
	c.session = &next
	c.backup.mu.Unlock()
	return nil
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
	if !c.cryptoReady {
		if err := c.helper.Init(ctx); err != nil {
			return fmt.Errorf("rihma: crypto init: %w", err)
		}
		c.Crypto = c.helper
		if c.opts.SlidingSync != nil {
			c.StateStore = &slidingStateStore{StateStore: c.StateStore}
		}
		if c.opts.ManagedCryptoBackground {
			background, ok := any(c.helper.Machine()).(managedCryptoBackground)
			if !ok {
				return ErrManagedCryptoUnavailable
			}
			if err := background.EnableManagedBackground(context.Background()); err != nil {
				return err
			}
			c.managed = background
		}
		if c.opts.SyncJournal != nil {
			cursor := &stagedSyncStore{SyncStore: c.Client.Store}
			c.Client.Store = cursor
			c.syncer.journal, c.syncer.cursor, c.syncer.user = c.opts.SyncJournal, cursor, c.UserID
		}
		c.syncer.installHooks(c)
		c.cryptoReady = true
		// Stored cross-signing keys are loaded only while the server still
		// publishes them; a device that cannot sign still syncs.
		if err := c.loadCrossSigningSecrets(ctx, c.helper.Machine(), c.publishedCrossSigningKeys); err != nil {
			c.opts.Logger.Warn().Err(err).Msg("cannot load this device's cross-signing keys")
		}
		// Devices that adopted the backup before rihma shared it offer it now.
		c.backup.mu.Lock()
		key := c.backup.key
		c.backup.mu.Unlock()
		if key != nil {
			if err := storeBackupSecret(ctx, c.helper.Machine(), key); err != nil {
				c.opts.Logger.Warn().Err(err).Msg("cannot offer the backup key to verified devices")
			}
		}
	}
	if c.sas != nil {
		if err := c.sas.init(ctx); err != nil {
			return err
		}
	}
	c.connected = true
	return nil
}

// Handlers is where callers register sync handlers. It is the embedded
// mautrix DefaultSyncer, so handlers take mautrix types.
func (c *Client) Handlers() *mautrix.DefaultSyncer { return c.syncer.DefaultSyncer }

// Close releases the store. Call it only after Sync has returned.
func (c *Client) Close() error {
	if c.managed != nil {
		c.managed.StopManagedBackground()
		c.utd.stopAndWait()
	}
	if c.sas != nil {
		c.sas.stop()
	}
	c.Asks().Shutdown()
	c.utd.stop()
	return c.helper.Close()
}

// Logout ends the session: server-side logout first, then the stored
// session, then the state directory. If the server cannot be reached it
// returns the error and changes nothing locally, so the device is not
// orphaned. An already-invalid token counts as logged out. An OAuth session
// is ended by revoking its tokens at the issuer (MSC4254), not by /logout.
func (c *Client) Logout(ctx context.Context) error {
	c.sessionMu.Lock()
	delegated := c.session.OAuth != nil
	c.sessionMu.Unlock()
	if delegated {
		if err := c.Client.OAuthRevokeToken(ctx); err != nil {
			return oauthRevokeError(ctx, err)
		}
	} else if _, err := c.Client.Logout(ctx); err != nil && !errors.Is(err, mautrix.MUnknownToken) {
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

// Detect this optional capability without making ordinary module consumers
// require a fork. Go does not inherit a dependency's replace directives.
type managedCryptoBackground interface {
	EnableManagedBackground(context.Context) error
	StopManagedBackground()
}

func supportsManagedCryptoBackground() bool {
	_, ok := any((*crypto.OlmMachine)(nil)).(managedCryptoBackground)
	return ok
}

// fetchVersions reads /versions into a value the caller owns. The embedded
// mautrix Client.SpecVersions field is unsynchronized: Client.Versions writes
// it and many mautrix methods read it. rihma paths, which can run concurrently
// with each other and with the application, neither read nor write it.
//
// request carries the caller's retry, logging and size options; its method and
// URL are set here. A zero request uses the client's retries, logger and
// response limit, as Client.Versions did. A successful response that is not a
// JSON object of the /versions shape returns errVersionsMalformed, which names
// no content. This decode is mautrix's, and as lenient: Sliding Sync uses it.
// RTC discovery validates the raw body strictly instead (rtcAdvertised).
func (c *Client) fetchVersions(ctx context.Context, request mautrix.FullRequest) (*mautrix.RespVersions, error) {
	raw, err := c.getVersions(ctx, request)
	if err != nil {
		return nil, err
	}
	var versions mautrix.RespVersions
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) || json.Unmarshal(raw, &versions) != nil {
		return nil, errVersionsMalformed
	}
	return &versions, nil
}

// getVersions returns the raw /versions body; see fetchVersions.
func (c *Client) getVersions(ctx context.Context, request mautrix.FullRequest) ([]byte, error) {
	request.Method, request.URL, request.ResponseJSON = http.MethodGet, c.BuildClientURL("versions"), nil
	return c.MakeFullRequest(ctx, request)
}

var errVersionsMalformed = errors.New("rihma: invalid /versions response")

// oversizedSuccess reports a 2xx response whose body exceeded the request's
// size limit. An oversized error body keeps its HTTP status instead.
func oversizedSuccess(err error) bool {
	var failure mautrix.HTTPError
	return errors.As(err, &failure) && failure.Response != nil && failure.Response.StatusCode >= 200 && failure.Response.StatusCode < 300 &&
		(errors.Is(err, mautrix.ErrResponseTooLong) || errors.Is(err, mautrix.ErrBodyReadReachedLimit))
}
