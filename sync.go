package rihma

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"

	"sync/atomic"
	"time"

	"go.mau.fi/util/retryafter"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	backoffMin = time.Second
	backoffMax = time.Minute
)

// syncer is mautrix's DefaultSyncer with capped exponential backoff in
// place of its flat ten-second retry. Embedding keeps it an
// ExtensibleSyncer and DispatchableSyncer, which cryptohelper needs.
type syncer struct {
	*mautrix.DefaultSyncer
	failures atomic.Int32
	onRetry  func()
	journal  func(context.Context, *mautrix.RespSync, string) error
	cursor   *stagedSyncStore
	user     id.UserID
}

func newSyncer() *syncer {
	return &syncer{DefaultSyncer: mautrix.NewDefaultSyncer()}
}

// OnFailedSync stops on an invalid token, which retrying cannot fix,
// and otherwise waits 1 s, 2 s, 4 s ... up to a minute.
func (s *syncer) OnFailedSync(_ *mautrix.RespSync, err error) (time.Duration, error) {
	if errors.Is(err, mautrix.MUnknownToken) {
		return 0, err
	}
	if s.onRetry != nil {
		s.onRetry()
	}
	return backoff(int(s.failures.Add(1))), nil
}

// backoff returns the wait after the nth consecutive failure, from 1.
func backoff(n int) time.Duration {
	d := backoffMin
	for i := 1; i < n && d < backoffMax; i++ {
		d *= 2
	}
	return min(d, backoffMax)
}

// installHooks runs once, after cryptohelper has registered its own
// handlers. OnSync hooks all run before any event is dispatched, so
// filtering the response here hides events from every event handler.
func (s *syncer) installHooks(c *Client) {
	s.OnSync(func(ctx context.Context, resp *mautrix.RespSync, since string) bool {
		s.failures.Store(0)
		if c.opts.SyncPolicy == SyncPolicyBot {
			filterSync(resp, c.UserID, since == "")
		}
		// Hooks run before events are dispatched, so a room key in this
		// response may be stored just after the uploader looks; the next
		// response or the uploader's timer picks it up.
		c.wakeBackup()
		return true
	})
}

// filterSync removes our own non-state timeline events (echo hygiene)
// and, when discardHistory is set, every non-state timeline event.
// State events stay: the state store and the crypto machine's
// membership tracking read them from the timeline too. Invites and
// to-device events are untouched.
//
// discardHistory is set when the sync had no since token, which happens
// only when no next_batch was ever stored: the first connect, or a lost
// store. Either way the timeline is history, not news.
func filterSync(resp *mautrix.RespSync, self id.UserID, discardHistory bool) {
	keep := func(evts []*event.Event) []*event.Event {
		out := evts[:0]
		for _, evt := range evts {
			if evt.StateKey != nil || (!discardHistory && evt.Sender != self) {
				out = append(out, evt)
			}
		}
		return out
	}
	for _, room := range resp.Rooms.Join {
		room.Timeline.Events = keep(room.Timeline.Events)
	}
	for _, room := range resp.Rooms.Leave {
		room.Timeline.Events = keep(room.Timeline.Events)
	}
}

// Sync connects if needed and runs the crypto-aware sync loop, delivering
// timeline events according to Options.SyncPolicy, until ctx ends or a
// fatal error: an invalid access token (M_UNKNOWN_TOKEN, matched by
// errors.Is) or a store failure. Transient failures, including during
// Connect and filter creation, are retried with backoff. It resumes from the stored
// next_batch, so messages sent while the program was down are delivered.
// On cancellation it returns ctx.Err(). Call Close only after it returns.
//
// Only one Sync may run on a state directory at a time, across processes;
// a second returns ErrSyncInProgress at once.
func (c *Client) Sync(ctx context.Context) error {
	unlock, err := lockSync(c.opts.StateDir)
	if err != nil {
		return err
	}
	defer unlock()
	c.connectOnce.Lock()
	if c.opts.ManagedCryptoBackground && c.syncStarted {
		c.connectOnce.Unlock()
		return errors.New("rihma: managed crypto client must be restored after stopping")
	}
	c.syncStarted = true
	c.connectOnce.Unlock()
	for n := 1; ; n++ {
		err := c.Connect(ctx)
		if err == nil {
			break
		}
		if errors.Is(err, mautrix.MUnknownToken) || ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		delay, retry := startupRetryDelay(err, n)
		if !retry {
			return err
		}
		c.opts.Logger.Warn().Err(err).Int("attempt", n).Msg("connect failed; retrying")
		if c.opts.OnSyncRetry != nil {
			c.opts.OnSyncRetry()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	if c.managed != nil {
		defer c.managed.StopManagedBackground()
		defer c.utd.stopAndWait()
	}
	if c.sas != nil {
		if err := c.sas.start(ctx); err != nil {
			return err
		}
		defer c.sas.stop()
	}
	// Prepare the filter while the SAS lifecycle is already owned, so a failed
	// bootstrap also stops the verification controller before stores close.
	originalStore := c.Store
	defer func() { c.Store = originalStore }()
	if err := c.prepareSyncFilter(ctx); err != nil {
		return err
	}
	// The uploader stops with the sync loop however it ends, and Sync
	// waits for it, so Close never races an upload.
	upCtx, stopUploads := context.WithCancel(ctx)
	uploads := make(chan struct{})
	go func() { defer close(uploads); c.runBackupUploads(upCtx) }()
	defer func() { stopUploads(); <-uploads }()
	return c.SyncWithContext(ctx)
}

// prepareSyncFilter retries only the network step. Store errors must escape
// without retrying, and the enclosing Sync holds the device's sync lock.
func (c *Client) prepareSyncFilter(ctx context.Context) error {
	// SQLCryptoStore intentionally does not retain filter IDs. Cache one for
	// this Sync invocation so mautrix uses the filter just created here.
	store := c.Store
	c.Store = &readyFilterStore{SyncStore: store}
	filterID, err := c.Store.LoadFilterID(ctx, c.UserID)
	if err != nil || filterID != "" {
		return err
	}
	filter := c.syncer.GetFilterJSON(c.UserID)
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		resp, err := c.CreateFilter(ctx, filter)
		if err == nil {
			if resp == nil || resp.FilterID == "" {
				return errors.New("rihma: server returned an empty sync filter ID")
			}
			return c.Store.SaveFilterID(ctx, c.UserID, resp.FilterID)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		delay, retry := startupRetryDelay(err, attempt)
		if !retry {
			return err
		}
		if c.opts.OnSyncRetry != nil {
			c.opts.OnSyncRetry()
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// startupRetryDelay retries temporary server/rate-limit/timeout statuses
// and transport failures, while leaving permanent HTTP errors fatal. A server's
// Retry-After can extend the ordinary capped backoff.
func startupRetryDelay(err error, attempt int) (time.Duration, bool) {
	if errors.Is(err, mautrix.MUnknownToken) {
		return 0, false
	}
	delay := backoff(attempt)
	var httpErr mautrix.HTTPError
	if errors.As(err, &httpErr) && httpErr.Response != nil {
		if retryafter.Should(httpErr.Response.StatusCode, true) || httpErr.IsStatus(http.StatusInternalServerError) || httpErr.IsStatus(http.StatusRequestTimeout) {
			return max(delay, retryafter.Parse(httpErr.Response.Header.Get("Retry-After"), delay)), true
		}
		return 0, false
	}
	var netErr net.Error
	if errors.As(err, &netErr) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return delay, true
	}
	return 0, false
}

// readyFilterStore retains the bootstrap filter only for this Sync call.
// The underlying store still owns next_batch and any durable filter storage.
type readyFilterStore struct {
	mautrix.SyncStore
	filterID string
}

func (s *readyFilterStore) LoadFilterID(ctx context.Context, user id.UserID) (string, error) {
	if s.filterID != "" {
		return s.filterID, nil
	}
	return s.SyncStore.LoadFilterID(ctx, user)
}
func (s *readyFilterStore) SaveFilterID(ctx context.Context, user id.UserID, filterID string) error {
	if err := s.SyncStore.SaveFilterID(ctx, user, filterID); err != nil {
		return err
	}
	s.filterID = filterID
	return nil
}
