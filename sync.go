package rihma

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

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
		filterSync(resp, c.UserID, since == "")
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

// Sync connects if needed and runs the sync loop until ctx ends or a
// fatal error: an invalid access token (M_UNKNOWN_TOKEN, matched by
// errors.Is) or a store failure. Transient failures, including during
// Connect, are retried with backoff. It resumes from the stored
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
	for n := 1; ; n++ {
		err := c.Connect(ctx)
		if err == nil {
			break
		}
		if errors.Is(err, mautrix.MUnknownToken) || ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		c.opts.Logger.Warn().Err(err).Int("attempt", n).Msg("connect failed; retrying")
		if c.opts.OnSyncRetry != nil {
			c.opts.OnSyncRetry()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff(n)):
		}
	}
	// The uploader stops with the sync loop however it ends, and Sync
	// waits for it, so Close never races an upload.
	upCtx, stopUploads := context.WithCancel(ctx)
	uploads := make(chan struct{})
	go func() { defer close(uploads); c.runBackupUploads(upCtx) }()
	defer func() { stopUploads(); <-uploads }()
	return c.SyncWithContext(ctx)
}
