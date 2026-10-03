package rihma

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Journal failure simulates a crash/failed durable write before materialization.
// A restart must still request the prior since token and see the missing batch.
func TestSyncJournalFailurePreservesCursorAndReplays(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	opts.Logger = zerolog.Nop()
	opts.SyncPolicy = SyncPolicyFullClient
	var mu sync.Mutex
	captured := 0
	opts.SyncJournal = func(ctx context.Context, resp *mautrix.RespSync, since string) error {
		mu.Lock()
		defer mu.Unlock()
		captured++
		if since != "" || resp.NextBatch != "batch-one" {
			t.Error("journal did not receive original response")
		}
		return errors.New("private journal error")
	}
	h.script(roomSync("batch-one", "!test:localhost", textEvent(testUser, "$event", "synthetic fixture")))
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal("open failed")
	}
	seen := 0
	c.Handlers().OnEventType(event.EventMessage, func(context.Context, *event.Event) { seen++ })
	if err := c.Sync(ctx); err != ErrSyncJournal {
		t.Fatal("journal error not sanitized")
	}
	if seen != 0 {
		t.Fatal("dispatch preceded durable capture")
	}
	if token, err := c.Store.LoadNextBatch(ctx, c.UserID); err != nil || token != "" {
		t.Fatal("failed journal advanced cursor")
	}
	c.Close()
	opts.Login = nil
	opts.SyncJournal = func(ctx context.Context, resp *mautrix.RespSync, since string) error {
		mu.Lock()
		defer mu.Unlock()
		captured++
		return nil
	}
	h.script(roomSync("batch-one", "!test:localhost", textEvent(testUser, "$event", "synthetic fixture")))
	c, err = Open(ctx, opts)
	if err != nil {
		t.Fatal("restart failed")
	}
	defer c.Close()
	received := make(chan struct{}, 1)
	c.Handlers().OnEventType(event.EventMessage, func(context.Context, *event.Event) { received <- struct{}{} })
	stop := runPolicySync(t, c)
	defer stop()
	<-received
	waitFor(t, "journal cursor committed", func() bool {
		token, err := c.Store.LoadNextBatch(ctx, c.UserID)
		return err == nil && token == "batch-one"
	})
	stop()
	if len(h.seenSinces()) < 2 || h.seenSinces()[1] != "" {
		t.Fatal("restart skipped failed batch")
	}
	mu.Lock()
	defer mu.Unlock()
	if captured != 2 {
		t.Fatal("missing replay capture")
	}
}
func TestSyncJournalRunsBeforeFilteringAndCursor(t *testing.T) {
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	opts.Logger = zerolog.Nop()
	var c *Client
	journaled := false
	opts.SyncJournal = func(ctx context.Context, resp *mautrix.RespSync, since string) error {
		if len(resp.Rooms.Join["!test:localhost"].Timeline.Events) != 2 {
			t.Error("journal saw filtered response")
		}
		if token, err := c.Store.LoadNextBatch(ctx, c.UserID); err != nil || token != "" {
			t.Error("journal followed committed cursor")
		}
		journaled = true
		return nil
	}
	h.script(roomSync("batch", "!test:localhost", memberEvent(testUser), textEvent(testUser, "$event", "synthetic fixture")))
	var err error
	c, err = Open(context.Background(), opts)
	if err != nil {
		t.Fatal("open failed")
	}
	defer c.Close()
	dispatched := false
	c.Handlers().OnEventType(event.StateMember, func(ctx context.Context, _ *event.Event) {
		if !journaled {
			t.Error("dispatch preceded journal")
		}
		if token, err := c.Store.LoadNextBatch(ctx, c.UserID); err != nil || token != "" {
			t.Error("cursor advanced before dispatch")
		}
		dispatched = true
	})
	c.Handlers().OnEventType(event.EventMessage, func(context.Context, *event.Event) { t.Error("journal changed bot filtering") })
	stop := runPolicySync(t, c)
	defer stop()
	waitFor(t, "journal sync cursor", func() bool {
		token, err := c.Store.LoadNextBatch(context.Background(), c.UserID)
		return err == nil && token == "batch"
	})
	stop()
	if !journaled || !dispatched {
		t.Fatal("journal or normal dispatch absent")
	}
}
func TestStagedSyncStoreCommitFailureAndCancellation(t *testing.T) {
	underlying := &failingCursorStore{SyncStore: mautrix.NewMemorySyncStore(), fail: true}
	s := &stagedSyncStore{SyncStore: underlying}
	ctx := context.Background()
	user := id.UserID("@fixture:localhost")
	if err := s.SaveNextBatch(ctx, user, "next"); err != nil {
		t.Fatal("stage failed")
	}
	if err := s.commit(ctx, user, "other"); err != ErrSyncCursor {
		t.Fatal("mismatched cursor committed")
	}
	if err := s.commit(ctx, user, "next"); err != ErrSyncCursor {
		t.Fatal("cursor failure not sanitized")
	}
	if token, _ := underlying.LoadNextBatch(ctx, user); token != "" {
		t.Fatal("failed commit changed cursor")
	}
	underlying.fail = false
	if err := s.commit(ctx, user, "next"); err != nil {
		t.Fatal("commit retry failed")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.SaveNextBatch(cancelled, user, "later"); err != context.Canceled {
		t.Fatal("stage ignored cancellation")
	}
	if token, _ := underlying.LoadNextBatch(ctx, user); token != "next" {
		t.Fatal("cancelled stage changed cursor")
	}
}

type failingCursorStore struct {
	mautrix.SyncStore
	fail bool
}

type cancellingCursorStore struct {
	mautrix.SyncStore
	cancel context.CancelFunc
}

func (s *cancellingCursorStore) SaveNextBatch(ctx context.Context, user id.UserID, token string) error {
	s.cancel()
	return ctx.Err()
}

func TestSyncJournalCursorFailureOrCancellationReplaysWholeLoop(t *testing.T) {
	for _, mode := range []string{"failure", "cancellation"} {
		t.Run(mode, func(t *testing.T) {
			h := newTestHS(t)
			opts := testOptions(t, h, t.TempDir())
			opts.Logger, opts.SyncPolicy = zerolog.Nop(), SyncPolicyFullClient
			captured := 0
			opts.SyncJournal = func(context.Context, *mautrix.RespSync, string) error { captured++; return nil }
			h.script(roomSync("replayed-batch", "!test:localhost", textEvent(testUser, "$event", "synthetic fixture")))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c, err := Open(ctx, opts)
			if err != nil {
				t.Fatal("open failed")
			}
			underlying := c.syncer.cursor.SyncStore
			if mode == "failure" {
				c.syncer.cursor.SyncStore = &failingCursorStore{SyncStore: underlying, fail: true}
			} else {
				c.syncer.cursor.SyncStore = &cancellingCursorStore{SyncStore: underlying, cancel: cancel}
			}
			dispatched := 0
			c.Handlers().OnEventType(event.EventMessage, func(context.Context, *event.Event) { dispatched++ })
			err = c.Sync(ctx)
			if mode == "failure" && !errors.Is(err, ErrSyncCursor) || mode == "cancellation" && !errors.Is(err, context.Canceled) {
				t.Fatal("cursor boundary error not preserved")
			}
			if captured != 1 || dispatched != 1 {
				t.Fatal("cursor failure did not follow capture and dispatch")
			}
			if token, err := underlying.LoadNextBatch(context.Background(), c.UserID); err != nil || token != "" {
				t.Fatal("failed final cursor advanced persistent since")
			}
			if err := c.Close(); err != nil {
				t.Fatal("close failed")
			}
			opts.Login = nil
			h.script(roomSync("replayed-batch", "!test:localhost", textEvent(testUser, "$event", "synthetic fixture")))
			c, err = Open(context.Background(), opts)
			if err != nil {
				t.Fatal("restart failed")
			}
			defer c.Close()
			seen := make(chan struct{}, 1)
			c.Handlers().OnEventType(event.EventMessage, func(context.Context, *event.Event) { seen <- struct{}{} })
			stop := runPolicySync(t, c)
			defer stop()
			select {
			case <-seen:
			case <-time.After(3 * time.Second):
				t.Fatal("restart skipped replay event")
			}
			waitFor(t, "replay final cursor", func() bool {
				token, err := c.Store.LoadNextBatch(context.Background(), c.UserID)
				return err == nil && token == "replayed-batch"
			})
			stop()
			if captured != 2 || len(h.seenSinces()) < 2 || h.seenSinces()[1] != "" {
				t.Fatal("whole loop did not replay failed window")
			}
		})
	}
}

func (f *failingCursorStore) SaveNextBatch(ctx context.Context, user id.UserID, token string) error {
	if f.fail {
		return errors.New("private cursor error")
	}
	return f.SyncStore.SaveNextBatch(ctx, user, token)
}
func TestSyncJournalDispatchFailureDoesNotCommit(t *testing.T) {
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	opts.Logger = zerolog.Nop()
	opts.SyncJournal = func(context.Context, *mautrix.RespSync, string) error { return nil }
	h.script(roomSync("bad-batch", "!test:localhost", memberEvent(testUser)))
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal("open failed")
	}
	defer c.Close()
	c.Handlers().OnEventType(event.StateMember, func(context.Context, *event.Event) { panic("synthetic handler failure") })
	if err := c.Sync(context.Background()); err == nil {
		t.Fatal("dispatch failure did not stop sync")
	}
	if token, err := c.Store.LoadNextBatch(context.Background(), c.UserID); err != nil || token != "" {
		t.Fatal("dispatch failure advanced cursor")
	}
}

func TestSyncJournalCancellationPreventsDispatchAndCursor(t *testing.T) {
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	opts.Logger = zerolog.Nop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts.SyncJournal = func(context.Context, *mautrix.RespSync, string) error { cancel(); return nil }
	h.script(roomSync("cancelled-batch", "!test:localhost", memberEvent(testUser)))
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal("open failed")
	}
	defer c.Close()
	c.Handlers().OnEventType(event.StateMember, func(context.Context, *event.Event) { t.Error("cancelled journal dispatched") })
	if err := c.Sync(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("journal ignored cancellation")
	}
	if token, err := c.Store.LoadNextBatch(context.Background(), c.UserID); err != nil || token != "" {
		t.Fatal("cancelled journal advanced cursor")
	}
}
func TestNilJournalPreservesNativeEarlyCursor(t *testing.T) {
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	opts.Logger = zerolog.Nop()
	h.script(roomSync("native-batch", "!test:localhost", memberEvent(testUser)))
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal("open failed")
	}
	defer c.Close()
	c.Handlers().OnEventType(event.StateMember, func(ctx context.Context, _ *event.Event) {
		if token, err := c.Store.LoadNextBatch(ctx, c.UserID); err != nil || token != "native-batch" {
			t.Error("nil journal changed native cursor timing")
		}
		panic("synthetic handler failure")
	})
	if err := c.Sync(context.Background()); err == nil {
		t.Fatal("handler panic did not stop native sync")
	}
	if token, err := c.Store.LoadNextBatch(context.Background(), c.UserID); err != nil || token != "native-batch" {
		t.Fatal("nil journal changed persistent native behavior")
	}
}
