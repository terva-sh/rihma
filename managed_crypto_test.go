package rihma

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func TestManagedCryptoSyncJoinsRealMissingSessionWorker(t *testing.T) {
	if !supportsManagedCryptoBackground() {
		t.Skip("requires the explicit managed mautrix candidate modfile")
	}
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	opts.Logger, opts.SyncPolicy, opts.ManagedCryptoBackground = zerolog.Nop(), SyncPolicyFullClient, true
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal("open failed")
	}
	defer c.Close()
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal("connect failed")
	}
	// A nonempty since token selects the helper's asynchronous missing-key path.
	if err := c.Store.SaveNextBatch(context.Background(), c.UserID, "prior"); err != nil {
		t.Fatal("cursor fixture failed")
	}
	e := &event.Event{ID: "$missing", Type: event.EventEncrypted, Sender: "@other:example.invalid", RoomID: "!test:localhost", Content: event.Content{Parsed: &event.EncryptedEventContent{Algorithm: id.AlgorithmMegolmV1, SenderKey: "synthetic-key", SessionID: id.SessionID(strings.Repeat("A", 43)), MegolmCiphertext: []byte(strings.Repeat("A", 100))}}}
	h.script(roomSync("next", "!test:localhost", e))
	dispatched, entered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	c.Handlers().OnEventType(event.EventEncrypted, func(context.Context, *event.Event) { close(dispatched) })
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	c.helper.DecryptErrorCallback = func(*event.Event, error) { close(entered); <-release }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Sync(ctx) }()
	select {
	case <-dispatched:
	case <-time.After(3 * time.Second):
		t.Fatal("encrypted event not dispatched")
	}
	cancel()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("missing-session worker did not reach cancellation callback")
	}
	select {
	case <-done:
		t.Fatal("Sync returned beneath a live dependency worker")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker not joined")
	}
	scheduler := any(c.OlmMachine()).(interface {
		GoBackground(context.Context, func(context.Context)) bool
	})
	if scheduler.GoBackground(context.Background(), func(context.Context) { t.Error("late work ran") }) {
		t.Fatal("worker admitted after Sync")
	}
	if err := c.Sync(context.Background()); err == nil {
		t.Fatal("single-use managed client restarted")
	}
}

func TestManagedCryptoUnavailableFailsBeforeSideEffects(t *testing.T) {
	if supportsManagedCryptoBackground() {
		t.Skip("unmodified dependency gate covered by default module checks")
	}
	opts := Options{ManagedCryptoBackground: true, Homeserver: "https://example.invalid", StateDir: filepath.Join(t.TempDir(), "state"), Sessions: rejectManagedSessionAccess{}}
	if _, err := Open(context.Background(), opts); !errors.Is(err, ErrManagedCryptoUnavailable) {
		t.Fatal("unsupported opt-in did not fail before loading a session")
	}
	if _, err := os.Stat(opts.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsupported opt-in created state")
	}
}

type rejectManagedSessionAccess struct{ SessionStore }

func (rejectManagedSessionAccess) Load(context.Context) (*Session, error) {
	panic("unsupported managed option accessed sessions")
}

func TestManagedCryptoExtendedWaitKeepsCallerCancellation(t *testing.T) {
	if !supportsManagedCryptoBackground() {
		t.Skip("requires explicit managed mautrix dependency")
	}
	h := newTestHS(t)
	started, cancelled := make(chan struct{}), make(chan struct{})
	var onceStart, onceCancel sync.Once
	inner := h.ms.Server.Config.Handler
	h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sendToDevice/m.room_key_request/") {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
			onceStart.Do(func() { close(started) })
			<-r.Context().Done()
			onceCancel.Do(func() { close(cancelled) })
			return
		}
		inner.ServeHTTP(w, r)
	})
	opts := testOptions(t, h, t.TempDir())
	opts.Logger, opts.ManagedCryptoBackground = zerolog.Nop(), true
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal("open failed")
	}
	defer c.Close()
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal("connect failed")
	}
	caller, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := context.WithValue(caller, mautrix.SyncTokenContextKey, "prior")
	e := &event.Event{ID: "$missing", Type: event.EventEncrypted, Sender: "@other:example.invalid", RoomID: "!test:localhost", Content: event.Content{Parsed: &event.EncryptedEventContent{Algorithm: id.AlgorithmMegolmV1, SenderKey: "synthetic-key", SessionID: id.SessionID(strings.Repeat("A", 43)), MegolmCiphertext: []byte(strings.Repeat("A", 100))}}}
	c.helper.HandleEncrypted(ctx, e)
	// The initial wait must finish normally and hand off to the extended wait.
	select {
	case <-started:
	case <-time.After(7 * time.Second):
		t.Fatal("normal parent completion cancelled extended key request")
	}
	cancel()
	// Cancel the caller only, without stopping the machine lifetime or sync.
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("key request ignored caller cancellation")
	}
}
