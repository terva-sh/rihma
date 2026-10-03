package rihma

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/mockserver"
)

// testHS is mautrix's mockserver plus the endpoints it lacks (/sync,
// filter, logout), behind a middleware that counts requests and can
// fail chosen paths.
type testHS struct {
	ms       *mockserver.MockServer
	requests atomic.Int32
	filters  atomic.Int32

	mu     sync.Mutex
	fail   map[string]int // path suffix -> remaining failures
	syncs  []func(since string) *mautrix.RespSync
	sinces []string
}

func newTestHS(t *testing.T) *testHS {
	h := &testHS{ms: mockserver.Create(t), fail: map[string]int{}}
	h.ms.Router.HandleFunc("GET /_matrix/client/v3/sync", h.sync)
	h.ms.Router.HandleFunc("POST /_matrix/client/v3/user/{userID}/filter", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"filter_id":"1"}`))
	})
	h.ms.Router.HandleFunc("POST /_matrix/client/v3/logout", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{}`))
	})
	h.ms.Router.HandleFunc("GET /_matrix/client/v3/user/{userID}/account_data/{type}", func(w http.ResponseWriter, r *http.Request) {
		data, ok := h.ms.AccountData[id.UserID(r.PathValue("userID"))][event.Type{Type: r.PathValue("type"), Class: event.AccountDataEventType}]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errcode":"M_NOT_FOUND","error":"no such account data"}`))
			return
		}
		w.Write(data)
	})
	inner := h.ms.Router
	h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.requests.Add(1)
		if strings.HasSuffix(r.URL.Path, "/filter") {
			h.filters.Add(1)
		}
		h.mu.Lock()
		for suffix, n := range h.fail {
			if n > 0 && strings.HasSuffix(r.URL.Path, suffix) {
				h.fail[suffix] = n - 1
				h.mu.Unlock()
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"injected"}`))
				return
			}
		}
		h.mu.Unlock()
		inner.ServeHTTP(w, r)
	})
	return h
}

func (h *testHS) failNext(suffix string, n int) {
	h.mu.Lock()
	h.fail[suffix] = n
	h.mu.Unlock()
}

// sync answers with the next scripted response, or holds the long poll
// until the client gives up once the script is spent.
func (h *testHS) sync(w http.ResponseWriter, r *http.Request) {
	since := r.URL.Query().Get("since")
	h.mu.Lock()
	h.sinces = append(h.sinces, since)
	var next func(string) *mautrix.RespSync
	if len(h.syncs) > 0 {
		next, h.syncs = h.syncs[0], h.syncs[1:]
	}
	h.mu.Unlock()
	if next == nil {
		<-r.Context().Done()
		return
	}
	json.NewEncoder(w).Encode(next(since))
}

func (h *testHS) script(fs ...func(since string) *mautrix.RespSync) {
	h.mu.Lock()
	h.syncs = append(h.syncs, fs...)
	h.mu.Unlock()
}

func (h *testHS) seenSinces() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.sinces...)
}

const testUser = id.UserID("@bot:localhost")

func testOptions(t *testing.T, h *testHS, dir string) Options {
	return Options{
		Homeserver: h.ms.Server.URL,
		StateDir:   filepath.Join(dir, "state"),
		Sessions:   FileSessionStore{Path: filepath.Join(dir, "session.json")},
		Login: &mautrix.ReqLogin{
			Type:       mautrix.AuthTypePassword,
			Identifier: mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: testUser.String()},
			Password:   "pw",
		},
		Logger: zerolog.New(zerolog.NewTestWriter(t)).Level(zerolog.WarnLevel),
	}
}

func textEvent(sender id.UserID, evtID id.EventID, body string) *event.Event {
	return &event.Event{
		Type: event.EventMessage, Sender: sender, ID: evtID,
		Content: event.Content{VeryRaw: json.RawMessage(`{"msgtype":"m.text","body":"` + body + `"}`)},
	}
}

func memberEvent(user id.UserID) *event.Event {
	key := user.String()
	return &event.Event{
		Type: event.StateMember, Sender: user, ID: id.EventID("$member-" + key), StateKey: &key,
		Content: event.Content{VeryRaw: json.RawMessage(`{"membership":"join"}`)},
	}
}

func roomSync(batch string, room id.RoomID, evts ...*event.Event) func(string) *mautrix.RespSync {
	return func(string) *mautrix.RespSync {
		resp := &mautrix.RespSync{NextBatch: batch}
		resp.Rooms.Join = map[id.RoomID]*mautrix.SyncJoinedRoom{room: {}}
		resp.Rooms.Join[room].Timeline.Events = evts
		return resp
	}
}

func TestOpenRequiresSessionOrLogin(t *testing.T) {
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	opts.Login = nil
	if _, err := Open(context.Background(), opts); !errors.Is(err, ErrNoSession) {
		t.Fatalf("Open = %v, want ErrNoSession", err)
	}
}

// TestOpenLoginThenRestore logs in once, then reopens the saved session
// and checks the reopen made no request at all.
func TestOpenLoginThenRestore(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	dir := t.TempDir()
	opts := testOptions(t, h, dir)

	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if c.UserID != testUser || c.DeviceID == "" || c.Crypto == nil {
		t.Fatalf("after login: user %q device %q crypto %v", c.UserID, c.DeviceID, c.Crypto != nil)
	}
	device := c.DeviceID
	c.Close()

	sess, err := opts.Sessions.Load(ctx)
	if err != nil || sess == nil {
		t.Fatalf("saved session = %v, %v", sess, err)
	}
	if sess.UserID != testUser || sess.DeviceID != device || sess.AccessToken == "" || len(sess.PickleKey) != 32 {
		t.Fatalf("saved session incomplete: user %q device %q token %t pickle %d bytes",
			sess.UserID, sess.DeviceID, sess.AccessToken != "", len(sess.PickleKey))
	}

	opts.Login = nil
	before := h.requests.Load()
	c, err = Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if n := h.requests.Load() - before; n != 0 {
		t.Fatalf("restoring a session made %d requests, want 0", n)
	}
	if c.DeviceID != device {
		t.Fatalf("restored device %q, want %q", c.DeviceID, device)
	}
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect on restored session: %v", err)
	}
}

// runSync starts Sync and returns a stop function that cancels it and
// waits for it to return, reporting its error.
func runSync(t *testing.T, c *Client) (stop func() error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Sync(ctx) }()
	return func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("Sync did not return after cancel")
			return nil
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type seen struct {
	mu   sync.Mutex
	msgs []string
	mems []string
}

func (s *seen) messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.msgs...)
}
func (s *seen) members() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.mems...)
}

func watch(c *Client) *seen {
	s := &seen{}
	c.Handlers().OnEventType(event.EventMessage, func(_ context.Context, evt *event.Event) {
		s.mu.Lock()
		s.msgs = append(s.msgs, evt.Content.AsMessage().Body)
		s.mu.Unlock()
	})
	c.Handlers().OnEventType(event.StateMember, func(_ context.Context, evt *event.Event) {
		s.mu.Lock()
		s.mems = append(s.mems, evt.GetStateKey())
		s.mu.Unlock()
	})
	return s
}

// TestSyncDiscardEchoAndWarmResume covers the sync discipline end to
// end: the first sync's history is hidden but its state kept, later
// messages arrive, our own do not, and a reopened client resumes from
// the stored token and delivers what arrived while it was down.
func TestSyncDiscardEchoAndWarmResume(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	dir := t.TempDir()
	opts := testOptions(t, h, dir)
	const room = id.RoomID("!room:localhost")
	other := id.UserID("@human:localhost")

	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	s := watch(c)
	h.script(
		roomSync("b1", room, memberEvent(other), textEvent(other, "$old", "history")),
		roomSync("b2", room, textEvent(other, "$new", "news"), textEvent(testUser, "$mine", "echo")),
	)
	stop := runSync(t, c)
	waitFor(t, "the second sync", func() bool { return len(s.messages()) > 0 })
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sync returned %v, want context.Canceled", err)
	}
	c.Close()

	if got := s.messages(); len(got) != 1 || got[0] != "news" {
		t.Fatalf("messages delivered = %q, want only [news]: history discarded, echo dropped", got)
	}
	if got := s.members(); len(got) != 1 || got[0] != other.String() {
		t.Fatalf("member events delivered = %q, want the first sync's state kept", got)
	}

	// Warm restart: a message sent while down must arrive.
	opts.Login = nil
	c, err = Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s = watch(c)
	h.script(roomSync("b3", room, textEvent(other, "$down", "while down")))
	stop = runSync(t, c)
	waitFor(t, "the downtime message", func() bool { return len(s.messages()) > 0 })
	stop()
	if got := s.messages(); len(got) != 1 || got[0] != "while down" {
		t.Fatalf("after warm restart delivered %q, want [while down]", got)
	}
	sinces := h.seenSinces()
	if sinces[0] != "" || sinces[len(sinces)-2] != "b2" {
		t.Fatalf("since tokens = %q: want a first sync with none and a resume from b2", sinces)
	}
}

func TestSyncUnknownTokenIsFatal(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	c, err := Open(ctx, testOptions(t, h, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/sync") {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"errcode":"M_UNKNOWN_TOKEN","error":"Invalid access token"}`))
			return
		}
		h.ms.Router.ServeHTTP(w, r)
	})
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.Sync(ctx); !errors.Is(err, mautrix.MUnknownToken) {
		t.Fatalf("Sync = %v, want M_UNKNOWN_TOKEN", err)
	}
}

// TestSyncRetriesTransientFailures fails the keys query that Connect
// makes and the first /sync, and checks Sync recovers from both.
func TestSyncRetriesTransientFailures(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	var retries atomic.Int32
	opts.OnSyncRetry = func() { retries.Add(1) }
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	opts.Login = nil
	c, err = Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	h.failNext("/keys/query", 1)
	h.failNext("/sync", 1)
	s := watch(c)
	const room = id.RoomID("!room:localhost")
	h.script(
		roomSync("b1", room),
		roomSync("b2", room, textEvent("@human:localhost", "$x", "after retries")),
	)
	stop := runSync(t, c)
	waitFor(t, "a message after both retries", func() bool { return len(s.messages()) > 0 })
	stop()
	if got := retries.Load(); got != 2 {
		t.Fatalf("retry notifications = %d, want one for Connect and one for /sync", got)
	}
}

func TestLogoutClearsEverything(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	dir := t.TempDir()
	opts := testOptions(t, h, dir)
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	if sess, err := opts.Sessions.Load(ctx); err != nil || sess != nil {
		t.Fatalf("session after Logout = %v, %v", sess, err)
	}
	if _, err := os.Stat(opts.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state dir after Logout: %v", err)
	}
}
