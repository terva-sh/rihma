package rihma

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
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

func slidingTestOptions() *SlidingSyncOptions {
	return &SlidingSyncOptions{Dialect: SlidingSyncSynapseExperimental, Lists: map[string]SlidingSyncList{"recent": {Ranges: []SlidingSyncRange{{0, 9}}, TimelineLimit: 10}}}
}
func slidingTestResponse(pos, td string, room id.RoomID, events ...*event.Event) []byte {
	body := map[string]any{"pos": pos, "lists": map[string]any{"recent": map[string]any{"count": 1, "ops": []any{map[string]any{"op": "SYNC", "range": []int{0, 9}, "room_ids": []id.RoomID{room}}}}},
		"rooms":      map[id.RoomID]any{room: map[string]any{"initial": true, "required_state": []*event.Event{memberEvent(testUser)}, "timeline": events, "prev_batch": "pagination-test"}},
		"extensions": map[string]any{"to_device": map[string]any{"next_batch": td, "events": []any{}}, "e2ee": map[string]any{"device_one_time_keys_count": map[string]int{"signed_curve25519": 1000}, "device_unused_fallback_key_types": []any{}}}, "unknown_top": map[string]any{"preserved": true}}
	raw, _ := json.Marshal(body)
	return raw
}

type slidingSeen struct{ position, device, connection string }
type slidingTestServer struct {
	*testHS
	mu          sync.Mutex
	responses   [][]byte
	seen        []slidingSeen
	expire      bool
	unsupported bool
}

func newSlidingTestServer(t *testing.T) *slidingTestServer {
	h := &slidingTestServer{testHS: newTestHS(t)}
	inner := h.ms.Server.Config.Handler
	h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_matrix/client/versions" {
			h.mu.Lock()
			unsupported := h.unsupported
			h.mu.Unlock()
			if unsupported {
				_, _ = w.Write([]byte(`{"versions":["v1.11"],"unstable_features":{}}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"versions":["v1.11"],"unstable_features":{"org.matrix.simplified_msc3575":true}}`))
			return
		}
		if r.URL.Path != "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync" {
			inner.ServeHTTP(w, r)
			return
		}
		var body struct {
			Connection string `json:"conn_id"`
			Extensions struct {
				ToDevice struct {
					Since string `json:"since"`
				} `json:"to_device"`
			} `json:"extensions"`
			Lists map[string]struct {
				State [][2]string `json:"required_state"`
			} `json:"lists"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Lists["recent"].State) != 1 || body.Lists["recent"].State[0] != [2]string{"*", "*"} {
			w.WriteHeader(400)
			return
		}
		h.mu.Lock()
		h.seen = append(h.seen, slidingSeen{r.URL.Query().Get("pos"), body.Extensions.ToDevice.Since, body.Connection})
		var raw []byte
		expired := h.expire
		h.expire = false
		if !expired && len(h.responses) > 0 {
			raw, h.responses = h.responses[0], h.responses[1:]
		}
		h.mu.Unlock()
		if expired {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"errcode":"M_UNKNOWN_POS","error":"fixture expired"}`))
			return
		}
		if raw == nil {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	})
	return h
}
func (h *slidingTestServer) enqueue(raw ...[]byte) {
	h.mu.Lock()
	h.responses = append(h.responses, raw...)
	h.mu.Unlock()
}
func (h *slidingTestServer) requestsCopy() []slidingSeen {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]slidingSeen(nil), h.seen...)
}

func TestSlidingRecoveryBeforeHTTPAndIndependentCursors(t *testing.T) {
	h := newSlidingTestServer(t)
	room := id.RoomID("!sliding:localhost")
	opts := testOptions(t, h.testHS, t.TempDir())
	opts.Logger = zerolog.Nop()
	opts.SyncPolicy = SyncPolicyFullClient
	opts.SlidingSync = slidingTestOptions()
	raw := slidingTestResponse("p-one", "td-one", room, textEvent(testUser, "$first", "private fixture payload"))
	h.enqueue(raw)
	opts.SlidingSyncJournal = func(ctx context.Context, batch *SlidingSyncBatch) error {
		if !bytes.Equal(batch.Raw, raw) || batch.Previous != (SlidingSyncCursor{}) {
			t.Error("journal was filtered or cursor advanced")
		}
		return errors.New("private application failure")
	}
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal("open failed")
	}
	c.Handlers().OnEventType(event.EventMessage, func(context.Context, *event.Event) { t.Error("failed journal dispatched") })
	if err = c.Sync(context.Background()); err != ErrSyncJournal {
		t.Fatal("journal failure not sanitized")
	}
	if token, err := c.Store.LoadNextBatch(context.Background(), c.UserID); err != nil || token != "" {
		t.Fatal("sliding changed classic cursor")
	}
	_ = c.Close()
	// Committed pending ciphertext must not expose response plaintext in DB/WAL.
	for _, name := range []string{"sliding.db", "sliding.db-wal"} {
		data, _ := os.ReadFile(filepath.Join(opts.StateDir, name))
		if bytes.Contains(data, []byte("private fixture payload")) || bytes.Contains(data, []byte("td-one")) {
			t.Fatal("unprotected recovery data written")
		}
	}
	opts.Login = nil
	journaled := 0
	opts.SlidingSyncJournal = func(ctx context.Context, batch *SlidingSyncBatch) error {
		journaled++
		if journaled == 1 && (len(h.requestsCopy()) != 1 || batch.Next.ToDevice != "td-one" || !bytes.Equal(batch.Raw, raw)) {
			t.Error("pending response not replayed before HTTP")
		}
		return nil
	}
	h.enqueue(slidingTestResponse("p-two", "td-two", room))
	c, err = Open(context.Background(), opts)
	if err != nil {
		t.Fatal("restore failed")
	}
	defer c.Close()
	seen := make(chan struct{}, 1)
	c.Handlers().OnEventType(event.EventMessage, func(context.Context, *event.Event) { seen <- struct{}{} })
	stop := runPolicySync(t, c)
	defer stop()
	waitFor(t, "sliding continuation", func() bool { return len(h.requestsCopy()) >= 3 })
	stop()
	select {
	case <-seen:
	default:
		t.Fatal("pending event not replayed")
	}
	requests := h.requestsCopy()
	if requests[1].position != "p-one" || requests[1].device != "td-one" || requests[2].position != "p-two" || requests[2].device != "td-two" {
		t.Fatal("independent cursor tuple did not commit")
	}
	view := c.SlidingSyncSnapshot()
	if view == nil || view.Counts["recent"] != 1 || view.Lists["recent"][0] != room {
		t.Fatal("room list not materialized")
	}
	view.Lists["recent"][0] = "!changed:localhost"
	if c.SlidingSyncSnapshot().Lists["recent"][0] != room {
		t.Fatal("snapshot aliases owner state")
	}
}

func TestSlidingConfigurationResetKeepsToDevice(t *testing.T) {
	h := newSlidingTestServer(t)
	room := id.RoomID("!sliding:localhost")
	opts := testOptions(t, h.testHS, t.TempDir())
	opts.Logger = zerolog.Nop()
	opts.SyncPolicy = SyncPolicyFullClient
	opts.SlidingSync = slidingTestOptions()
	h.enqueue(slidingTestResponse("p-one", "td-one", room))
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal("open failed")
	}
	stop := runPolicySync(t, c)
	waitFor(t, "first sliding commit", func() bool { return len(h.requestsCopy()) >= 2 })
	stop()
	_ = c.Close()
	before := h.requestsCopy()[0]
	opts.Login = nil
	opts.SlidingSync.Lists["recent"] = SlidingSyncList{Ranges: []SlidingSyncRange{{2, 4}}, TimelineLimit: 5}
	c, err = Open(context.Background(), opts)
	if err != nil {
		t.Fatal("reopen failed")
	}
	defer c.Close()
	stop = runPolicySync(t, c)
	defer stop()
	waitFor(t, "changed view request", func() bool { return len(h.requestsCopy()) >= 3 })
	stop()
	after := h.requestsCopy()[2]
	if after.position != "" || after.device != "td-one" || after.connection == before.connection {
		t.Fatal("view change reused connection or forgot device acknowledgement")
	}
}

func TestSlidingDiskFailureAndAuthentication(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sliding.db")
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	disk, err := openSlidingDisk(ctx, path, key, "identity")
	if err != nil {
		t.Fatal("disk open failed")
	}
	record, err := disk.load(ctx)
	if err != nil {
		t.Fatal("disk load failed")
	}
	record.Pending = []byte(`{"private":"payload"}`)
	record.Cursor = SlidingSyncCursor{Position: "p", ToDevice: "td"}
	if disk.save(ctx, record) != nil {
		t.Fatal("disk stage failed")
	}
	var synchronous int
	if disk.db.QueryRow("PRAGMA synchronous").Scan(&synchronous) != nil || synchronous != 2 {
		t.Fatal("recovery store is not FULL synchronous")
	}
	if err = disk.db.Close(); err != nil {
		t.Fatal("close failed")
	}
	if disk.save(ctx, record) != ErrSlidingStore {
		t.Fatal("storage failure not sanitized")
	}
	disk, err = openSlidingDisk(ctx, path, key, "identity")
	if err != nil {
		t.Fatal("reopen failed")
	}
	defer disk.db.Close()
	loaded, err := disk.load(ctx)
	if err != nil || !bytes.Equal(loaded.Pending, record.Pending) || loaded.Cursor != record.Cursor {
		t.Fatal("pending recovery was not durable")
	}
	wrong, err := openSlidingDisk(ctx, path, key, "other-identity")
	if err != nil {
		t.Fatal("identity probe open failed")
	}
	defer wrong.db.Close()
	if _, err = wrong.load(ctx); err != ErrSlidingStore {
		t.Fatal("cross-account recovery admitted")
	}
	if _, err = disk.db.Exec("UPDATE sliding_recovery SET record=?", []byte("corrupt")); err != nil {
		t.Fatal("corruption injection failed")
	}
	if _, err = disk.load(ctx); err != ErrSlidingStore {
		t.Fatal("corrupt record admitted")
	}
}

func TestSlidingValidationBeforeSideEffectsAndImmutableConfig(t *testing.T) {
	for _, config := range []*SlidingSyncOptions{{Dialect: "unknown"}, slidingTestOptions()} {
		opts := Options{SlidingSync: config, SyncJournal: func(context.Context, *mautrix.RespSync, string) error { return nil }}
		if _, err := Open(context.Background(), opts); err != ErrSlidingUnsupported {
			t.Fatal("invalid opt-in touched dependencies")
		}
	}
	config := slidingTestOptions()
	copy, err := config.copied()
	if err != nil {
		t.Fatal("valid config rejected")
	}
	config.Lists["recent"].Ranges[0][0] = 4
	if copy.Lists["recent"].Ranges[0][0] != 0 {
		t.Fatal("config shares ranges")
	}
	bad := strings.Repeat("x", slidingMaxResponse+1)
	if _, _, _, err := decodeSliding([]byte(bad)); err != ErrSlidingProtocol {
		t.Fatal("oversized response accepted")
	}
	if _, _, _, err := decodeSliding([]byte(`{"pos":"p","rooms":{},"extensions":{}}`)); err != ErrSlidingProtocol {
		t.Fatal("missing crypto extensions accepted")
	}
}

func TestSlidingExpiredPositionKeepsDeviceAcknowledgement(t *testing.T) {
	h := newSlidingTestServer(t)
	room := id.RoomID("!sliding:localhost")
	opts := testOptions(t, h.testHS, t.TempDir())
	opts.Logger, opts.SyncPolicy, opts.SlidingSync = zerolog.Nop(), SyncPolicyFullClient, slidingTestOptions()
	h.enqueue(slidingTestResponse("p-one", "td-one", room))
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal("open failed")
	}
	stop := runPolicySync(t, c)
	waitFor(t, "first commit", func() bool { return len(h.requestsCopy()) >= 2 })
	stop()
	_ = c.Close()
	h.mu.Lock()
	h.expire = true
	h.mu.Unlock()
	h.enqueue(slidingTestResponse("p-new", "td-new", room))
	opts.Login = nil
	c, err = Open(context.Background(), opts)
	if err != nil {
		t.Fatal("reopen failed")
	}
	defer c.Close()
	stop = runPolicySync(t, c)
	defer stop()
	waitFor(t, "expired-position recovery", func() bool { return len(h.requestsCopy()) >= 5 })
	stop()
	requests := h.requestsCopy()
	refused, reset, continued := requests[2], requests[3], requests[4]
	if refused.position != "p-one" || reset.position != "" || reset.device != "td-one" || reset.connection == refused.connection || continued.position != "p-new" || continued.device != "td-new" {
		t.Fatal("expired-position recovery mixed cursor namespaces")
	}
}

func TestSlidingDispatchAndCommitFailuresReplay(t *testing.T) {
	for _, kind := range []string{"dispatch", "commit"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "sliding.db")
			key := make([]byte, 32)
			_, _ = rand.Read(key)
			disk, err := openSlidingDisk(ctx, path, key, "identity")
			if err != nil {
				t.Fatal("open failed")
			}
			record, _ := disk.load(ctx)
			record.Options = slidingTestOptions()
			record.Configuration = slidingFingerprint(record.Options)
			record.Pending = slidingTestResponse("p-next", "td-next", "!room:localhost", textEvent(testUser, "$replay", "synthetic replay"))
			if disk.save(ctx, record) != nil {
				t.Fatal("stage failed")
			}
			c := &Client{Client: &mautrix.Client{UserID: testUser}, opts: Options{SlidingSync: record.Options}, syncer: newSyncer()}
			count := 0
			c.syncer.OnEventType(event.EventMessage, func(context.Context, *event.Event) {
				count++
				if kind == "dispatch" {
					panic("private dispatch detail")
				}
				_ = disk.db.Close()
			})
			_, err = c.processSliding(ctx, disk, record)
			expected := ErrSyncDispatch
			if kind == "commit" {
				expected = ErrSlidingStore
			}
			if err != expected || count != 1 {
				t.Fatal("failure was not sanitized or dispatch did not run")
			}
			_ = disk.db.Close()
			disk, err = openSlidingDisk(ctx, path, key, "identity")
			if err != nil {
				t.Fatal("reopen failed")
			}
			defer disk.db.Close()
			pending, err := disk.load(ctx)
			if err != nil || pending.Cursor != (SlidingSyncCursor{}) || len(pending.Pending) == 0 {
				t.Fatal("failed processing advanced cursor or lost pending response")
			}
			c.syncer = newSyncer()
			c.syncer.OnEventType(event.EventMessage, func(context.Context, *event.Event) { count++ })
			committed, err := c.processSliding(ctx, disk, pending)
			if err != nil || count != 2 || len(committed.Pending) != 0 || committed.Cursor.Position != "p-next" || committed.Cursor.ToDevice != "td-next" {
				t.Fatal("failed exchange not replayable")
			}
		})
	}
}

type slidingRoundTripFunc func(*http.Request) (*http.Response, error)

func (f slidingRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSlidingLateSuccessfulResponseIsDiscarded(t *testing.T) {
	h := newSlidingTestServer(t)
	opts := testOptions(t, h.testHS, t.TempDir())
	opts.Logger, opts.SlidingSync = zerolog.Nop(), slidingTestOptions()
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal("open failed")
	}
	defer c.Close()
	entered := make(chan struct{})
	original := c.Client.Client.Transport
	if original == nil {
		original = http.DefaultTransport
	}
	c.Client.Client.Transport = slidingRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(r.URL.Path, "simplified_msc3575/sync") {
			return original.RoundTrip(r)
		}
		close(entered)
		<-r.Context().Done()
		// Deliberately return success even though the request has been abandoned.
		raw := slidingTestResponse("late", "late-td", "!room:localhost")
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw)), Request: r}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Sync(ctx) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	if err = c.Sync(context.Background()); err != ErrSyncInProgress {
		t.Fatal("sliding owner lock bypassed")
	}
	cancel()
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled owner did not stop")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not returned")
	}
	identity := slidingFingerprint([]string{c.HomeserverURL.String(), string(c.UserID), string(c.DeviceID), string(opts.SlidingSync.Dialect)})
	disk, err := openSlidingDisk(context.Background(), filepath.Join(opts.StateDir, "sliding.db"), c.session.PickleKey, identity)
	if err != nil {
		t.Fatal("recovery open failed")
	}
	defer disk.db.Close()
	record, err := disk.load(context.Background())
	if err != nil || record.Cursor != (SlidingSyncCursor{}) || len(record.Pending) != 0 {
		t.Fatal("late response staged or committed")
	}
	unlock, err := lockSync(opts.StateDir)
	if err != nil {
		t.Fatal("cancelled owner retained lock")
	}
	unlock()
}

func TestSlidingExtensionsAndAuthoritativeState(t *testing.T) {
	room := id.RoomID("!extensions:localhost")
	join := memberEvent(testUser)
	leave := memberEvent(testUser)
	leave.Content = event.Content{Raw: map[string]any{"membership": "leave"}}
	marshal := func(v any) json.RawMessage { raw, _ := json.Marshal(v); return raw }
	response, td, ee, err := decodeSliding(slidingTestResponse("p", "td", room))
	if err != nil {
		t.Fatal("decode failed")
	}
	ee.DeviceLists = mautrix.DeviceLists{Changed: []id.UserID{testUser}, Left: []id.UserID{"@left:localhost"}}
	ee.Fallback = []id.KeyAlgorithm{id.KeyAlgorithmSignedCurve25519}
	record := &slidingRecord{View: emptySlidingView(), Membership: make(map[id.RoomID]string), Options: slidingTestOptions()}
	response.Rooms[room] = marshal(map[string]any{"initial": true, "timeline": []*event.Event{leave}, "required_state": []*event.Event{join}})
	adapted, err := adaptSliding(response, td, ee, record, testUser)
	if err != nil || adapted.Rooms.Join[room] == nil || adapted.Rooms.Join[room].StateAfter == nil || len(adapted.DeviceLists.Changed) != 1 || len(adapted.FallbackKeys) != 1 || record.Membership[room] != "join" {
		t.Fatal("current state or crypto metadata lost")
	}
	// A later extension-only response must use stored membership, not require
	// another timeline or infer a leave from a room missing from the window.
	response.Rooms = map[id.RoomID]json.RawMessage{}
	response.Extensions["account_data"] = marshal(map[string]any{"global": []any{map[string]any{"type": "m.direct", "content": map[string]any{}}}, "rooms": map[id.RoomID]any{room: []any{map[string]any{"type": "m.tag", "content": map[string]any{"tags": map[string]any{}}}}}})
	response.Extensions["typing"] = marshal(map[string]any{"rooms": map[id.RoomID]any{room: map[string]any{"type": "m.typing", "content": map[string]any{"user_ids": []id.UserID{testUser}}}}})
	response.Extensions["receipts"] = marshal(map[string]any{"rooms": map[id.RoomID]any{room: map[string]any{"type": "m.receipt", "content": map[string]any{}}}})
	adapted, err = adaptSliding(response, td, ee, record, testUser)
	if err != nil || len(adapted.AccountData.Events) != 1 || len(adapted.Rooms.Join[room].AccountData.Events) != 1 || len(adapted.Rooms.Join[room].Ephemeral.Events) != 2 {
		t.Fatal("extension-only events lost")
	}
	s := newSyncer()
	seen := map[string]bool{}
	s.OnEvent(func(_ context.Context, ev *event.Event) {
		seen[ev.Type.Type] = true
		if ev.Type.Type == "m.direct" {
			if ev.RoomID != "" || ev.Type.Class != event.AccountDataEventType {
				t.Error("global account-data class incorrect")
			}
		} else {
			if ev.RoomID != room {
				t.Error("extension room ID missing")
			}
			if (ev.Type.Type == "m.typing" || ev.Type.Type == "m.receipt") && ev.Type.Class != event.EphemeralEventType {
				t.Error("ephemeral class incorrect")
			}
		}
	})
	if s.DefaultSyncer.ProcessResponse(context.Background(), adapted, "previous") != nil || len(seen) != 4 {
		t.Fatal("extension dispatch incomplete")
	}
	// The state guard prevents a historical leave from reverting the current
	// joined membership while callbacks are observing the timeline.
	base := mautrix.NewMemoryStateStore()
	guard := &slidingStateStore{StateStore: base}
	join.RoomID, join.Type.Class = room, event.StateEventType
	_ = join.Content.ParseRaw(join.Type)
	guard.UpdateState(context.Background(), join)
	leave.RoomID, leave.Type.Class = room, event.StateEventType
	_ = leave.Content.ParseRaw(leave.Type)
	leave.Mautrix.EventSource = event.SourceJoin | event.SourceTimeline
	guard.UpdateState(context.Background(), leave)
	if member, err := base.GetMember(context.Background(), room, testUser); err != nil || member.Membership != event.MembershipJoin {
		t.Fatal("historical timeline reverted current membership")
	}
}

func TestSlidingRejectsUnrequestedWindowsAndKnocks(t *testing.T) {
	response, td, ee, err := decodeSliding(slidingTestResponse("p", "td", "!room:localhost"))
	if err != nil {
		t.Fatal("decode failed")
	}
	record := &slidingRecord{View: emptySlidingView(), Membership: make(map[id.RoomID]string), Options: slidingTestOptions()}
	record.Options.Lists["recent"] = SlidingSyncList{Ranges: []SlidingSyncRange{{2, 4}}, TimelineLimit: 5}
	if materializeSliding(record, response) != ErrSlidingProtocol {
		t.Fatal("unrequested list range accepted")
	}
	knock := memberEvent(testUser)
	knock.Content = event.Content{Raw: map[string]any{"membership": "knock"}}
	response.Rooms["!room:localhost"], _ = json.Marshal(map[string]any{"invite_state": []*event.Event{knock}})
	if _, err = adaptSliding(response, td, ee, record, testUser); err != ErrSlidingUnsupported {
		t.Fatal("unsupported knock state silently acknowledged")
	}
}

func TestSlidingVerificationStopsWithOwner(t *testing.T) {
	h := newSlidingTestServer(t)
	opts := testOptions(t, h.testHS, t.TempDir())
	opts.Logger, opts.SlidingSync = zerolog.Nop(), slidingTestOptions()
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal("open failed")
	}
	defer c.Close()
	controller, err := c.EnableSAS()
	if err != nil {
		t.Fatal("verification enable failed")
	}
	stop := runPolicySync(t, c)
	defer stop()
	waitFor(t, "verification-owned sliding poll", func() bool { return len(h.requestsCopy()) > 0 })
	controller.mu.Lock()
	active := controller.started && !controller.stopped
	controller.mu.Unlock()
	if !active {
		t.Fatal("verification not owned by sliding Sync")
	}
	stop()
	if controller.Snapshot().State != SASStopped {
		t.Fatal("verification not stopped before owner returned")
	}
}

func TestSlidingUnsupportedCapabilityAndMalformedResponse(t *testing.T) {
	for _, kind := range []string{"capability", "response"} {
		t.Run(kind, func(t *testing.T) {
			h := newSlidingTestServer(t)
			opts := testOptions(t, h.testHS, t.TempDir())
			opts.Logger, opts.SlidingSync = zerolog.Nop(), slidingTestOptions()
			c, err := Open(context.Background(), opts)
			if err != nil {
				t.Fatal("open failed")
			}
			defer c.Close()
			if kind == "capability" {
				h.mu.Lock()
				h.unsupported = true
				h.mu.Unlock()
			} else {
				h.enqueue([]byte(`{"pos":"p","rooms":{},"extensions":{}}`))
			}
			err = c.Sync(context.Background())
			if kind == "capability" {
				if err != ErrSlidingUnsupported || len(h.requestsCopy()) != 0 {
					t.Fatal("unsupported server contacted sliding endpoint")
				}

			} else {
				if err != ErrSlidingProtocol {
					t.Fatal("malformed crypto response not refused")
				}
				identity := slidingFingerprint([]string{c.HomeserverURL.String(), string(c.UserID), string(c.DeviceID), string(opts.SlidingSync.Dialect)})
				disk, err := openSlidingDisk(context.Background(), filepath.Join(opts.StateDir, "sliding.db"), c.session.PickleKey, identity)
				if err != nil {
					t.Fatal("recovery open failed")
				}
				defer disk.db.Close()
				record, err := disk.load(context.Background())
				if err != nil || len(record.Pending) != 0 || record.Cursor != (SlidingSyncCursor{}) {
					t.Fatal("malformed response acknowledged or staged")
				}
			}
		})
	}
}

func TestSlidingInvalidBatchNeverPoisonsRecovery(t *testing.T) {
	for _, kind := range []string{"list-name", "window", "membership", "event", "knock"} {
		t.Run(kind, func(t *testing.T) {
			h := newSlidingTestServer(t)
			room := id.RoomID("!validation:localhost")
			raw := slidingTestResponse("invalid-pos", "invalid-td", room)
			var body map[string]json.RawMessage
			_ = json.Unmarshal(raw, &body)
			switch kind {
			case "list-name":
				body["lists"] = json.RawMessage(`{"unrequested":{"count":0,"ops":[]}}`)
			case "window":
				body["lists"] = json.RawMessage(`{"recent":{"count":0,"ops":[{"op":"SYNC","range":[10,11],"room_ids":[]}]}}`)
			case "membership":
				body["rooms"] = json.RawMessage(`{"!validation:localhost":{"initial":true,"required_state":[]}}`)
			case "event":
				body["rooms"] = json.RawMessage(`{"!validation:localhost":{"timeline":[null]}}`)
			}
			raw, _ = json.Marshal(body)
			// Bind the synthetic knock to the fixture account, without assuming its ID.
			if kind == "knock" {
				ev := memberEvent(testUser)
				ev.Content = event.Content{Raw: map[string]any{"membership": "knock"}}
				body["rooms"], _ = json.Marshal(map[id.RoomID]any{room: map[string]any{"invite_state": []*event.Event{ev}}})
				raw, _ = json.Marshal(body)
			}
			h.enqueue(raw)
			opts := testOptions(t, h.testHS, t.TempDir())
			opts.Logger, opts.SlidingSync = zerolog.Nop(), slidingTestOptions()
			captures := 0
			opts.SlidingSyncJournal = func(context.Context, *SlidingSyncBatch) error { captures++; return nil }
			c, err := Open(context.Background(), opts)
			if err != nil {
				t.Fatal("open failed")
			}
			err = c.Sync(context.Background())
			expected := ErrSlidingProtocol
			if kind == "knock" {
				expected = ErrSlidingUnsupported
			}
			if err != expected || captures != 0 {
				t.Fatal("invalid batch was not refused before capture")
			}
			_ = c.Close()
			opts.Login = nil
			h.enqueue(slidingTestResponse("valid-pos", "valid-td", room))
			c, err = Open(context.Background(), opts)
			if err != nil {
				t.Fatal("reopen failed")
			}
			defer c.Close()
			stop := runPolicySync(t, c)
			defer stop()
			waitFor(t, "valid response after rejected batch", func() bool { return len(h.requestsCopy()) >= 3 })
			stop()
			if captures != 1 || h.requestsCopy()[1].position != "" || h.requestsCopy()[1].device != "" || h.requestsCopy()[2].position != "valid-pos" {
				t.Fatal("rejected batch poisoned recovery or advanced acknowledgements")
			}
		})
	}
}

func TestSlidingReplayPrecedesCapabilityDiscovery(t *testing.T) {
	for _, kind := range []string{"removed", "unavailable"} {
		t.Run(kind, func(t *testing.T) {
			h := newSlidingTestServer(t)
			room := id.RoomID("!replay:localhost")
			opts := testOptions(t, h.testHS, t.TempDir())
			opts.Logger, opts.SyncPolicy, opts.SlidingSync = zerolog.Nop(), SyncPolicyFullClient, slidingTestOptions()
			opts.SlidingSyncJournal = func(context.Context, *SlidingSyncBatch) error { return errors.New("application stopped") }
			h.enqueue(slidingTestResponse("pending-pos", "pending-td", room, textEvent(testUser, "$pending", "synthetic replay")))
			c, err := Open(context.Background(), opts)
			if err != nil {
				t.Fatal("open failed")
			}
			if c.Sync(context.Background()) != ErrSyncJournal {
				t.Fatal("pending response not staged")
			}
			_ = c.Close()
			opts.Login = nil
			opts.SlidingSyncJournal = nil
			c, err = Open(context.Background(), opts)
			if err != nil {
				t.Fatal("restore failed")
			}
			defer c.Close()
			delivered, discovered := false, false
			original := c.Client.Client.Transport
			if original == nil {
				original = http.DefaultTransport
			}
			c.Client.Client.Transport = slidingRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/_matrix/client/versions" {
					return original.RoundTrip(r)
				}
				discovered = true
				if !delivered {
					t.Error("capability discovery preceded local replay")
				}
				status, body := http.StatusOK, `{"versions":["v1.11"],"unstable_features":{}}`
				if kind == "unavailable" {
					status, body = http.StatusForbidden, `{"errcode":"M_FORBIDDEN","error":"fixture unavailable"}`
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			c.Handlers().OnEventType(event.EventMessage, func(context.Context, *event.Event) { delivered = true })
			if err = c.Sync(context.Background()); err != ErrSlidingUnsupported || !delivered || !discovered || len(h.requestsCopy()) != 1 {
				t.Fatal("pending response depended on server capability")
			}
			identity := slidingFingerprint([]string{c.HomeserverURL.String(), string(c.UserID), string(c.DeviceID), string(opts.SlidingSync.Dialect)})
			disk, err := openSlidingDisk(context.Background(), filepath.Join(opts.StateDir, "sliding.db"), c.session.PickleKey, identity)
			if err != nil {
				t.Fatal("recovery open failed")
			}
			defer disk.db.Close()
			record, err := disk.load(context.Background())
			if err != nil || len(record.Pending) != 0 || record.Cursor.Position != "pending-pos" || record.Cursor.ToDevice != "pending-td" {
				t.Fatal("replay was not checkpointed before discovery refusal")
			}
		})
	}
}
