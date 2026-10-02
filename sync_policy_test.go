package rihma

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func TestInvalidSyncPolicyHasNoSideEffects(t *testing.T) {
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	opts.SyncPolicy = SyncPolicy(255)
	if _, err := Open(context.Background(), opts); !errors.Is(err, ErrInvalidSyncPolicy) {
		t.Fatal("invalid policy was not rejected")
	}
	if h.requests.Load() != 0 {
		t.Fatal("invalid policy contacted homeserver")
	}
	if _, err := os.Stat(opts.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid policy created state")
	}
}

// These responses enter through Client.Sync and its installed hooks, not by
// calling the filter directly. Sender=self with no unsigned transaction ID is
// the shape seen for a message sent by another device of the same account.
func TestSyncPolicyJoinedLeftStateAndToDevice(t *testing.T) {
	for _, policy := range []SyncPolicy{SyncPolicyBot, SyncPolicyFullClient} {
		t.Run(map[SyncPolicy]string{SyncPolicyBot: "bot", SyncPolicyFullClient: "full_client"}[policy], func(t *testing.T) {
			ctx := context.Background()
			h := newTestHS(t)
			opts := testOptions(t, h, t.TempDir())
			opts.SyncPolicy, opts.Logger = policy, zerolog.Nop()
			c, err := Open(ctx, opts)
			if err != nil {
				t.Fatal("open failed")
			}
			defer c.Close()
			var mu sync.Mutex
			ids := map[id.EventID]bool{}
			var dummy atomic.Int32
			c.Handlers().OnEvent(func(_ context.Context, evt *event.Event) {
				mu.Lock()
				ids[evt.ID] = true
				mu.Unlock()
			})
			c.Handlers().OnEventType(event.ToDeviceDummy, func(context.Context, *event.Event) { dummy.Add(1) })
			const joined = id.RoomID("!joined:example.invalid")
			const left = id.RoomID("!left:example.invalid")
			h.script(func(string) *mautrix.RespSync {
				r := &mautrix.RespSync{NextBatch: "b1"}
				r.Rooms.Join = map[id.RoomID]*mautrix.SyncJoinedRoom{joined: {}}
				r.Rooms.Leave = map[id.RoomID]*mautrix.SyncLeftRoom{left: {}}
				r.Rooms.Join[joined].Timeline.Events = []*event.Event{
					memberEvent(testUser), textEvent("@other:example.invalid", "$initial-other", "synthetic"),
					textEvent(testUser, "$initial-self", "synthetic"),
				}
				r.Rooms.Leave[left].Timeline.Events = []*event.Event{textEvent(testUser, "$left-initial", "synthetic")}
				r.ToDevice.Events = []*event.Event{{Type: event.ToDeviceDummy, Sender: testUser, Content: event.Content{VeryRaw: json.RawMessage(`{}`)}}}
				return r
			}, func(string) *mautrix.RespSync {
				r := roomSync("b2", joined,
					textEvent("@other:example.invalid", "$live-other", "synthetic"),
					textEvent(testUser, "$live-self", "synthetic"),
				)("")
				r.Rooms.Leave = map[id.RoomID]*mautrix.SyncLeftRoom{left: {}}
				r.Rooms.Leave[left].Timeline.Events = []*event.Event{textEvent(testUser, "$left-live", "synthetic")}
				return r
			})
			stop := runPolicySync(t, c)
			defer stop()
			waitFor(t, "both responses dispatched", func() bool { return len(h.seenSinces()) >= 3 })
			stop()
			mu.Lock()
			defer mu.Unlock()
			if !ids["$member-"+id.EventID(testUser)] || !ids["$live-other"] || dummy.Load() != 1 {
				t.Fatal("state, live event or to-device delivery changed")
			}
			for _, evtID := range []id.EventID{"$initial-other", "$initial-self", "$left-initial", "$live-self", "$left-live"} {
				if ids[evtID] != (policy == SyncPolicyFullClient) {
					t.Errorf("policy %d: wrong delivery for event %s", policy, evtID)
				}
			}
		})
	}
}

// Use a second logged-in device and real goolm Megolm sessions to prove that
// initial and self-sent encrypted events reach normal plaintext handlers. Keys
// stay in disposable stores/memory; failures report only fixed messages/IDs.
func TestFullClientDecryptsOtherDeviceHistoryAndResumes(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	opts.SyncPolicy, opts.Logger = SyncPolicyFullClient, zerolog.Nop()
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal("receiver open failed")
	}
	t.Cleanup(func() { c.Close() })
	senderOpts := testOptions(t, h, t.TempDir())
	senderOpts.Logger = zerolog.Nop()
	sender, err := Open(ctx, senderOpts)
	if err != nil {
		t.Fatal("sender open failed")
	}
	defer sender.Close()
	if sender.DeviceID == c.DeviceID || sender.UserID != c.UserID {
		t.Fatal("expected two devices of one account")
	}
	const room = id.RoomID("!encrypted:example.invalid")
	if err := sender.OlmMachine().ShareGroupSession(ctx, room, nil); err != nil {
		t.Fatal("create disposable group session failed")
	}
	// Install the second device's group key in the receiver without involving
	// a real server. Full-client filtering must not replace crypto decryption.
	outbound, err := sender.OlmMachine().CryptoStore.GetOutboundGroupSession(ctx, room)
	if err != nil || outbound == nil {
		t.Fatal("outbound session missing")
	}
	shareContent := outbound.ShareContent()
	key := shareContent.AsRoomKey()
	first, err := sender.Crypto.Encrypt(ctx, room, event.EventMessage, &event.MessageEventContent{MsgType: event.MsgText, Body: "synthetic"})
	if err != nil {
		t.Fatal("encrypt initial event failed")
	}
	inbound, err := crypto.NewInboundGroupSession(first.SenderKey, sender.OlmMachine().OwnIdentity().SigningKey, room, key.SessionKey, 7*24*time.Hour, 100, nil, false)
	if err != nil {
		t.Fatal("prepare receiver group session failed")
	}
	if err := c.OlmMachine().StoreGroupSession(ctx, inbound); err != nil {
		t.Fatal("store receiver group session failed")
	}
	encrypted := func(evtID id.EventID, content *event.EncryptedEventContent) *event.Event {
		return &event.Event{ID: evtID, Sender: sender.UserID, Type: event.EventEncrypted, Content: event.Content{Parsed: content}}
	}
	var count atomic.Int32
	attach := func(client *Client) {
		client.Handlers().OnEventType(event.EventMessage, func(_ context.Context, evt *event.Event) {
			if !evt.Mautrix.WasEncrypted || evt.Sender != testUser || evt.Content.AsMessage().Body != "synthetic" {
				t.Error("plaintext handler did not receive expected decrypted event")
			}
			count.Add(1)
		})
	}
	attach(c)
	second, err := sender.Crypto.Encrypt(ctx, room, event.EventMessage, &event.MessageEventContent{MsgType: event.MsgText, Body: "synthetic"})
	if err != nil {
		t.Fatal("encrypt live event failed")
	}
	h.script(roomSync("b1", room, encrypted("$initial", first)), roomSync("b2", room, encrypted("$live", second)))
	stop := runPolicySync(t, c)
	waitFor(t, "decrypted initial and live events", func() bool { return count.Load() == 2 })
	stop()
	if err := c.Close(); err != nil {
		t.Fatal("close before resume failed")
	}
	opts.Login = nil
	restored, err := Open(ctx, opts)
	if err != nil {
		t.Fatal("restore receiver failed")
	}
	c = restored
	attach(c)
	third, err := sender.Crypto.Encrypt(ctx, room, event.EventMessage, &event.MessageEventContent{MsgType: event.MsgText, Body: "synthetic"})
	if err != nil {
		t.Fatal("encrypt downtime event failed")
	}
	h.script(func(since string) *mautrix.RespSync {
		if since != "b2" {
			t.Error("full-client resume lost persistent cursor")
		}
		return roomSync("b3", room, encrypted("$downtime", third))(since)
	})
	stop = runPolicySync(t, c)
	defer stop()
	waitFor(t, "decrypted event after resume", func() bool { return count.Load() == 3 })
	stop()
}

// The existing runSync helper is single-call; these tests also need cleanup on
// failure and explicit stop/reopen, so make their stopper idempotent.
func runPolicySync(t *testing.T, c *Client) func() error {
	t.Helper()
	stop := runSync(t, c)
	var once sync.Once
	var err error
	result := func() error { once.Do(func() { err = stop() }); return err }
	t.Cleanup(func() { result() })
	return result
}

func TestFullClientKeepsOneSyncPerStateDir(t *testing.T) {
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	opts.SyncPolicy, opts.Logger = SyncPolicyFullClient, zerolog.Nop()
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal("open failed")
	}
	defer c.Close()
	stop := runPolicySync(t, c)
	defer stop()
	waitFor(t, "full-client sync started", func() bool { return len(h.seenSinces()) > 0 })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Sync(ctx); !errors.Is(err, ErrSyncInProgress) {
		t.Fatal("full-client mode allowed competing sync")
	}
	stop()
	unlock, err := lockSync(opts.StateDir)
	if err != nil {
		t.Fatal("full-client mode retained sync lock after cancellation")
	}
	unlock()
}
