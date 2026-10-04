//go:build e2e

package rihma

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// TestE2EFullClientOtherDeviceHistoryAndResume uses two disposable devices of
// one account against the isolated Synapse harness. The receiving device first
// syncs after a send, then observes a live send and a send made while stopped.
// No recovery shortcut or direct key insertion is used in this test.
func TestE2EFullClientOtherDeviceHistoryAndResume(t *testing.T) { fullClientHistoryAndResume(t, false) }
func TestE2EJournalledFullClientHistoryAndResume(t *testing.T)  { fullClientHistoryAndResume(t, true) }
func TestE2EManagedCryptoHistoryAndResume(t *testing.T) {
	if !supportsManagedCryptoBackground() {
		t.Skip("requires explicit managed mautrix dependency")
	}
	fullClientHistoryAndResume(t, true, true)
}
func fullClientHistoryAndResume(t *testing.T, journal bool, managed ...bool) {
	fullClientHistoryAndResumeWithTransport(t, journal, len(managed) > 0 && managed[0], false)
}

func TestE2ESlidingManagedCryptoHistoryAndResume(t *testing.T) {
	if !supportsManagedCryptoBackground() {
		t.Skip("requires explicit managed mautrix dependency")
	}
	fullClientHistoryAndResumeWithTransport(t, true, true, true)
}

func TestE2ESlidingEncryptedHistoryAndResume(t *testing.T) {
	fullClientHistoryAndResumeWithTransport(t, true, false, true)
}

func fullClientHistoryAndResumeWithTransport(t *testing.T, journal, managed, sliding bool) {
	hs := e2eHomeserver(t)
	if sliding {
		requireSlidingFixture(t, hs)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	name, password := "fullclient-"+e2eTag(), "disposable-test-password"
	register(t, ctx, hs, name, password)
	opts := e2eOptions(t, hs, name, password, t.TempDir())
	opts.Logger = zerolog.Nop()
	opts.ManagedCryptoBackground = managed
	sender := openAndSync(t, ctx, opts, nil)
	opts = e2eOptions(t, hs, name, password, t.TempDir())
	opts.SyncPolicy, opts.Logger = SyncPolicyFullClient, zerolog.Nop()
	opts.ManagedCryptoBackground = managed
	if sliding {
		opts.SlidingSync = slidingTestOptions()
	}
	var captureMu sync.Mutex
	captured := map[id.EventID]bool{}
	if journal && sliding {
		opts.SlidingSyncJournal = func(_ context.Context, batch *SlidingSyncBatch) error {
			var resp slidingResponse
			if json.Unmarshal(batch.Raw, &resp) != nil {
				return ErrSlidingProtocol
			}
			captureMu.Lock()
			defer captureMu.Unlock()
			for _, raw := range resp.Rooms {
				var room slidingRoom
				if json.Unmarshal(raw, &room) != nil {
					return ErrSlidingProtocol
				}
				for _, ev := range room.Timeline {
					captured[ev.ID] = true
				}
			}
			return nil
		}
	} else if journal {
		opts.SyncJournal = func(_ context.Context, resp *mautrix.RespSync, _ string) error {
			captureMu.Lock()
			defer captureMu.Unlock()
			for _, room := range resp.Rooms.Join {
				for _, ev := range room.Timeline.Events {
					captured[ev.ID] = true
				}
			}
			return nil
		}
	}
	receiver, err := Open(ctx, opts)
	if err != nil {
		t.Fatal("receiver login failed")
	}
	// The current receiver is closed only after its sync owner returns.
	var stop func() error
	t.Cleanup(func() {
		if stop != nil {
			if err := stop(); err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("sync stopped: protocol=%t unsupported=%t store=%t dispatch=%t", errors.Is(err, ErrSlidingProtocol), errors.Is(err, ErrSlidingUnsupported), errors.Is(err, ErrSlidingStore), errors.Is(err, ErrSyncDispatch))
			}
		}
		receiver.Close()
	})
	if sender.DeviceID == receiver.DeviceID {
		t.Fatal("expected distinct test devices")
	}
	created, err := sender.CreateRoom(ctx, &mautrix.ReqCreateRoom{
		Preset:       "private_chat",
		InitialState: []*event.Event{{Type: event.StateEncryption, Content: event.Content{Parsed: &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}}}},
	})
	if err != nil {
		t.Fatal("create encrypted room failed")
	}
	room := created.RoomID
	waitJoined(t, ctx, sender.Client, room, sender.UserID)
	waitFor(t, "sender encryption state", func() bool {
		encrypted, err := sender.StateStore.IsEncrypted(ctx, room)
		return err == nil && encrypted
	})
	var mu sync.Mutex
	seen := map[id.EventID]bool{}
	var replied atomic.Bool
	attach := func(c *Client) {
		c.Handlers().OnEventType(event.EventMessage, func(_ context.Context, evt *event.Event) {
			if evt.RoomID != room || evt.Sender != sender.UserID {
				return
			}
			if journal {
				captureMu.Lock()
				wasCaptured := captured[evt.ID]
				captureMu.Unlock()
				if !wasCaptured {
					t.Error("decrypted event preceded raw capture")
				}
			}
			if !evt.Mautrix.WasEncrypted {
				t.Error("plaintext handler received unencrypted timeline event")
			}
			if sliding && replied.CompareAndSwap(false, true) {
				reply, err := c.SendText(ctx, room, "synthetic encrypted callback reply")
				if err != nil {
					t.Error("encrypted callback reply failed")
				} else {
					wire, err := c.Client.GetEvent(ctx, room, reply.EventID)
					if err != nil || wire.Type != event.EventEncrypted {
						t.Error("callback reply was not encrypted on the wire")
					}
				}
			}
			mu.Lock()
			seen[evt.ID] = true
			mu.Unlock()
		})
	}
	attach(receiver)
	send := func() id.EventID {
		r, err := sender.SendText(ctx, room, "synthetic full-client test")
		if err != nil {
			t.Fatal("encrypted send failed")
		}
		return r.EventID
	}
	waitSeen := func(evtID id.EventID) {
		waitFor(t, "decrypted event delivery", func() bool { mu.Lock(); defer mu.Unlock(); return seen[evtID] })
	}
	history := send()
	stop = runPolicySync(t, receiver)
	waitSeen(history)
	live := send()
	waitSeen(live)
	stop()
	if err := receiver.Close(); err != nil {
		t.Fatal("close before restart failed")
	}
	stop = nil
	if sliding {
		// Simulate server-side connection expiry with an unrecognized conn_id,
		// keeping the last committed sliding and independent device positions.
		identity := slidingFingerprint([]string{receiver.HomeserverURL.String(), string(receiver.UserID), string(receiver.DeviceID), string(opts.SlidingSync.Dialect)})
		disk, err := openSlidingDisk(ctx, filepath.Join(opts.StateDir, "sliding.db"), receiver.session.PickleKey, identity)
		if err != nil {
			t.Fatal("expiry injection open failed")
		}
		record, err := disk.load(ctx)
		if err != nil {
			t.Fatal("expiry injection load failed")
		}
		record.Connection, err = newSlidingConnection()
		if err != nil || disk.save(ctx, record) != nil {
			t.Fatal("expiry injection failed")
		}
		_ = disk.db.Close()
	}
	downtime := send()
	opts.Login = nil
	var retried atomic.Bool
	if sliding {
		opts.OnSyncRetry = func() { retried.Store(true) }
	}
	restored, err := Open(ctx, opts)
	if err != nil {
		t.Fatal("restore receiver failed")
	}
	receiver = restored
	attach(receiver)
	stop = runPolicySync(t, receiver)
	waitSeen(downtime)
	if sliding && !retried.Load() {
		t.Error("unrecognized server connection did not trigger recovery")
	}
	stop()
	if sliding {
		if err := receiver.Close(); err != nil {
			t.Fatal("close before window change failed")
		}
		stop = nil
		opts.SlidingSync.Lists["recent"] = SlidingSyncList{Ranges: []SlidingSyncRange{{0, 0}}, TimelineLimit: 10}
		receiver, err = Open(ctx, opts)
		if err != nil {
			t.Fatal("window change restore failed")
		}
		attach(receiver)
		stop = runPolicySync(t, receiver)
		waitFor(t, "changed sliding window", func() bool {
			view := receiver.SlidingSyncSnapshot()
			return view != nil && len(view.Lists["recent"]) == 1 && view.Lists["recent"][0] == room
		})
		waitSeen(send())
		stop()
	}
}
