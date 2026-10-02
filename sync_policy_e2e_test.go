//go:build e2e

package rihma

import (
	"context"
	"sync"
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
func TestE2EFullClientOtherDeviceHistoryAndResume(t *testing.T) {
	hs := e2eHomeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	name, password := "fullclient-"+e2eTag(), "disposable-test-password"
	register(t, ctx, hs, name, password)
	opts := e2eOptions(t, hs, name, password, t.TempDir())
	opts.Logger = zerolog.Nop()
	sender := openAndSync(t, ctx, opts, nil)
	opts = e2eOptions(t, hs, name, password, t.TempDir())
	opts.SyncPolicy, opts.Logger = SyncPolicyFullClient, zerolog.Nop()
	receiver, err := Open(ctx, opts)
	if err != nil {
		t.Fatal("receiver login failed")
	}
	// The current receiver is closed only after its sync owner returns.
	var stop func() error
	t.Cleanup(func() {
		if stop != nil {
			stop()
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
	attach := func(c *Client) {
		c.Handlers().OnEventType(event.EventMessage, func(_ context.Context, evt *event.Event) {
			if evt.RoomID != room || evt.Sender != sender.UserID {
				return
			}
			if !evt.Mautrix.WasEncrypted {
				t.Error("plaintext handler received unencrypted timeline event")
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
	downtime := send()
	opts.Login = nil
	restored, err := Open(ctx, opts)
	if err != nil {
		t.Fatal("restore receiver failed")
	}
	receiver = restored
	attach(receiver)
	stop = runPolicySync(t, receiver)
	waitSeen(downtime)
	stop()
}
