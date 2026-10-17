//go:build e2e

package rihma

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// A device verified by SAS gets the key backup key from the device that
// verified it and reads history sent before it existed, without the
// recovery key. An unverified device gets nothing. The peer runs rihma's
// own client, so this also proves rihma devices answer. All accounts are
// disposable; assertions print no keys or message bodies.
func TestE2EVerifiedDeviceReceivesBackupKey(t *testing.T) {
	hs := e2eHomeserver(t)
	u, err := url.Parse(hs)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || os.Getenv("RIHMA_E2E_DISPOSABLE") != "1" {
		t.Skip("owned loopback fixture required")
	}
	defer func(old time.Duration) { shareRequestInterval = old }(shareRequestInterval)
	shareRequestInterval = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	name, password := "share-"+e2eTag(), "disposable-test-password"
	register(t, ctx, hs, name, password)
	open := func() *Client {
		opts := e2eOptions(t, hs, name, password, t.TempDir())
		opts.Logger = zerolog.Nop()
		opts.SyncPolicy = SyncPolicyFullClient
		c, err := Open(ctx, opts)
		if err != nil {
			t.Fatal("device login failed")
		}
		t.Cleanup(func() { c.Close() })
		return c
	}

	first := open()
	recovery, err := first.CreateRecoveryKey(ctx, "")
	if err != nil || recovery == "" {
		t.Fatal("identity creation failed")
	}
	if err := first.EnableKeyBackup(ctx, recovery); err != nil {
		t.Fatal("backup creation failed")
	}
	peerCB := &sasPeerCallbacks{sasCallbacks: sasCallbacks{events: make(chan sasEvent, 32), overflow: make(chan struct{}, 1)}, ready: make(chan id.VerificationTransactionID, 4)}
	store := newSASStore()
	gate := &sasEventGate{active: true}
	original := first.Client.Syncer
	first.Client.Syncer = &sasHandlerSyncer{DefaultSyncer: first.Handlers(), underlying: first.Handlers(), gate: gate, user: first.UserID, device: first.DeviceID}
	peer := verificationhelper.NewVerificationHelper(first.Client, first.OlmMachine(), store, peerCB, false, false, true)
	if err := peer.Init(ctx); err != nil {
		t.Fatal("peer helper failed")
	}
	first.Client.Syncer = original
	stopFirst := runPolicySync(t, first)
	t.Cleanup(func() {
		stopFirst()
		gate.mu.Lock()
		gate.active = false
		gate.mu.Unlock()
		store.close()
		_ = peer.DismissVerification(context.Background(), "")
	})

	// History the next device was never sent a room key for.
	created, err := first.CreateRoom(ctx, &mautrix.ReqCreateRoom{Preset: "private_chat", InitialState: []*event.Event{{Type: event.StateEncryption, Content: event.Content{Parsed: &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}}}}})
	if err != nil {
		t.Fatal("encrypted room failed")
	}
	room := created.RoomID
	liveSASWait(t, ctx, func() bool { ok, err := first.StateStore.IsEncrypted(ctx, room); return err == nil && ok })
	history := sendText(t, ctx, first, room, "before the new device")
	waitBackupCount(t, ctx, first, 1)

	// An unverified device asks and is ignored.
	stranger := open()
	if err := stranger.RequestKeyBackup(ctx, 3*time.Second); !errors.Is(err, ErrBackupKeyNotShared) {
		t.Fatalf("unverified device request = %v, want ErrBackupKeyNotShared", err)
	}
	if stranger.KeyBackupVersion() != "" {
		t.Fatal("unverified device adopted the backup")
	}

	second := open()
	controller, err := second.EnableSAS()
	if err != nil {
		t.Fatal("controller preparation failed")
	}
	runPolicySync(t, second)
	txn, err := peer.StartVerification(ctx, first.UserID)
	if err != nil {
		t.Fatal("verification request failed")
	}
	liveSASWait(t, ctx, func() bool { s := controller.Snapshot(); return s.TransactionID == txn && s.State == SASRequested })
	if err := controller.Accept(ctx, txn); err != nil {
		t.Fatal("accept failed")
	}
	select {
	case <-peerCB.ready:
	case <-ctx.Done():
		t.Fatal("peer readiness timed out")
	}
	if err := peer.StartSAS(ctx, txn); err != nil {
		t.Fatal("peer SAS start failed")
	}
	liveSASWait(t, ctx, func() bool { return controller.Snapshot().State == SASShowing })
	if err := controller.Confirm(ctx, txn, true); err != nil {
		t.Fatal("confirm failed")
	}
	if err := peer.ConfirmSAS(ctx, txn); err != nil {
		t.Fatal("peer confirmation failed")
	}
	liveSASWait(t, ctx, func() bool { return controller.Snapshot().State == SASDone })

	if err := second.RequestKeyBackup(ctx, 30*time.Second); err != nil {
		t.Fatalf("verified device request failed: %v", err)
	}
	if second.KeyBackupVersion() == "" || second.KeyBackupVersion() != first.KeyBackupVersion() {
		t.Fatal("verified device did not adopt the account's backup")
	}
	evt, err := second.GetEvent(ctx, room, history)
	if err != nil {
		t.Fatal("history fetch failed")
	}
	if evt.Content.Parsed == nil {
		if err := evt.Content.ParseRaw(evt.Type); err != nil {
			t.Fatal("history parse failed")
		}
	}
	dec, err := second.OlmMachine().DecryptMegolmEvent(ctx, evt)
	if err != nil || dec.Content.AsMessage().Body != "before the new device" {
		t.Fatal("verified device cannot read history from the shared backup key")
	}
}
