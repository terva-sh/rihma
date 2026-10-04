//go:build e2e

package rihma

import (
	"context"
	"net/url"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type sasPeerCallbacks struct {
	sasCallbacks
	ready chan id.VerificationTransactionID
}

func (p *sasPeerCallbacks) VerificationReady(_ context.Context, txn id.VerificationTransactionID, _ id.DeviceID, _ bool, _ bool, _ *verificationhelper.QRCode) {
	select {
	case p.ready <- txn:
	default:
	}
}
func liveSASWait(t *testing.T, ctx context.Context, ready func() bool) {
	t.Helper()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if ready() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("live verification stage timed out")
		case <-tick.C:
		}
	}
}

// The peer uses mautrix's helper solely as a test driver. Both directions use
// the production controller on the unverified device. All accounts/data are disposable;
// assertions print no message bodies, credentials, public keys or emoji.
func TestE2ESASDuringNormalSync(t *testing.T)         { sasDuringNormalSync(t, false, false) }
func TestE2EOutgoingSASDuringNormalSync(t *testing.T) { sasDuringNormalSync(t, false, true) }
func TestE2EManagedCryptoSASDuringNormalSync(t *testing.T) {
	if !supportsManagedCryptoBackground() {
		t.Skip("requires explicit managed mautrix dependency")
	}
	sasDuringNormalSync(t, true, false)
}
func TestE2EManagedCryptoOutgoingSASDuringNormalSync(t *testing.T) {
	if !supportsManagedCryptoBackground() {
		t.Skip("requires explicit managed mautrix dependency")
	}
	sasDuringNormalSync(t, true, true)
}
func sasDuringNormalSync(t *testing.T, managed, outgoing bool) {
	hs := e2eHomeserver(t)
	u, err := url.Parse(hs)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || os.Getenv("RIHMA_E2E_DISPOSABLE") != "1" {
		t.Skip("owned loopback fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	name, password := "sas-"+e2eTag(), "disposable-test-password"
	registration, err := mautrix.NewClient(hs, "", "")
	if err != nil {
		t.Fatal("registration preparation failed")
	}
	registration.Log = zerolog.Nop()
	if _, err := registration.RegisterDummy(ctx, &mautrix.ReqRegister[any]{Username: name, Password: password, InhibitLogin: true}); err != nil {
		t.Fatal("registration failed")
	}
	open := func(dir string) *Client {
		opts := e2eOptions(t, hs, name, password, dir)
		opts.Logger = zerolog.Nop()
		opts.SyncPolicy = SyncPolicyFullClient
		opts.ManagedCryptoBackground = managed
		c, err := Open(ctx, opts)
		if err != nil {
			t.Fatal("device login failed")
		}
		return c
	}
	first := open(t.TempDir())
	recovery, err := first.CreateRecoveryKey(ctx, "")
	if err != nil || recovery == "" {
		first.Close()
		t.Fatal("identity creation failed")
	}
	if err := first.EnableKeyBackup(ctx, recovery); err != nil {
		first.Close()
		t.Fatal("backup creation failed")
	}
	secondOpts := e2eOptions(t, hs, name, password, t.TempDir())
	secondOpts.Logger = zerolog.Nop()
	secondOpts.SyncPolicy = SyncPolicyFullClient
	secondOpts.ManagedCryptoBackground = managed
	second, err := Open(ctx, secondOpts)
	if err != nil {
		first.Close()
		t.Fatal("second device login failed")
	}
	controller, err := second.EnableSAS()
	if err != nil {
		first.Close()
		second.Close()
		t.Fatal("controller preparation failed")
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
	var mu sync.Mutex
	seen := map[id.EventID]bool{}
	second.Handlers().OnEventType(event.EventMessage, func(_ context.Context, ev *event.Event) {
		if ev.Mautrix.WasEncrypted {
			mu.Lock()
			seen[ev.ID] = true
			mu.Unlock()
		}
	})
	stopFirst := runPolicySync(t, first)
	stopSecond := runPolicySync(t, second)
	t.Cleanup(func() {
		stopSecond()
		stopFirst()
		gate.mu.Lock()
		gate.active = false
		gate.mu.Unlock()
		store.close()
		_ = peer.DismissVerification(context.Background(), "")
		second.Close()
		first.Close()
	})
	created, err := first.CreateRoom(ctx, &mautrix.ReqCreateRoom{Preset: "private_chat", InitialState: []*event.Event{{Type: event.StateEncryption, Content: event.Content{Parsed: &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}}}}})
	if err != nil {
		t.Fatal("encrypted room failed")
	}
	room := created.RoomID
	liveSASWait(t, ctx, func() bool {
		a, e := first.StateStore.IsEncrypted(ctx, room)
		b, f := second.StateStore.IsEncrypted(ctx, room)
		return e == nil && f == nil && a && b
	})
	transact := func(mode string) {
		var txn id.VerificationTransactionID
		var err error
		if outgoing {
			txn, err = controller.Start(ctx)
		} else {
			txn, err = peer.StartVerification(ctx, first.UserID)
		}
		if err != nil {
			t.Fatal("outgoing test request failed")
		}
		if outgoing {
			if s := controller.Snapshot(); s.TransactionID != txn || s.State != SASSent {
				t.Fatal("outgoing receipt not published")
			}
			requested := false
			for !requested {
				select {
				case ev := <-peerCB.events:
					requested = ev.txn == txn && ev.requested
				case <-ctx.Done():
					t.Fatal("outgoing delivery timed out")
				}
			}
		} else {
			liveSASWait(t, ctx, func() bool { s := controller.Snapshot(); return s.TransactionID == txn && s.State == SASRequested })
		}
		// Sending while the verification prompt waits must not start a second sync.
		sent, err := first.SendText(ctx, room, "synthetic verification fixture")
		if err != nil {
			t.Fatal("send during verification failed")
		}
		liveSASWait(t, ctx, func() bool { mu.Lock(); defer mu.Unlock(); return seen[sent.EventID] })
		if mode == "cancel" {
			if err := controller.Cancel(ctx, txn); err != nil {
				t.Fatal("cancel failed")
			}
			return
		}
		if outgoing {
			if err := peer.AcceptVerification(ctx, txn); err != nil {
				t.Fatal("peer acceptance failed")
			}
		} else {
			if err := controller.Accept(ctx, txn); err != nil {
				t.Fatal("accept failed")
			}
			select {
			case ready := <-peerCB.ready:
				if ready != txn {
					t.Fatal("wrong ready transaction")
				}
			case <-ctx.Done():
				t.Fatal("peer readiness timed out")
			}
			if err := peer.StartSAS(ctx, txn); err != nil {
				t.Fatal("peer SAS start failed")
			}
		}
		var peerEmoji []SASEmoji
		for peerEmoji == nil {
			select {
			case ev := <-peerCB.events:
				if ev.txn == txn && ev.emoji != nil {
					peerEmoji = ev.emoji
				}
			case <-ctx.Done():
				t.Fatal("peer SAS timed out")
			}
		}
		liveSASWait(t, ctx, func() bool { return controller.Snapshot().State == SASShowing })
		if !reflect.DeepEqual(peerEmoji, controller.Snapshot().Emoji) {
			t.Fatal("SAS disagree")
		}
		if mode == "mismatch" {
			if err := controller.Confirm(ctx, txn, false); err != nil {
				t.Fatal("mismatch cancellation failed")
			}
			return
		}
		if err := controller.Confirm(ctx, txn, true); err != nil {
			t.Fatal("confirm failed")
		}
		if err := peer.ConfirmSAS(ctx, txn); err != nil {
			t.Fatal("peer confirmation failed")
		}
		liveSASWait(t, ctx, func() bool { return controller.Snapshot().State == SASDone })
	}
	transact("cancel")
	// The peer cancellation must be consumed before it starts its next attempt.
	liveSASWait(t, ctx, func() bool { all, _ := store.GetAllVerificationTransactions(ctx); return len(all) == 0 })
	transact("mismatch")
	liveSASWait(t, ctx, func() bool { all, _ := store.GetAllVerificationTransactions(ctx); return len(all) == 0 })
	transact("complete")
	if verdict, err := second.Verification(ctx); err != nil || verdict != Verified {
		t.Fatal("completed SAS did not verify device")
	}
	stopSecond()
	if err := second.Close(); err != nil {
		t.Fatal("close before restart failed")
	}
	secondOpts.Login = nil
	second, err = Open(ctx, secondOpts)
	if err != nil {
		t.Fatal("restart failed")
	}
	controller, err = second.EnableSAS()
	if err != nil {
		t.Fatal("restart controller failed")
	}
	if controller.Snapshot().State != SASIdle {
		t.Fatal("pending verification survived restart")
	}
	stopSecond = runPolicySync(t, second)
	if verdict, err := second.Verification(ctx); err != nil || verdict != Verified {
		t.Fatal("verification trust lost on restart")
	}
}
