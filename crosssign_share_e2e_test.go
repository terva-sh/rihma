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
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/id"
)

// testPeer drives the other side of SAS with mautrix's helper on a rihma
// client. Create it before the client syncs: Init registers handlers.
type testPeer struct {
	helper *verificationhelper.VerificationHelper
	cb     *sasPeerCallbacks
}

func newTestPeer(t *testing.T, ctx context.Context, c *Client) *testPeer {
	t.Helper()
	cb := &sasPeerCallbacks{sasCallbacks: sasCallbacks{events: make(chan sasEvent, 32), overflow: make(chan struct{}, 1)}, ready: make(chan id.VerificationTransactionID, 4)}
	store := newSASStore()
	gate := &sasEventGate{active: true}
	original := c.Client.Syncer
	c.Client.Syncer = &sasHandlerSyncer{DefaultSyncer: c.Handlers(), underlying: c.Handlers(), gate: gate, user: c.UserID, device: c.DeviceID}
	helper := verificationhelper.NewVerificationHelper(c.Client, c.OlmMachine(), store, cb, false, false, true)
	if err := helper.Init(ctx); err != nil {
		t.Fatal("peer helper failed")
	}
	c.Client.Syncer = original
	t.Cleanup(func() {
		gate.mu.Lock()
		gate.active = false
		gate.mu.Unlock()
		store.close()
		_ = helper.DismissVerification(context.Background(), "")
	})
	return &testPeer{helper: helper, cb: cb}
}

// verify has the peer ask the controller's device to verify it and runs SAS
// to completion on both sides.
func (p *testPeer) verify(t *testing.T, ctx context.Context, user id.UserID, controller *SASController) {
	t.Helper()
	txn, err := p.helper.StartVerification(ctx, user)
	if err != nil {
		t.Fatal("verification request failed")
	}
	liveSASWait(t, ctx, func() bool { s := controller.Snapshot(); return s.TransactionID == txn && s.State == SASRequested })
	if err := controller.Accept(ctx, txn); err != nil {
		t.Fatal("accept failed")
	}
	for ready := false; !ready; {
		select {
		case got := <-p.cb.ready:
			ready = got == txn
		case <-ctx.Done():
			t.Fatal("peer readiness timed out")
		}
	}
	if err := p.helper.StartSAS(ctx, txn); err != nil {
		t.Fatal("peer SAS start failed")
	}
	liveSASWait(t, ctx, func() bool { return controller.Snapshot().State == SASShowing })
	if err := controller.Confirm(ctx, txn, true); err != nil {
		t.Fatal("confirm failed")
	}
	if err := p.helper.ConfirmSAS(ctx, txn); err != nil {
		t.Fatal("peer confirmation failed")
	}
	liveSASWait(t, ctx, func() bool { return controller.Snapshot().State == SASDone })
}

// A device verified by SAS gets the cross-signing keys from the device that
// verified it, keeps them across a restart, and then verifies another new
// device on its own. An unverified device gets nothing. Accounts are
// disposable; assertions print no keys.
func TestE2EVerifiedDeviceVerifiesTheNext(t *testing.T) {
	hs := e2eHomeserver(t)
	u, err := url.Parse(hs)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || os.Getenv("RIHMA_E2E_DISPOSABLE") != "1" {
		t.Skip("owned loopback fixture required")
	}
	defer func(old time.Duration) { shareRequestInterval = old }(shareRequestInterval)
	shareRequestInterval = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	name, password := "xsign-"+e2eTag(), "disposable-test-password"
	register(t, ctx, hs, name, password)
	open := func(dir string, login bool) *Client {
		opts := e2eOptions(t, hs, name, password, dir)
		opts.Logger = zerolog.Nop()
		opts.SyncPolicy = SyncPolicyFullClient
		if !login {
			opts.Login = nil
		}
		c, err := Open(ctx, opts)
		if err != nil {
			t.Fatal("device open failed")
		}
		t.Cleanup(func() { c.Close() })
		return c
	}

	first := open(t.TempDir(), true)
	if recovery, err := first.CreateRecoveryKey(ctx, ""); err != nil || recovery == "" {
		t.Fatal("identity creation failed")
	}
	if !first.HasCrossSigningKeys() {
		t.Fatal("the creating device does not hold its cross-signing keys")
	}
	peer := newTestPeer(t, ctx, first)
	stopFirst := runPolicySync(t, first)

	stranger := open(t.TempDir(), true)
	if err := stranger.RequestCrossSigningKeys(ctx, 3*time.Second); !errors.Is(err, ErrCrossSigningKeysNotShared) {
		t.Fatalf("unverified device request = %v, want ErrCrossSigningKeysNotShared", err)
	}
	if stranger.HasCrossSigningKeys() {
		t.Fatal("unverified device received cross-signing keys")
	}

	secondDir := t.TempDir()
	second := open(secondDir, true)
	controller, err := second.EnableSAS()
	if err != nil {
		t.Fatal("controller preparation failed")
	}
	stopSecond := runPolicySync(t, second)
	peer.verify(t, ctx, first.UserID, controller)
	if err := second.RequestCrossSigningKeys(ctx, 30*time.Second); err != nil {
		t.Fatalf("verified device request failed: %v", err)
	}
	if !second.HasCrossSigningKeys() {
		t.Fatal("verified device holds no cross-signing keys")
	}

	// The keys survive a restart, and the first device is gone from here on.
	stopFirst()
	stopSecond()
	if err := second.Close(); err != nil {
		t.Fatal("close before restart failed")
	}
	second = open(secondDir, false)
	controller, err = second.EnableSAS()
	if err != nil {
		t.Fatal("restart controller failed")
	}
	runPolicySync(t, second)
	liveSASWait(t, ctx, second.HasCrossSigningKeys)

	third := open(t.TempDir(), true)
	thirdPeer := newTestPeer(t, ctx, third)
	runPolicySync(t, third)
	if verdict, err := third.Verification(ctx); err != nil || verdict != Unverified {
		t.Fatal("new device should start unverified")
	}
	thirdPeer.verify(t, ctx, third.UserID, controller)
	liveSASWait(t, ctx, func() bool { verdict, err := third.Verification(ctx); return err == nil && verdict == Verified })

	// After another device resets the identity, the old keys are dropped at
	// the next start rather than used to sign.
	if _, err := third.ResetCrossSigningIdentity(ctx, CrossSigningAuth{Password: password}); err != nil {
		t.Fatal("identity reset failed")
	}
	if err := second.Close(); err != nil {
		t.Fatal("close before second restart failed")
	}
	second = open(secondDir, false)
	if err := second.Connect(ctx); err != nil {
		t.Fatal("connect after reset failed")
	}
	if second.HasCrossSigningKeys() {
		t.Fatal("keys from before the reset were loaded")
	}
	for _, secret := range crossSigningSecrets {
		for _, name := range []id.Secret{secret.name, secret.kept} {
			if stored, err := second.OlmMachine().CryptoStore.GetSecret(ctx, name); err != nil || stored != "" {
				t.Fatal("keys from before the reset were kept")
			}
		}
	}
}
