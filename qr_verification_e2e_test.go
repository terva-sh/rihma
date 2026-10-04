//go:build e2e

package rihma

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/id"
)

// This is a dependency proof, not a production QR API. QR payloads stay in
// bounded private test channels and are cleared without printing their contents.
type qrProofReady struct {
	txn  id.VerificationTransactionID
	data []byte
}

type qrProofCallbacks struct {
	sasCallbacks
	ready   chan qrProofReady
	scanned chan id.VerificationTransactionID
}

func (q *qrProofCallbacks) VerificationReady(_ context.Context, txn id.VerificationTransactionID, _ id.DeviceID, _ bool, _ bool, code *verificationhelper.QRCode) {
	data := code.Bytes()
	select {
	case q.ready <- qrProofReady{txn: txn, data: data}:
	default:
		clear(data)
		q.post(sasEvent{txn: txn, cancelled: "m.test_overflow"})
	}
}

func (q *qrProofCallbacks) QRCodeScanned(_ context.Context, txn id.VerificationTransactionID) {
	select {
	case q.scanned <- txn:
	default:
		q.post(sasEvent{txn: txn, cancelled: "m.test_overflow"})
	}
}

func qrProofWaitEvent(t *testing.T, ctx context.Context, callbacks *qrProofCallbacks, txn id.VerificationTransactionID, requested bool) {
	t.Helper()
	for {
		select {
		case ev := <-callbacks.events:
			if ev.txn == txn {
				if requested && ev.requested || !requested && ev.done {
					return
				}
				if ev.cancelled != "" {
					t.Fatal("QR proof unexpectedly cancelled")
				}
			}
		case <-ctx.Done():
			t.Fatal("QR proof stage timed out")
		}
	}
}

func qrProofWaitCode(t *testing.T, ctx context.Context, callbacks *qrProofCallbacks, txn id.VerificationTransactionID) []byte {
	t.Helper()
	for {
		select {
		case ready := <-callbacks.ready:
			if ready.txn == txn {
				if len(ready.data) == 0 {
					t.Fatal("QR proof display not available")
				}
				return ready.data
			}
			clear(ready.data)
		case <-ctx.Done():
			t.Fatal("QR proof display timed out")
		}
	}
}

func TestE2EQRTrustedDisplayUntrustedScan(t *testing.T) {
	hs := e2eHomeserver(t)
	u, err := url.Parse(hs)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || os.Getenv("RIHMA_E2E_DISPOSABLE") != "1" {
		t.Skip("owned loopback fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ctx = zerolog.Nop().WithContext(ctx)
	name, password := "qr-"+e2eTag(), "disposable-test-password"
	registration, err := mautrix.NewClient(hs, "", "")
	if err != nil {
		t.Fatal("QR fixture preparation failed")
	}
	registration.Log = zerolog.Nop()
	if _, err := registration.RegisterDummy(ctx, &mautrix.ReqRegister[any]{Username: name, Password: password, InhibitLogin: true}); err != nil {
		t.Fatal("QR fixture registration failed")
	}
	open := func() *Client {
		opts := e2eOptions(t, hs, name, password, t.TempDir())
		opts.Logger = zerolog.Nop()
		opts.SyncPolicy = SyncPolicyFullClient
		c, err := Open(ctx, opts)
		if err != nil {
			t.Fatal("QR fixture login failed")
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	trusted := open()
	recovery, err := trusted.CreateRecoveryKey(ctx, "")
	if err != nil || recovery == "" {
		t.Fatal("QR fixture identity failed")
	}
	if err := trusted.EnableKeyBackup(ctx, recovery); err != nil {
		t.Fatal("QR fixture backup failed")
	}
	recovery = ""
	untrusted := open()
	prepare := func(c *Client) (*verificationhelper.VerificationHelper, *sasStore, *sasEventGate, *qrProofCallbacks) {
		store := newSASStore()
		gate := &sasEventGate{active: true, store: store, recent: make(map[id.VerificationTransactionID]time.Time)}
		callbacks := &qrProofCallbacks{sasCallbacks: sasCallbacks{events: make(chan sasEvent, 32), overflow: make(chan struct{}, 1)}, ready: make(chan qrProofReady, 4), scanned: make(chan id.VerificationTransactionID, 4)}
		original := c.Client.Syncer
		c.Client.Syncer = &sasHandlerSyncer{DefaultSyncer: c.Handlers(), underlying: c.Handlers(), gate: gate, user: c.UserID, device: c.DeviceID}
		helper := verificationhelper.NewVerificationHelper(c.Client, c.OlmMachine(), store, callbacks, true, true, false)
		err := helper.Init(ctx)
		c.Client.Syncer = original
		if err != nil {
			t.Fatal("QR helper initialization failed")
		}
		t.Cleanup(func() {
			gate.mu.Lock()
			gate.active = false
			gate.mu.Unlock()
			store.close()
			_ = helper.DismissVerification(context.Background(), "")
			for len(callbacks.ready) > 0 {
				clear((<-callbacks.ready).data)
			}
		})
		return helper, store, gate, callbacks
	}
	display, displayStore, displayGate, displayCB := prepare(trusted)
	scanner, scanStore, _, scanCB := prepare(untrusted)
	stopDisplay := runPolicySync(t, trusted)
	stopScan := runPolicySync(t, untrusted)
	t.Cleanup(func() { stopScan(); stopDisplay() })
	request := func() (id.VerificationTransactionID, []byte) {
		// The upstream initiator saves after send; serialize fast ready admission.
		displayGate.mu.Lock()
		txn, err := display.StartVerification(ctx, trusted.UserID)
		displayGate.mu.Unlock()
		if err != nil {
			t.Fatal("QR proof request failed")
		}
		qrProofWaitEvent(t, ctx, scanCB, txn, true)
		if err := scanner.AcceptVerification(ctx, txn); err != nil {
			t.Fatal("QR proof accept failed")
		}
		code := qrProofWaitCode(t, ctx, displayCB, txn)
		parsed, err := verificationhelper.NewQRCodeFromBytes(code)
		if err != nil || parsed.Mode != verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted {
			clear(code)
			t.Fatal("QR proof trust mode differs")
		}
		return txn, code
	}
	txn, code := request()
	before, err := untrusted.Verification(ctx)
	if err != nil || before == Verified {
		clear(code)
		t.Fatal("QR fixture already trusted")
	}
	// Change the expected master public key; no generated material is printed.
	code[10+len(txn)] ^= 1
	if err := scanQR(ctx, txn, code, scanner); err == nil {
		clear(code)
		t.Fatal("QR wrong-key code accepted")
	}
	clear(code)
	liveSASWait(t, ctx, func() bool {
		a, _ := displayStore.GetAllVerificationTransactions(ctx)
		b, _ := scanStore.GetAllVerificationTransactions(ctx)
		return len(a) == 0 && len(b) == 0
	})
	if after, err := untrusted.Verification(ctx); err != nil || after != before {
		t.Fatal("wrong-key QR changed trust")
	}
	master, err := untrusted.OlmMachine().GetOwnCrossSigningPublicKeys(ctx)
	if err != nil || master == nil {
		t.Fatal("QR master identity not cached")
	}
	masterTrusted := func() bool {
		trusted, err := untrusted.OlmMachine().CryptoStore.IsKeySignedBy(ctx, untrusted.UserID, master.MasterKey, untrusted.UserID, untrusted.OlmMachine().OwnIdentity().SigningKey)
		if err != nil {
			t.Fatal("QR master trust query failed")
		}
		return trusted
	}
	if masterTrusted() {
		t.Fatal("wrong-key QR trusted master identity")
	}
	txn, code = request()
	if err := scanQR(ctx, txn, code, scanner); err != nil {
		clear(code)
		t.Fatal("QR correct code scan failed")
	}
	clear(code)
	select {
	case scanned := <-displayCB.scanned:
		if scanned != txn {
			t.Fatal("QR scan bound to wrong transaction")
		}
	case <-ctx.Done():
		t.Fatal("QR reciprocation timed out")
	}
	// Characterize upstream timing: scanning signs the master before the display
	// side confirms completion. A future controller must disclose this boundary.
	if !masterTrusted() {
		t.Fatal("QR scanner trust timing changed; reassess dependency contract")
	}
	if err := display.ConfirmQRCodeScanned(ctx, txn); err != nil {
		t.Fatal("QR display confirmation failed")
	}
	qrProofWaitEvent(t, ctx, displayCB, txn, false)
	qrProofWaitEvent(t, ctx, scanCB, txn, false)
	if verdict, err := untrusted.Verification(ctx); err != nil || verdict != Verified {
		t.Fatal("QR completion did not verify device")
	}
}
