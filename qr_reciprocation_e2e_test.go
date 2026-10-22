//go:build e2e

package rihma

// Live counterparts of qr_reciprocation_test.go. Each test registers a
// fresh account on the owned disposable Synapse, opens fresh devices,
// runs the upstream helper through ordinary rihma Sync, and reads
// published trust back from the server with keys/query. Only key ids
// are compared; no QR payload, shared secret or signature value is
// printed or kept beyond the test's bounded channels.

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type qrLivePeer struct {
	c      *Client
	fault  *qrLiveFault
	helper *verificationhelper.VerificationHelper
	store  *sasStore
	gate   *sasEventGate
	cb     *qrProofCallbacks
}

type qrLiveAccount struct {
	ctx   context.Context
	user  id.UserID
	peers []*qrLivePeer
}

// newQRLiveAccount opens n fresh devices on a fresh account. The first
// creates the cross-signing identity and holds its private keys; the
// others trust nothing. Every device knows every other before Sync.
func newQRLiveAccount(t *testing.T, n int) *qrLiveAccount {
	t.Helper()
	hs := e2eHomeserver(t)
	u, err := url.Parse(hs)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || os.Getenv("RIHMA_E2E_DISPOSABLE") != "1" {
		t.Skip("owned loopback fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	ctx = zerolog.Nop().WithContext(ctx)
	name, password := "qrr-"+e2eTag(), "disposable-test-password"
	registration, err := mautrix.NewClient(hs, "", "")
	if err != nil {
		t.Fatal("QR fixture preparation failed")
	}
	registration.Log = zerolog.Nop()
	if _, err := registration.RegisterDummy(ctx, &mautrix.ReqRegister[any]{Username: name, Password: password, InhibitLogin: true}); err != nil {
		t.Fatal("QR fixture registration failed")
	}
	acct := &qrLiveAccount{ctx: ctx}
	for i := 0; i < n; i++ {
		opts := e2eOptions(t, hs, name, password, t.TempDir())
		opts.Logger = zerolog.Nop()
		opts.SyncPolicy = SyncPolicyFullClient
		c, err := Open(ctx, opts)
		if err != nil {
			t.Fatal("QR fixture login failed")
		}
		t.Cleanup(func() { c.Close() })
		// Install the fault transport before anything else uses the client
		// concurrently; tests arm it through its own lock while Sync runs.
		base := c.Client.Client.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		fault := &qrLiveFault{base: base}
		c.Client.Client.Transport = fault
		if i == 0 {
			recovery, err := c.CreateRecoveryKey(ctx, "")
			if err != nil || recovery == "" {
				t.Fatal("QR fixture identity failed")
			}
			recovery = ""
		}
		acct.user = c.UserID
		acct.peers = append(acct.peers, &qrLivePeer{c: c, fault: fault})
	}
	for _, p := range acct.peers {
		if _, err := p.c.OlmMachine().FetchKeys(ctx, []id.UserID{acct.user}, true); err != nil {
			t.Fatal("QR fixture device list failed")
		}
		if _, err := p.c.OlmMachine().GetOwnCrossSigningPublicKeys(ctx); err != nil {
			t.Fatal("QR fixture identity cache failed")
		}
		p.store = newSASStore()
		p.gate = &sasEventGate{active: true, store: p.store, recent: make(map[id.VerificationTransactionID]time.Time)}
		p.cb = &qrProofCallbacks{sasCallbacks: sasCallbacks{events: make(chan sasEvent, 32), overflow: make(chan struct{}, 1)}, ready: make(chan qrProofReady, 4), scanned: make(chan id.VerificationTransactionID, 4)}
		original := p.c.Client.Syncer
		p.c.Client.Syncer = &sasHandlerSyncer{DefaultSyncer: p.c.Handlers(), underlying: p.c.Handlers(), gate: p.gate, user: p.c.UserID, device: p.c.DeviceID}
		p.helper = verificationhelper.NewVerificationHelper(p.c.Client, p.c.OlmMachine(), p.store, p.cb, true, true, false)
		err := p.helper.Init(ctx)
		p.c.Client.Syncer = original
		if err != nil {
			t.Fatal("QR helper initialization failed")
		}
		gate, store, cb := p.gate, p.store, p.cb
		t.Cleanup(func() {
			gate.mu.Lock()
			gate.active = false
			gate.mu.Unlock()
			store.close()
			for len(cb.ready) > 0 {
				clear((<-cb.ready).data)
			}
		})
	}
	for _, p := range acct.peers {
		runPolicySync(t, p.c)
	}
	return acct
}

// show runs a request from display to scanner up to display's code and
// checks its mode. The caller clears the returned code.
func (acct *qrLiveAccount) show(t *testing.T, display, scanner *qrLivePeer, mode verificationhelper.QRCodeMode) (id.VerificationTransactionID, []byte) {
	t.Helper()
	display.gate.mu.Lock()
	txn, err := display.helper.StartVerification(acct.ctx, acct.user)
	display.gate.mu.Unlock()
	if err != nil {
		t.Fatal("QR request failed")
	}
	qrProofWaitEvent(t, acct.ctx, scanner.cb, txn, true)
	if err := scanner.helper.AcceptVerification(acct.ctx, txn); err != nil {
		t.Fatal("QR accept failed")
	}
	code := qrProofWaitCode(t, acct.ctx, display.cb, txn)
	parsed, err := verificationhelper.NewQRCodeFromBytes(code)
	if err != nil || parsed.Mode != mode {
		clear(code)
		t.Fatal("QR display mode differs")
	}
	return txn, code
}

func (acct *qrLiveAccount) waitScanned(t *testing.T, display *qrLivePeer, txn id.VerificationTransactionID) {
	t.Helper()
	select {
	case got := <-display.cb.scanned:
		if got != txn {
			t.Fatal("QR scan reported for another transaction")
		}
	case <-acct.ctx.Done():
		t.Fatal("QR scan report timed out")
	}
}

// waitCancelled returns the cancellation code p's helper reported for txn.
func (acct *qrLiveAccount) waitCancelled(t *testing.T, p *qrLivePeer, txn id.VerificationTransactionID) event.VerificationCancelCode {
	t.Helper()
	for {
		select {
		case ev := <-p.cb.events:
			if ev.txn == txn && ev.cancelled != "" {
				return ev.cancelled
			}
			if ev.txn == txn && ev.done {
				t.Fatal("QR verification finished instead of cancelling")
			}
		case <-acct.ctx.Done():
			t.Fatal("QR cancellation timed out")
		}
	}
}

// waitIdle waits until none of the peers holds a transaction, so the
// next request is not dropped as busy.
func (acct *qrLiveAccount) waitIdle(t *testing.T) {
	t.Helper()
	liveSASWait(t, acct.ctx, func() bool {
		for _, p := range acct.peers {
			if all, _ := p.store.GetAllVerificationTransactions(acct.ctx); len(all) != 0 {
				return false
			}
		}
		return true
	})
}

// qrLivePublished is what the server publishes for the account: which
// key ids signed the master key and each device.
type qrLivePublished struct {
	master  map[id.KeyID]bool
	devices map[id.DeviceID]map[id.KeyID]bool
	ssk     id.KeyID
}

func (acct *qrLiveAccount) published(t *testing.T, via *qrLivePeer) qrLivePublished {
	t.Helper()
	resp, err := via.c.Client.QueryKeys(acct.ctx, &mautrix.ReqQueryKeys{DeviceKeys: mautrix.DeviceKeysRequest{acct.user: mautrix.DeviceIDList{}}})
	if err != nil {
		t.Fatal("QR published key query failed")
	}
	out := qrLivePublished{master: map[id.KeyID]bool{}, devices: map[id.DeviceID]map[id.KeyID]bool{}}
	for keyID := range resp.MasterKeys[acct.user].Signatures[acct.user] {
		out.master[keyID] = true
	}
	for device, keys := range resp.DeviceKeys[acct.user] {
		out.devices[device] = map[id.KeyID]bool{}
		for keyID := range keys.Signatures[acct.user] {
			out.devices[device][keyID] = true
		}
	}
	ssk := resp.SelfSigningKeys[acct.user]
	out.ssk = id.NewKeyID(id.KeyAlgorithmEd25519, ssk.FirstKey().String())
	return out
}

func (p qrLivePublished) masterBy(d *qrLivePeer) bool {
	return p.master[id.NewKeyID(id.KeyAlgorithmEd25519, d.c.DeviceID.String())]
}

func (p qrLivePublished) crossSigned(d *qrLivePeer) bool { return p.devices[d.c.DeviceID][p.ssk] }

// localMaster reports whether p's store holds its own signature on the master key.
func (acct *qrLiveAccount) localMaster(t *testing.T, p *qrLivePeer) bool {
	t.Helper()
	mach := p.c.OlmMachine()
	keys, err := mach.GetOwnCrossSigningPublicKeys(acct.ctx)
	if err != nil || keys == nil {
		t.Fatal("QR master identity not cached")
	}
	signed, err := mach.CryptoStore.IsKeySignedBy(acct.ctx, acct.user, keys.MasterKey, acct.user, mach.OwnIdentity().SigningKey)
	if err != nil {
		t.Fatal("QR master trust query failed")
	}
	return signed
}

// localVerified reports whether p's store marks peer's device verified.
func (acct *qrLiveAccount) localVerified(t *testing.T, p, peer *qrLivePeer) bool {
	t.Helper()
	dev, err := p.c.OlmMachine().CryptoStore.GetDevice(acct.ctx, acct.user, peer.c.DeviceID)
	if err != nil || dev == nil {
		t.Fatal("QR peer device lookup failed")
	}
	return dev.Trust == id.TrustStateVerified
}

func (acct *qrLiveAccount) verdict(t *testing.T, p *qrLivePeer) Verdict {
	t.Helper()
	v, err := p.c.Verification(acct.ctx)
	if err != nil {
		t.Fatal("QR verification verdict failed")
	}
	return v
}

// A wrong shared secret: Synapse publishes the scanner's master
// signature although the display cancelled, and the scanner's device
// stays without a cross-signature, so its verdict stays Unverified.
func TestE2EQRWrongSecretPublishesScannerTrust(t *testing.T) {
	acct := newQRLiveAccount(t, 2)
	display, scanner := acct.peers[0], acct.peers[1]
	if acct.verdict(t, scanner) == Verified || acct.published(t, display).masterBy(scanner) {
		t.Fatal("QR fixture already trusted")
	}
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	code[len(code)-1] ^= 1
	err := scanQR(acct.ctx, txn, code, scanner.helper)
	clear(code)
	if err != nil {
		t.Fatal("QR wrong-secret scan was refused before the helper")
	}
	if c := acct.waitCancelled(t, display, txn); c != event.VerificationCancelCodeKeyMismatch {
		t.Fatal("QR display did not cancel with a key mismatch")
	}
	if c := acct.waitCancelled(t, scanner, txn); c != event.VerificationCancelCodeKeyMismatch {
		t.Fatal("QR scanner did not see the cancellation")
	}
	pub := acct.published(t, display)
	if !acct.localMaster(t, scanner) || !pub.masterBy(scanner) {
		t.Fatal("QR wrong secret withdrew or never published the scanner's master signature")
	}
	if pub.crossSigned(scanner) || acct.localVerified(t, display, scanner) {
		t.Fatal("QR display trusted a scanner that sent a wrong secret")
	}
	if acct.verdict(t, scanner) == Verified {
		t.Fatal("QR wrong secret verified the scanner's device")
	}
}

// The display cancels after the scan, before confirming: as for a wrong
// secret, the scanner's master signature stays published.
func TestE2EQRDisplayCancelAfterScanPublishesScannerTrust(t *testing.T) {
	acct := newQRLiveAccount(t, 2)
	display, scanner := acct.peers[0], acct.peers[1]
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	err := scanQR(acct.ctx, txn, code, scanner.helper)
	clear(code)
	if err != nil {
		t.Fatal("QR scan failed")
	}
	acct.waitScanned(t, display, txn)
	if err := display.helper.CancelVerification(acct.ctx, txn, event.VerificationCancelCodeUser, ""); err != nil {
		t.Fatal("QR display cancel failed")
	}
	if c := acct.waitCancelled(t, scanner, txn); c != event.VerificationCancelCodeUser {
		t.Fatal("QR scanner did not see the cancellation")
	}
	pub := acct.published(t, display)
	if !acct.localMaster(t, scanner) || !pub.masterBy(scanner) {
		t.Fatal("QR cancellation withdrew the scanner's master signature")
	}
	if pub.crossSigned(scanner) || acct.verdict(t, scanner) == Verified {
		t.Fatal("QR cancelled display cross-signed the scanner")
	}
}

// qrLiveFault fails one request whose path contains the armed part,
// before it reaches the server. It is installed on every fixture client
// before Sync starts, so arming it never replaces a transport in use.
type qrLiveFault struct {
	base http.RoundTripper
	mu   sync.Mutex
	part string
}

func (f *qrLiveFault) arm(part string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.part = part
}

func (f *qrLiveFault) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	hit := f.part != "" && strings.Contains(r.URL.Path, f.part)
	if hit {
		f.part = ""
	}
	f.mu.Unlock()
	if hit {
		return nil, errQRLiveFault
	}
	return f.base.RoundTrip(r)
}

type qrLiveFaultError struct{}

func (qrLiveFaultError) Error() string { return "injected transport fault" }

var errQRLiveFault error = qrLiveFaultError{}

// The reciprocation fails to send: Synapse already publishes the
// scanner's master signature while the display has seen nothing. A retry
// of the same code then completes, and the device is verified.
func TestE2EQRStartSendFailurePublishesBeforeReciprocation(t *testing.T) {
	acct := newQRLiveAccount(t, 2)
	display, scanner := acct.peers[0], acct.peers[1]
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	defer clear(code)
	scanner.fault.arm("/sendToDevice/m.key.verification.start/")
	if err := scanQR(acct.ctx, txn, code, scanner.helper); err == nil {
		t.Fatal("QR failed reciprocation send was not reported")
	}
	if !acct.published(t, display).masterBy(scanner) {
		t.Fatal("QR scanner signature was not published before the reciprocation")
	}
	select {
	case <-display.cb.scanned:
		t.Fatal("QR display saw a reciprocation that was never sent")
	case <-time.After(2 * time.Second):
	}
	if err := scanQR(acct.ctx, txn, code, scanner.helper); err != nil {
		t.Fatal("QR retried scan failed")
	}
	acct.waitScanned(t, display, txn)
	if err := display.helper.ConfirmQRCodeScanned(acct.ctx, txn); err != nil {
		t.Fatal("QR display confirmation failed")
	}
	qrProofWaitEvent(t, acct.ctx, display.cb, txn, false)
	qrProofWaitEvent(t, acct.ctx, scanner.cb, txn, false)
	if acct.verdict(t, scanner) != Verified {
		t.Fatal("QR retried verification did not verify the device")
	}
}

// Reverse mode: an untrusted display and a trusted scanner holding the
// self-signing key. Synapse publishes the display's cross-signature at
// scan time, before the display confirms; after confirmation the display
// also signs the master and is Verified.
func TestE2EQRReverseModeVerifiesDisplay(t *testing.T) {
	acct := newQRLiveAccount(t, 2)
	scanner, display := acct.peers[0], acct.peers[1]
	if acct.verdict(t, display) == Verified {
		t.Fatal("QR fixture already trusted")
	}
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyUntrusted)
	err := scanQR(acct.ctx, txn, code, scanner.helper)
	clear(code)
	if err != nil {
		t.Fatal("QR reverse-mode scan failed")
	}
	acct.waitScanned(t, display, txn)
	pub := acct.published(t, scanner)
	if !pub.crossSigned(display) || !acct.localVerified(t, scanner, display) {
		t.Fatal("QR reverse-mode scan did not publish the display's cross-signature")
	}
	if pub.masterBy(display) || acct.localMaster(t, display) {
		t.Fatal("QR display trusted the master before confirming")
	}
	if err := display.helper.ConfirmQRCodeScanned(acct.ctx, txn); err != nil {
		t.Fatal("QR display confirmation failed")
	}
	qrProofWaitEvent(t, acct.ctx, display.cb, txn, false)
	qrProofWaitEvent(t, acct.ctx, scanner.cb, txn, false)
	if !acct.published(t, scanner).masterBy(display) || !acct.localMaster(t, display) {
		t.Fatal("QR display did not sign the master at confirmation")
	}
	if acct.verdict(t, display) != Verified {
		t.Fatal("QR reverse mode did not verify the display")
	}
}

// Reverse mode with a wrong secret: the trusted scanner has already
// published the display's cross-signature when the display cancels.
// The display does not trust the master, and its own verdict stays
// Unverified, but the server lists its device as cross-signed.
func TestE2EQRReverseModeWrongSecretPublishesDeviceSignature(t *testing.T) {
	acct := newQRLiveAccount(t, 2)
	scanner, display := acct.peers[0], acct.peers[1]
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyUntrusted)
	code[len(code)-1] ^= 1
	err := scanQR(acct.ctx, txn, code, scanner.helper)
	clear(code)
	if err != nil {
		t.Fatal("QR reverse-mode scan failed")
	}
	if c := acct.waitCancelled(t, display, txn); c != event.VerificationCancelCodeKeyMismatch {
		t.Fatal("QR display did not cancel with a key mismatch")
	}
	acct.waitCancelled(t, scanner, txn)
	pub := acct.published(t, scanner)
	if !pub.crossSigned(display) || !acct.localVerified(t, scanner, display) {
		t.Fatal("QR wrong secret withdrew the display's cross-signature")
	}
	if pub.masterBy(display) || acct.localMaster(t, display) {
		t.Fatal("QR display trusted the master after a wrong secret")
	}
	if acct.verdict(t, display) == Verified {
		t.Fatal("QR display reports Verified after cancelling")
	}
}

// A display that trusts the master without the self-signing private key
// is the state a device is left in by a QR scan or SAS. It still shows a
// trusted-mode code, both sides reach done, and the scanner's device is
// never cross-signed, so it stays Unverified.
func TestE2EQRTrustedDisplayWithoutSelfSigningKeyLeavesScannerUnverified(t *testing.T) {
	acct := newQRLiveAccount(t, 3)
	owner, middle, fresh := acct.peers[0], acct.peers[1], acct.peers[2]
	// The owner verifies middle; middle then trusts the master and is
	// cross-signed, but holds no private cross-signing key.
	txn, code := acct.show(t, owner, middle, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	err := scanQR(acct.ctx, txn, code, middle.helper)
	clear(code)
	if err != nil {
		t.Fatal("QR first scan failed")
	}
	acct.waitScanned(t, owner, txn)
	if err := owner.helper.ConfirmQRCodeScanned(acct.ctx, txn); err != nil {
		t.Fatal("QR first confirmation failed")
	}
	qrProofWaitEvent(t, acct.ctx, owner.cb, txn, false)
	qrProofWaitEvent(t, acct.ctx, middle.cb, txn, false)
	if acct.verdict(t, middle) != Verified || middle.c.OlmMachine().CrossSigningKeys != nil {
		t.Fatal("QR fixture did not leave a verified device without private keys")
	}
	acct.waitIdle(t)
	txn, code = acct.show(t, middle, fresh, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	err = scanQR(acct.ctx, txn, code, fresh.helper)
	clear(code)
	if err != nil {
		t.Fatal("QR second scan failed")
	}
	acct.waitScanned(t, middle, txn)
	if err := middle.helper.ConfirmQRCodeScanned(acct.ctx, txn); err != nil {
		t.Fatal("QR confirmation without the self-signing key was refused")
	}
	qrProofWaitEvent(t, acct.ctx, middle.cb, txn, false)
	qrProofWaitEvent(t, acct.ctx, fresh.cb, txn, false)
	pub := acct.published(t, owner)
	if !pub.masterBy(fresh) || !acct.localMaster(t, fresh) || !acct.localVerified(t, middle, fresh) {
		t.Fatal("QR second verification trust differs")
	}
	if pub.crossSigned(fresh) || acct.verdict(t, fresh) == Verified {
		t.Fatal("QR display without the self-signing key cross-signed the scanner")
	}
}
