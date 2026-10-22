package rihma

// Tests for the QR trust characterization in docs/qr-verification.md.
// They pin what mautrix v0.31.0's verificationhelper leaves behind, in
// local and published trust, when a same-account QR verification
// succeeds, sees a wrong shared secret, fails to send, is cancelled, or
// lacks a trust or private-key prerequisite. Every test uses fresh
// devices on mautrix's mock server with in-memory stores, and scans
// through rihma's scanQR admission. A mautrix upgrade that changes any
// of these outcomes fails here, so the QR controller's contract can be
// revisited.
//
// "Local" trust is what a device's crypto store holds. "Published"
// trust is what a device's signature uploads put on the server, as a
// recording transport saw them accepted. The mock server keeps no
// signatures of its own, so the live tests in
// qr_reciprocation_e2e_test.go read published trust back from Synapse.
// Neither ever records a QR payload, shared secret or signature value.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/mockserver"
)

const qrUser = id.UserID("@alice:example.org")

var errQRTestFault = errors.New("injected transport fault")

type qrFault int

const (
	qrRefuse       qrFault = iota + 1 // the request never reaches the server
	qrLoseResponse                    // the server handles it; the client sees an error
)

// qrUpload is one signature the server accepted. It names the signed
// key and the signing key by their public identifiers only.
type qrUpload struct {
	uploader id.DeviceID
	target   string // a device id, or a master public key
	signer   id.KeyID
}

// qrNet records accepted signature uploads and injects one-shot faults.
type qrNet struct {
	mu        sync.Mutex
	published []qrUpload
	faults    map[id.DeviceID]map[string]qrFault
}

func (n *qrNet) failOnce(device id.DeviceID, pathPart string, f qrFault) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.faults[device] == nil {
		n.faults[device] = map[string]qrFault{}
	}
	n.faults[device][pathPart] = f
}

func (n *qrNet) take(device id.DeviceID, path string) qrFault {
	n.mu.Lock()
	defer n.mu.Unlock()
	for part, f := range n.faults[device] {
		if strings.Contains(path, part) {
			delete(n.faults[device], part)
			return f
		}
	}
	return 0
}

func (n *qrNet) record(uploader id.DeviceID, body []byte) {
	var req map[id.UserID]map[string]struct {
		Signatures map[id.UserID]map[id.KeyID]json.RawMessage `json:"signatures"`
	}
	if json.Unmarshal(body, &req) != nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, keys := range req {
		for target, obj := range keys {
			for _, sigs := range obj.Signatures {
				for signer := range sigs {
					n.published = append(n.published, qrUpload{uploader: uploader, target: target, signer: signer})
				}
			}
		}
	}
}

func (n *qrNet) reset() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.published = nil
}

// count reports how many accepted uploads signed target with signer.
func (n *qrNet) count(target string, signer id.KeyID) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, u := range n.published {
		if u.target == target && u.signer == signer {
			c++
		}
	}
	return c
}

func (n *qrNet) total() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.published)
}

type qrTransport struct {
	base   http.RoundTripper
	net    *qrNet
	device id.DeviceID
}

func (t *qrTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	fault := t.net.take(t.device, r.URL.Path)
	if fault == qrRefuse {
		return nil, errQRTestFault
	}
	resp, err := t.base.RoundTrip(r)
	if err == nil && resp.StatusCode == http.StatusOK && strings.HasSuffix(r.URL.Path, "/keys/signatures/upload") {
		t.net.record(t.device, body)
	}
	if fault == qrLoseResponse {
		if err == nil {
			resp.Body.Close()
		}
		return nil, errQRTestFault
	}
	return resp, err
}

// qrCallbacks adds the QR show callbacks to the SAS ones. Each shown
// code is copied into a bounded channel and cleared by its reader.
type qrCallbacks struct {
	sasCallbacks
	codes   chan []byte
	scanned chan id.VerificationTransactionID
}

func (q *qrCallbacks) VerificationReady(ctx context.Context, txn id.VerificationTransactionID, device id.DeviceID, supportsSAS bool, supportsScan bool, code *verificationhelper.QRCode) {
	if code != nil {
		data := code.Bytes()
		select {
		case q.codes <- data:
		default:
			clear(data)
		}
	}
	q.sasCallbacks.VerificationReady(ctx, txn, device, supportsSAS, supportsScan, code)
}

func (q *qrCallbacks) QRCodeScanned(_ context.Context, txn id.VerificationTransactionID) {
	select {
	case q.scanned <- txn:
	default:
	}
}

type qrPeer struct {
	client  *mautrix.Client
	machine *crypto.OlmMachine
	helper  *verificationhelper.VerificationHelper
	store   *sasStore
	cb      *qrCallbacks
}

func (p *qrPeer) device() id.DeviceID { return p.client.DeviceID }

// events returns the cancellation code and whether done arrived, from
// every callback posted so far.
func (p *qrPeer) events() (cancelled event.VerificationCancelCode, done bool) {
	for {
		select {
		case ev := <-p.cb.events:
			if ev.cancelled != "" {
				cancelled = ev.cancelled
			}
			done = done || ev.done
		default:
			return cancelled, done
		}
	}
}

func (p *qrPeer) scannedCallback() bool {
	select {
	case <-p.cb.scanned:
		return true
	default:
		return false
	}
}

func (p *qrPeer) transactions(t *testing.T, ctx context.Context) int {
	t.Helper()
	all, err := p.store.GetAllVerificationTransactions(ctx)
	if err != nil {
		t.Fatal("transaction listing failed")
	}
	return len(all)
}

// qrAccount is one account on a fresh mock server: OWNER generated the
// cross-signing identity and holds its private keys; NEWA and NEWB are
// fresh devices that know the public identity but trust nothing.
type qrAccount struct {
	ctx    context.Context
	ms     *mockserver.MockServer
	net    *qrNet
	owner  *qrPeer
	a, b   *qrPeer
	master id.Ed25519
	ssk    id.Ed25519
}

func newQRAccount(t *testing.T) *qrAccount {
	t.Helper()
	ctx := zerolog.Nop().WithContext(context.Background())
	ms := mockserver.Create(t)
	n := &qrNet{faults: map[id.DeviceID]map[string]qrFault{}}
	login := func(device id.DeviceID) *qrPeer {
		client, _ := ms.Login(t, ctx, qrUser, device)
		client.Client = &http.Client{Transport: &qrTransport{base: ms.Server.Client().Transport, net: n, device: device}}
		machine := client.Crypto.(*cryptohelper.CryptoHelper).Machine()
		quiet := zerolog.Nop()
		machine.Log = &quiet
		cb := &qrCallbacks{sasCallbacks: sasCallbacks{events: make(chan sasEvent, 32), overflow: make(chan struct{}, 1)}, codes: make(chan []byte, 4), scanned: make(chan id.VerificationTransactionID, 4)}
		store := newSASStore()
		helper := verificationhelper.NewVerificationHelper(client, machine, store, cb, true, true, false)
		if err := helper.Init(ctx); err != nil {
			t.Fatal("helper init failed")
		}
		t.Cleanup(func() {
			for len(cb.codes) > 0 {
				clear(<-cb.codes)
			}
		})
		return &qrPeer{client: client, machine: machine, helper: helper, store: store, cb: cb}
	}
	acct := &qrAccount{ctx: ctx, ms: ms, net: n, owner: login("OWNER")}
	if _, _, err := acct.owner.machine.GenerateAndUploadCrossSigningKeys(ctx, nil, ""); err != nil {
		t.Fatal("cross-signing fixture failed")
	}
	acct.a, acct.b = login("NEWA"), login("NEWB")
	for _, p := range []*qrPeer{acct.owner, acct.a, acct.b} {
		if _, err := p.machine.FetchKeys(ctx, []id.UserID{qrUser}, true); err != nil {
			t.Fatal("device fixture failed")
		}
	}
	keys, err := acct.a.machine.GetOwnCrossSigningPublicKeys(ctx)
	if err != nil || keys == nil {
		t.Fatal("public identity not cached")
	}
	acct.master, acct.ssk = keys.MasterKey, keys.SelfSigningKey
	return acct
}

// trustWithoutKeys makes p trust the master key, as a QR scan or SAS
// does, without giving it any private cross-signing key.
func (acct *qrAccount) trustWithoutKeys(t *testing.T, p *qrPeer) {
	t.Helper()
	if err := p.machine.SignOwnMasterKey(acct.ctx); err != nil {
		t.Fatal("trust fixture failed")
	}
	acct.net.reset()
}

// qrTrust is one device's local view of the account and of its peer.
type qrTrust struct {
	masterTrusted   bool // the master key is signed by this device's key
	peerVerified    bool // the peer device is marked verified in the store
	peerCrossSigned bool // the store holds a self-signing signature on the peer
}

func (acct *qrAccount) local(t *testing.T, p, peer *qrPeer) qrTrust {
	t.Helper()
	ctx, store := acct.ctx, p.machine.CryptoStore
	master, err := store.IsKeySignedBy(ctx, qrUser, acct.master, qrUser, p.machine.OwnIdentity().SigningKey)
	if err != nil {
		t.Fatal("master trust lookup failed")
	}
	dev, err := store.GetDevice(ctx, qrUser, peer.device())
	if err != nil || dev == nil {
		t.Fatal("peer device lookup failed")
	}
	signed, err := store.IsKeySignedBy(ctx, qrUser, dev.SigningKey, qrUser, acct.ssk)
	if err != nil {
		t.Fatal("device signature lookup failed")
	}
	return qrTrust{masterTrusted: master, peerVerified: dev.Trust == id.TrustStateVerified, peerCrossSigned: signed}
}

// masterBy counts accepted uploads of p's device signature on the master key.
func (acct *qrAccount) masterBy(p *qrPeer) int {
	return acct.net.count(acct.master.String(), id.NewKeyID(id.KeyAlgorithmEd25519, p.device().String()))
}

// crossSigned counts accepted uploads of a self-signing signature on p's device.
func (acct *qrAccount) crossSigned(p *qrPeer) int {
	return acct.net.count(p.device().String(), id.NewKeyID(id.KeyAlgorithmEd25519, acct.ssk.String()))
}

func (acct *qrAccount) deliver(t *testing.T, p *qrPeer) {
	t.Helper()
	acct.ms.DispatchToDevice(t, acct.ctx, p.client)
}

// show runs a request from display to scanner up to display showing its
// code, checks the code's mode, and returns the transaction and a copy
// of the code that the caller must clear.
func (acct *qrAccount) show(t *testing.T, display, scanner *qrPeer, mode verificationhelper.QRCodeMode) (id.VerificationTransactionID, []byte) {
	t.Helper()
	txn, err := display.helper.StartVerification(acct.ctx, qrUser)
	if err != nil {
		t.Fatal("request failed")
	}
	acct.deliver(t, scanner)
	if err := scanner.helper.AcceptVerification(acct.ctx, txn); err != nil {
		t.Fatal("accept failed")
	}
	for len(scanner.cb.codes) > 0 {
		clear(<-scanner.cb.codes)
	}
	acct.deliver(t, display)
	var code []byte
	select {
	case code = <-display.cb.codes:
	default:
		t.Fatal("display showed no code")
	}
	parsed, err := verificationhelper.NewQRCodeFromBytes(code)
	if err != nil || parsed.Mode != mode || parsed.TransactionID != txn {
		clear(code)
		t.Fatal("display showed a code for another mode or transaction")
	}
	display.events()
	scanner.events()
	return txn, code
}

// corruptSecret changes the last shared-secret byte, leaving the
// transaction and both keys intact.
func corruptSecret(code []byte) { code[len(code)-1] ^= 1 }

// Baseline, trusted display and untrusted scanner: the scanner signs the
// master key, and publishes that signature, before it sends the
// reciprocation; the display marks and cross-signs the scanner only at
// its confirmation.
func TestUpstreamQRTrustedDisplayTrustOrdering(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.owner, acct.a
	acct.net.reset()
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	defer clear(code)
	if got := acct.local(t, scanner, display); got.masterTrusted || got.peerVerified {
		t.Fatal("the scanner trusted something before scanning")
	}
	if err := scanQR(acct.ctx, txn, code, scanner.helper); err != nil {
		t.Fatal("scan failed")
	}
	if got := acct.local(t, scanner, display); !got.masterTrusted || got.peerVerified {
		t.Fatal("upstream scan trust changed; revisit the scanner contract")
	}
	if acct.masterBy(scanner) != 1 || acct.net.total() != 1 {
		t.Fatal("upstream no longer publishes the scanner's master signature at scan time")
	}
	acct.deliver(t, display)
	if !display.scannedCallback() {
		t.Fatal("the display did not report the scan")
	}
	if got := acct.local(t, display, scanner); got.peerVerified || got.peerCrossSigned || acct.crossSigned(scanner) != 0 {
		t.Fatal("the display trusted the scanner before confirming")
	}
	if err := display.helper.ConfirmQRCodeScanned(acct.ctx, txn); err != nil {
		t.Fatal("confirmation failed")
	}
	if got := acct.local(t, display, scanner); !got.peerVerified || !got.peerCrossSigned || acct.crossSigned(scanner) != 1 {
		t.Fatal("the display did not mark and cross-sign the scanner at confirmation")
	}
	acct.deliver(t, scanner)
	if _, done := display.events(); !done {
		t.Fatal("the display did not finish")
	}
	if _, done := scanner.events(); !done {
		t.Fatal("the scanner did not finish")
	}
}

// A wrong shared secret passes rihma's admission, which cannot check it,
// and the scanner signs before sending it. The display then cancels with
// m.key_mismatch and never offers confirmation. The specification says
// a secret mismatch "does not affect" the scanner's verification of the
// keys, so the scanner's local and published master signature remain.
func TestUpstreamQRWrongSecretKeepsScannerTrust(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.owner, acct.a
	acct.net.reset()
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	defer clear(code)
	corruptSecret(code)
	if err := scanQR(acct.ctx, txn, code, scanner.helper); err != nil {
		t.Fatal("a wrong secret was refused before the helper; revisit the admission contract")
	}
	acct.deliver(t, display)
	if display.scannedCallback() {
		t.Fatal("the display accepted a wrong secret")
	}
	if code, _ := display.events(); code != event.VerificationCancelCodeKeyMismatch {
		t.Fatal("the display did not cancel with a key mismatch")
	}
	acct.deliver(t, scanner)
	if code, done := scanner.events(); code != event.VerificationCancelCodeKeyMismatch || done {
		t.Fatal("the scanner did not see the cancellation")
	}
	if got := acct.local(t, scanner, display); !got.masterTrusted || acct.masterBy(scanner) != 1 {
		t.Fatal("upstream now withdraws scanner trust on a wrong secret; revisit the contract")
	}
	if got := acct.local(t, display, scanner); got.peerVerified || got.peerCrossSigned || acct.crossSigned(scanner) != 0 {
		t.Fatal("the display trusted a scanner that sent a wrong secret")
	}
	if display.transactions(t, acct.ctx) != 0 || scanner.transactions(t, acct.ctx) != 0 {
		t.Fatal("a cancelled transaction remained")
	}
}

// The same in reverse mode: the trusted scanner marks the untrusted
// display's device verified and publishes a self-signing signature on
// it, and then the display cancels. The display never trusts the master.
func TestUpstreamQRWrongSecretReverseModeKeepsDeviceSignature(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.a, acct.owner
	acct.net.reset()
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyUntrusted)
	defer clear(code)
	corruptSecret(code)
	if err := scanQR(acct.ctx, txn, code, scanner.helper); err != nil {
		t.Fatal("scan failed")
	}
	acct.deliver(t, display)
	if code, _ := display.events(); code != event.VerificationCancelCodeKeyMismatch {
		t.Fatal("the display did not cancel with a key mismatch")
	}
	acct.deliver(t, scanner)
	if got := acct.local(t, scanner, display); !got.peerVerified || !got.peerCrossSigned || acct.crossSigned(display) != 1 {
		t.Fatal("upstream reverse-mode scan trust changed; revisit the contract")
	}
	if got := acct.local(t, display, scanner); got.masterTrusted || got.peerVerified || acct.masterBy(display) != 0 {
		t.Fatal("the display trusted something after a wrong secret")
	}
}

// The reciprocation fails to send. The scanner has already signed and
// published; the helper returns an error without cancelling, and keeps
// the transaction ready, so the same code can be scanned again. The
// retry signs a second time and completes.
func TestUpstreamQRStartSendFailureKeepsTrustAndAllowsRetry(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.owner, acct.a
	acct.net.reset()
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	defer clear(code)
	acct.net.failOnce(scanner.device(), "/sendToDevice/m.key.verification.start/", qrRefuse)
	if err := scanQR(acct.ctx, txn, code, scanner.helper); !errors.Is(err, errQRScanFailed) {
		t.Fatal("a failed reciprocation send was not reported")
	}
	if got := acct.local(t, scanner, display); !got.masterTrusted || acct.masterBy(scanner) != 1 {
		t.Fatal("upstream no longer signs before sending the reciprocation")
	}
	if c, _ := scanner.events(); c != "" || scanner.transactions(t, acct.ctx) != 1 {
		t.Fatal("upstream now cancels or drops the transaction after a failed reciprocation send")
	}
	acct.deliver(t, display)
	if display.scannedCallback() {
		t.Fatal("the display saw a reciprocation that was never sent")
	}
	if err := scanQR(acct.ctx, txn, code, scanner.helper); err != nil {
		t.Fatal("the retried scan failed")
	}
	if acct.masterBy(scanner) != 2 {
		t.Fatal("the retried scan did not sign again")
	}
	acct.deliver(t, display)
	if !display.scannedCallback() {
		t.Fatal("the display did not report the retried scan")
	}
	if err := display.helper.ConfirmQRCodeScanned(acct.ctx, txn); err != nil {
		t.Fatal("confirmation failed")
	}
	acct.deliver(t, scanner)
	if _, done := scanner.events(); !done {
		t.Fatal("the retried verification did not finish")
	}
}

// The reciprocation is sent but the scanner's done fails to send. The
// helper returns an error and leaves its transaction ready. The display
// confirms, cross-signs the scanner and sends done, which the scanner
// then rejects as unexpected. Both sides end cancelled, holding and
// having published every signature a completed verification leaves.
func TestUpstreamQRDoneSendFailureCancelsAfterFullTrust(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.owner, acct.a
	acct.net.reset()
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	defer clear(code)
	acct.net.failOnce(scanner.device(), "/sendToDevice/m.key.verification.done/", qrRefuse)
	if err := scanQR(acct.ctx, txn, code, scanner.helper); !errors.Is(err, errQRScanFailed) {
		t.Fatal("a failed done send was not reported")
	}
	acct.deliver(t, display)
	if !display.scannedCallback() {
		t.Fatal("the display did not report the scan")
	}
	if err := display.helper.ConfirmQRCodeScanned(acct.ctx, txn); err != nil {
		t.Fatal("confirmation failed")
	}
	acct.deliver(t, scanner)
	if c, done := scanner.events(); c != event.VerificationCancelCodeUnexpectedMessage || done {
		t.Fatal("upstream now accepts the display's done after a failed scanner done; revisit the contract")
	}
	acct.deliver(t, display)
	if c, done := display.events(); c != event.VerificationCancelCodeUnexpectedMessage || done {
		t.Fatal("the display did not see the cancellation")
	}
	if got := acct.local(t, scanner, display); !got.masterTrusted || acct.masterBy(scanner) != 1 {
		t.Fatal("the scanner's master signature changed")
	}
	if got := acct.local(t, display, scanner); !got.peerVerified || !got.peerCrossSigned || acct.crossSigned(scanner) != 1 {
		t.Fatal("the display's signature on the scanner changed")
	}
}

// The display's done fails to send after it has marked and cross-signed
// the scanner. The helper returns an error and keeps the transaction in
// the scanned state, so confirming again signs again and completes.
func TestUpstreamQRConfirmSendFailureAllowsRetry(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.owner, acct.a
	acct.net.reset()
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	defer clear(code)
	if err := scanQR(acct.ctx, txn, code, scanner.helper); err != nil {
		t.Fatal("scan failed")
	}
	acct.deliver(t, display)
	acct.net.failOnce(display.device(), "/sendToDevice/m.key.verification.done/", qrRefuse)
	if err := display.helper.ConfirmQRCodeScanned(acct.ctx, txn); err == nil {
		t.Fatal("a failed done send was not reported")
	}
	if got := acct.local(t, display, scanner); !got.peerVerified || !got.peerCrossSigned || acct.crossSigned(scanner) != 1 {
		t.Fatal("upstream no longer signs the scanner before sending done")
	}
	if c, _ := display.events(); c != "" || display.transactions(t, acct.ctx) != 1 {
		t.Fatal("upstream now cancels or drops the transaction after a failed done send")
	}
	if err := display.helper.ConfirmQRCodeScanned(acct.ctx, txn); err != nil {
		t.Fatal("the retried confirmation failed")
	}
	if acct.crossSigned(scanner) != 2 {
		t.Fatal("the retried confirmation did not sign again")
	}
	acct.deliver(t, scanner)
	if _, done := display.events(); !done {
		t.Fatal("the display did not finish")
	}
	if _, done := scanner.events(); !done {
		t.Fatal("the scanner did not finish")
	}
}

// The scanner's signature upload is refused. Upstream stores a signature
// only after its upload succeeds, so nothing changes locally or on the
// server, and the scanner cancels.
func TestUpstreamQRSignatureUploadRefusedChangesNothing(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.owner, acct.a
	acct.net.reset()
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	defer clear(code)
	acct.net.failOnce(scanner.device(), "/keys/signatures/upload", qrRefuse)
	if err := scanQR(acct.ctx, txn, code, scanner.helper); !errors.Is(err, errQRScanFailed) {
		t.Fatal("a refused upload was not reported")
	}
	if c, _ := scanner.events(); c != event.VerificationCancelCodeInternalError {
		t.Fatal("the scanner did not cancel")
	}
	if got := acct.local(t, scanner, display); got.masterTrusted || acct.net.total() != 0 {
		t.Fatal("a refused upload changed trust")
	}
	acct.deliver(t, display)
	if c, _ := display.events(); c != event.VerificationCancelCodeInternalError || display.scannedCallback() {
		t.Fatal("the display did not see the cancellation")
	}
}

// The server accepts the scanner's signature but the response is lost.
// The scanner stores nothing and cancels, while the server publishes
// the signature: published trust can exceed local trust, and neither
// side can withdraw it.
func TestUpstreamQRLostUploadResponsePublishesWithoutLocalTrust(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.owner, acct.a
	acct.net.reset()
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	defer clear(code)
	acct.net.failOnce(scanner.device(), "/keys/signatures/upload", qrLoseResponse)
	if err := scanQR(acct.ctx, txn, code, scanner.helper); !errors.Is(err, errQRScanFailed) {
		t.Fatal("a lost response was not reported")
	}
	if c, _ := scanner.events(); c != event.VerificationCancelCodeInternalError {
		t.Fatal("the scanner did not cancel")
	}
	if got := acct.local(t, scanner, display); got.masterTrusted {
		t.Fatal("the scanner stored a signature whose upload it saw fail")
	}
	if acct.masterBy(scanner) != 1 {
		t.Fatal("the server did not keep the accepted signature")
	}
}

// The display cancels after the scan, before confirming. The scanner's
// signature stays, local and published; the display trusts nothing.
func TestUpstreamQRDisplayCancelAfterScanKeepsScannerTrust(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.owner, acct.a
	acct.net.reset()
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	defer clear(code)
	if err := scanQR(acct.ctx, txn, code, scanner.helper); err != nil {
		t.Fatal("scan failed")
	}
	acct.deliver(t, display)
	if !display.scannedCallback() {
		t.Fatal("the display did not report the scan")
	}
	if err := display.helper.CancelVerification(acct.ctx, txn, event.VerificationCancelCodeUser, ""); err != nil {
		t.Fatal("cancel failed")
	}
	acct.deliver(t, scanner)
	if c, done := scanner.events(); c != event.VerificationCancelCodeUser || done {
		t.Fatal("the scanner did not see the cancellation")
	}
	if got := acct.local(t, scanner, display); !got.masterTrusted || acct.masterBy(scanner) != 1 {
		t.Fatal("upstream now withdraws scanner trust on cancellation; revisit the contract")
	}
	if got := acct.local(t, display, scanner); got.peerVerified || got.peerCrossSigned || acct.crossSigned(scanner) != 0 {
		t.Fatal("a cancelled display trusted the scanner")
	}
}

// The scanner cancels before scanning, then scans the stale code. The
// helper finds no transaction and changes nothing.
func TestUpstreamQRCancelBeforeScanChangesNothing(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.owner, acct.a
	acct.net.reset()
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	defer clear(code)
	if err := scanner.helper.CancelVerification(acct.ctx, txn, event.VerificationCancelCodeUser, ""); err != nil {
		t.Fatal("cancel failed")
	}
	acct.deliver(t, display)
	if c, _ := display.events(); c != event.VerificationCancelCodeUser {
		t.Fatal("the display did not see the cancellation")
	}
	if err := scanQR(acct.ctx, txn, code, scanner.helper); !errors.Is(err, errQRScanFailed) {
		t.Fatal("a stale code was not refused")
	}
	if got := acct.local(t, scanner, display); got.masterTrusted || acct.net.total() != 0 {
		t.Fatal("a stale code changed trust")
	}
}

// Reverse mode, untrusted display and trusted scanner holding the
// self-signing key: the scanner marks and cross-signs the display at
// scan time, and the display signs the master at confirmation.
func TestUpstreamQRReverseModeCompletes(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.a, acct.owner
	acct.net.reset()
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyUntrusted)
	defer clear(code)
	if err := scanQR(acct.ctx, txn, code, scanner.helper); err != nil {
		t.Fatal("scan failed")
	}
	if got := acct.local(t, scanner, display); !got.peerVerified || !got.peerCrossSigned || acct.crossSigned(display) != 1 {
		t.Fatal("upstream reverse-mode scan no longer cross-signs the display at scan time")
	}
	acct.deliver(t, display)
	if !display.scannedCallback() {
		t.Fatal("the display did not report the scan")
	}
	if got := acct.local(t, display, scanner); got.masterTrusted || got.peerVerified {
		t.Fatal("the display trusted something before confirming")
	}
	if err := display.helper.ConfirmQRCodeScanned(acct.ctx, txn); err != nil {
		t.Fatal("confirmation failed")
	}
	if got := acct.local(t, display, scanner); !got.masterTrusted || !got.peerVerified || acct.masterBy(display) != 1 {
		t.Fatal("the display did not trust the master at confirmation")
	}
	acct.deliver(t, scanner)
	if _, done := display.events(); !done {
		t.Fatal("the display did not finish")
	}
	if _, done := scanner.events(); !done {
		t.Fatal("the scanner did not finish")
	}
}

// Reverse mode with a scanner that trusts the master but lacks the
// self-signing private key. Upstream marks the display's device
// verified in the scanner's store before it tries to sign, then cancels
// when signing fails. Nothing is published, but the local mark remains.
func TestUpstreamQRReverseModeWithoutSelfSigningKeyLeavesLocalMark(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.a, acct.b
	acct.trustWithoutKeys(t, scanner)
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyUntrusted)
	defer clear(code)
	if err := scanQR(acct.ctx, txn, code, scanner.helper); !errors.Is(err, errQRScanFailed) {
		t.Fatal("a scan without the self-signing key succeeded")
	}
	if c, _ := scanner.events(); c != event.VerificationCancelCodeInternalError {
		t.Fatal("the scanner did not cancel")
	}
	if got := acct.local(t, scanner, display); !got.peerVerified || got.peerCrossSigned {
		t.Fatal("upstream now checks the self-signing key before marking the device; revisit the preflight")
	}
	if acct.net.total() != 0 {
		t.Fatal("a scan without the self-signing key published a signature")
	}
	acct.deliver(t, display)
	if c, _ := display.events(); c != event.VerificationCancelCodeInternalError {
		t.Fatal("the display did not see the cancellation")
	}
	if got := acct.local(t, display, scanner); got.masterTrusted || got.peerVerified {
		t.Fatal("the display trusted something")
	}
}

// Neither device trusts the master. Both show reverse-mode codes, and
// scanning one is refused with the master-key-not-trusted code before
// any trust changes.
func TestUpstreamQRMissingTrustIsRefused(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.a, acct.b
	acct.net.reset()
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyUntrusted)
	defer clear(code)
	if err := scanQR(acct.ctx, txn, code, scanner.helper); !errors.Is(err, errQRScanFailed) {
		t.Fatal("a scan without trust succeeded")
	}
	if c, _ := scanner.events(); c != event.VerificationCancelCodeMasterKeyNotTrusted {
		t.Fatal("the scanner did not cancel with the master-key-not-trusted code")
	}
	if got := acct.local(t, scanner, display); got.masterTrusted || got.peerVerified || acct.net.total() != 0 {
		t.Fatal("a refused scan changed trust")
	}
	acct.deliver(t, display)
	if c, _ := display.events(); c != event.VerificationCancelCodeMasterKeyNotTrusted {
		t.Fatal("the display did not see the cancellation")
	}
}

// A display that trusts the master but lacks the self-signing private
// key still shows a trusted-mode code. At confirmation, upstream picks
// what to sign by whether this device holds private keys rather than by
// the code's mode: it signs the master again instead of the scanner's
// device, and sends done. Both sides finish, and the scanner's device is
// never cross-signed.
func TestUpstreamQRTrustedDisplayWithoutSelfSigningKeyFinishesUnsigned(t *testing.T) {
	acct := newQRAccount(t)
	display, scanner := acct.b, acct.a
	acct.trustWithoutKeys(t, display)
	txn, code := acct.show(t, display, scanner, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted)
	defer clear(code)
	if err := scanQR(acct.ctx, txn, code, scanner.helper); err != nil {
		t.Fatal("scan failed")
	}
	acct.deliver(t, display)
	if !display.scannedCallback() {
		t.Fatal("the display did not report the scan")
	}
	if err := display.helper.ConfirmQRCodeScanned(acct.ctx, txn); err != nil {
		t.Fatal("upstream now refuses to confirm without the self-signing key; revisit the preflight")
	}
	acct.deliver(t, scanner)
	if _, done := display.events(); !done {
		t.Fatal("the display did not finish")
	}
	if _, done := scanner.events(); !done {
		t.Fatal("the scanner did not finish")
	}
	if got := acct.local(t, display, scanner); !got.peerVerified || got.peerCrossSigned {
		t.Fatal("the display's local trust in the scanner changed")
	}
	if acct.crossSigned(scanner) != 0 || acct.masterBy(display) != 1 || acct.masterBy(scanner) != 1 {
		t.Fatal("upstream now cross-signs the scanner, or stops re-signing the master, without the self-signing key")
	}
}
