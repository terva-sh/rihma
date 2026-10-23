package rihma

// Tests for StartUser: outgoing to-device SAS with another user, run
// between a rihma bot and a bare mautrix helper acting as the owner, both
// on the mock server. See docs/cross-user-verification.md.

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const sasOwner = id.UserID("@owner:localhost")

type crossUserSAS struct {
	t        *testing.T
	ctx      context.Context
	h        *testHS
	bot      *Client
	s        *SASController
	owner    *upstreamPeer
	ownerKey id.Ed25519
	sends    *atomic.Int32
	logs     *bytes.Buffer
	changes  []IdentityChange
}

// newCrossUserFixture opens a bot and an owner, each with a cross-signing
// identity when asked, and gives the owner the bot's keys. Nothing syncs.
func newCrossUserFixture(t *testing.T, botIdentity, ownerIdentity bool, ownerDevice id.DeviceID) *crossUserSAS {
	t.Helper()
	x := &crossUserSAS{t: t, ctx: zerolog.Nop().WithContext(context.Background()), h: newTestHS(t), sends: new(atomic.Int32), logs: &bytes.Buffer{}}
	keepSignatures(x.h)
	inner := x.h.ms.Server.Config.Handler
	x.h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sendToDevice/") && r.Header.Get("Authorization") != "" {
			x.sends.Add(1)
		}
		inner.ServeHTTP(w, r)
	})
	x.bot = openAs(t, x.h, testUser, t.TempDir(), func(o *Options) {
		o.Logger = zerolog.New(x.logs).Level(zerolog.TraceLevel)
		o.OnIdentityChange = func(c IdentityChange) { x.changes = append(x.changes, c) }
	})
	if botIdentity {
		createIdentity(t, x.bot)
	}
	if ownerDevice == "" {
		ownerDevice = "OWNERDEVICE"
	}
	x.owner = newUpstreamPeer(t, x.ctx, x.h.ms, sasOwner, ownerDevice)
	if ownerIdentity {
		if _, _, err := x.owner.machine.GenerateAndUploadCrossSigningKeys(x.ctx, nil, ""); err != nil {
			t.Fatal("owner identity failed")
		}
		x.ownerKey = x.owner.machine.CrossSigningKeys.MasterKey.PublicKey()
	}
	if _, err := x.owner.machine.FetchKeys(x.ctx, []id.UserID{testUser}, true); err != nil {
		t.Fatal("owner key fetch failed")
	}
	return x
}

// newCrossUserSAS is newCrossUserFixture with the bot's controller enabled
// and the bot syncing.
func newCrossUserSAS(t *testing.T, botIdentity, ownerIdentity bool, ownerDevice id.DeviceID) *crossUserSAS {
	t.Helper()
	x := newCrossUserFixture(t, botIdentity, ownerIdentity, ownerDevice)
	s, err := x.bot.EnableSAS()
	if err != nil {
		t.Fatal("enable failed")
	}
	x.s = s
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- x.bot.Sync(ctx) }()
	sasWait(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.started })
	t.Cleanup(func() { cancel(); <-done })
	x.h.awaitSyncRequests(t, 1)
	return x
}

// toBot dispatches the bot's to-device inbox and returns what it held.
func (x *crossUserSAS) toBot() []event.Event {
	x.t.Helper()
	inbox := x.h.ms.DeviceInbox[x.bot.UserID][x.bot.DeviceID]
	x.h.ms.DeviceInbox[x.bot.UserID][x.bot.DeviceID] = nil
	for i := range inbox {
		x.bot.Handlers().Dispatch(context.Background(), &inbox[i])
	}
	return inbox
}

func (x *crossUserSAS) toOwner() { x.h.ms.DispatchToDevice(x.t, x.ctx, x.owner.client) }

func (x *crossUserSAS) wait(state SASState) SASSnapshot {
	x.t.Helper()
	sasWait(x.t, func() bool { return x.s.Snapshot().State == state })
	return x.s.Snapshot()
}

// toShowing runs a StartUser attempt until both sides show the same emoji.
func (x *crossUserSAS) toShowing() id.VerificationTransactionID {
	x.t.Helper()
	txn, err := x.s.StartUser(context.Background(), sasOwner)
	if err != nil || txn == "" {
		x.t.Fatalf("start user: %v", err)
	}
	if got := x.s.Snapshot(); got.State != SASSent || got.OtherUser != sasOwner || got.Room != "" || got.MasterKey != "" {
		x.t.Fatalf("snapshot after start = %+v", got)
	}
	x.toOwner()
	if err := x.owner.helper.AcceptVerification(x.ctx, txn); err != nil {
		x.t.Fatal("owner accept failed")
	}
	x.toBot() // ready
	x.wait(SASAccepted)
	x.toOwner() // start; owner sends accept
	x.toBot()   // accept; bot sends key
	x.toOwner() // key; owner sends key and shows emoji
	x.toBot()   // key; bot shows emoji
	got := x.wait(SASShowing)
	var ownerEmoji []SASEmoji
	for _, ev := range x.owner.drain() {
		if ev.emoji != nil {
			ownerEmoji = ev.emoji
		}
	}
	if len(got.Emoji) != 7 || len(ownerEmoji) != 7 {
		x.t.Fatal("emoji not shown on both sides")
	}
	for i := range ownerEmoji {
		if ownerEmoji[i] != got.Emoji[i] {
			x.t.Fatal("emoji differ between the sides")
		}
	}
	return txn
}

// ownerSignedBot reports whether the owner's store holds its user-signing
// key's signature on the bot's master key.
func (x *crossUserSAS) ownerSignedBot() bool {
	x.t.Helper()
	own, err := x.owner.machine.GetOwnCrossSigningPublicKeys(x.ctx)
	theirs, err2 := x.owner.machine.GetCrossSigningPublicKeys(x.ctx, testUser)
	if err != nil || err2 != nil || own == nil || theirs == nil {
		x.t.Fatal("cross-signing keys missing")
	}
	signed, err := x.owner.machine.CryptoStore.IsKeySignedBy(x.ctx, testUser, theirs.MasterKey, sasOwner, own.UserSigningKey)
	if err != nil {
		x.t.Fatal("signature lookup failed")
	}
	return signed
}

// checkCompleted asserts the end state of a successful attempt: done with
// the owner's master key, signatures both ways, the owner recorded for
// change reports, and no MAC value in the logs.
func (x *crossUserSAS) checkCompleted(txn id.VerificationTransactionID, macs []event.Event) {
	x.t.Helper()
	got := x.wait(SASDone)
	if got.TransactionID != txn || got.OtherUser != sasOwner || got.MasterKey != x.ownerKey || got.Reason != "" {
		x.t.Fatalf("done snapshot = %+v", got)
	}
	ident, err := x.bot.UserIdentity(context.Background(), sasOwner)
	if err != nil || !ident.SignedByUs || ident.MasterKey != x.ownerKey {
		x.t.Fatalf("owner identity after SAS = %+v, %v", ident, err)
	}
	if !x.ownerSignedBot() {
		x.t.Fatal("the owner did not sign the bot's master key")
	}
	publishIdentity(x.t, x.h, sasOwner)
	if _, err := x.bot.UserIdentity(context.Background(), sasOwner); err != nil {
		x.t.Fatal("identity query failed")
	}
	if len(x.changes) != 1 || x.changes[0].Signed != x.ownerKey {
		x.t.Fatalf("the signed owner was not recorded for change reports: %+v", x.changes)
	}
	for _, ev := range macs {
		for _, mac := range ev.Content.AsVerificationMAC().MAC {
			if bytes.Contains(x.logs.Bytes(), []byte(base64.RawStdEncoding.EncodeToString(mac))) {
				x.t.Fatal("a MAC value reached the logs")
			}
		}
	}
}

func macEvents(evs []event.Event) []event.Event {
	var out []event.Event
	for _, ev := range evs {
		if ev.Type == event.ToDeviceVerificationMAC {
			out = append(out, ev)
		}
	}
	return out
}

// The owner confirms first and its MAC reaches the bot before the person
// at the bot's terminal answers. The gate holds it until the bot's own MAC
// is sent, so the bot checks it second and signs the owner.
func TestStartUserCompletesWhenTheBotConfirmsSecond(t *testing.T) {
	x := newCrossUserSAS(t, true, true, "")
	txn := x.toShowing()
	if err := x.owner.helper.ConfirmSAS(x.ctx, txn); err != nil {
		t.Fatal("owner confirm failed")
	}
	macs := macEvents(x.toBot())
	if len(macs) != 1 {
		t.Fatal("the owner's MAC did not reach the bot")
	}
	if got := x.s.Snapshot(); got.State != SASShowing {
		t.Fatalf("a held MAC changed the attempt: %+v", got)
	}
	if err := x.s.Confirm(context.Background(), txn, true); err != nil {
		t.Fatalf("bot confirm: %v", err)
	}
	x.toOwner() // the bot's MAC and done
	x.toBot()   // the owner's done
	x.checkCompleted(txn, macs)
}

// The bot confirms before the owner's MAC arrives, so nothing is held.
func TestStartUserCompletesWhenTheBotConfirmsFirst(t *testing.T) {
	x := newCrossUserSAS(t, true, true, "")
	txn := x.toShowing()
	if err := x.s.Confirm(context.Background(), txn, true); err != nil {
		t.Fatalf("bot confirm: %v", err)
	}
	x.wait(SASConfirmed)
	// The owner confirms before reading the bot's MAC, the order in which
	// the upstream helper signs; Element is not bound by it.
	held := x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID]
	x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID] = nil
	if err := x.owner.helper.ConfirmSAS(x.ctx, txn); err != nil {
		t.Fatal("owner confirm failed")
	}
	x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID] = append(held, x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID]...)
	macs := macEvents(x.toBot()) // the owner's MAC; the bot signs and sends done
	x.toOwner()                  // the bot's MAC and done
	x.toBot()                    // the owner's done
	x.checkCompleted(txn, macs)
}

// Every failed prerequisite returns its sentinel and sends nothing.
func TestStartUserPrerequisitesSendNothing(t *testing.T) {
	cases := []struct {
		name          string
		botIdentity   bool
		ownerIdentity bool
		ownerDevice   func(*Client) id.DeviceID
		user          id.UserID
		want          error
	}{
		{"own user", true, true, nil, testUser, ErrOwnUser},
		{"no keys held", false, true, nil, sasOwner, ErrNoCrossSigningKeys},
		{"no peer identity", true, false, nil, sasOwner, ErrNoUserIdentity},
		{"shared device id", true, true, func(c *Client) id.DeviceID { return c.DeviceID }, sasOwner, ErrPeerDeviceIDConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var x *crossUserSAS
			if tc.ownerDevice != nil {
				// The owner's device id must match the bot's, which is chosen
				// at the bot's login; log the owner in afterwards.
				x = newCrossUserSAS(t, tc.botIdentity, false, "")
				shared := newUpstreamPeer(t, x.ctx, x.h.ms, "@twin:localhost", tc.ownerDevice(x.bot))
				if _, _, err := shared.machine.GenerateAndUploadCrossSigningKeys(x.ctx, nil, ""); err != nil {
					t.Fatal("twin identity failed")
				}
				tc.user = "@twin:localhost"
			} else {
				x = newCrossUserSAS(t, tc.botIdentity, tc.ownerIdentity, "")
			}
			before, revision := x.sends.Load(), x.s.Snapshot().Revision
			if _, err := x.s.StartUser(context.Background(), tc.user); !errors.Is(err, tc.want) {
				t.Fatalf("StartUser = %v, want %v", err, tc.want)
			}
			if x.sends.Load() != before || x.s.Snapshot().Revision != revision {
				t.Fatal("a refused StartUser sent something or changed the snapshot")
			}
		})
	}
}

// Follow-ups bound to the attempt's user: another user, and this account
// itself, cannot steer a cross-user attempt, and a ready from a device the
// request did not go to is dropped.
func TestStartUserDropsForeignFollowUps(t *testing.T) {
	x := newCrossUserSAS(t, true, true, "")
	txn, err := x.s.StartUser(context.Background(), sasOwner)
	if err != nil {
		t.Fatalf("start user: %v", err)
	}
	revision := x.s.Snapshot().Revision
	for _, sender := range []id.UserID{"@mallory:localhost", testUser} {
		for _, ev := range sasFollowUps(txn) {
			ev.Sender = sender
			x.bot.Handlers().Dispatch(context.Background(), ev)
		}
		sasReady(x.bot, txn, sender, "OWNERDEVICE", event.VerificationMethodSAS)
	}
	sasReady(x.bot, txn, sasOwner, "UNREQUESTED", event.VerificationMethodSAS)
	if got := x.s.Snapshot(); got.State != SASSent || got.Revision != revision {
		t.Fatalf("a foreign follow-up changed the attempt: %+v", got)
	}
	sasReady(x.bot, txn, sasOwner, "OWNERDEVICE", event.VerificationMethodSAS)
	if got := x.wait(SASAccepted); got.OtherDevice != "OWNERDEVICE" || got.OtherUser != sasOwner {
		t.Fatalf("the owner's ready was not admitted: %+v", got)
	}
}

// hideOwnerIdentity publishes an identity for the owner but hides it from
// the owner's own device, which therefore names no master key in its MAC.
func (x *crossUserSAS) hideOwnerIdentity() {
	x.ownerKey = publishIdentity(x.t, x.h, sasOwner)
	inner := x.h.ms.Server.Config.Handler
	x.h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/keys/query") && r.Header.Get("Authorization") == "Bearer "+x.owner.client.AccessToken {
			w.Write([]byte(`{"device_keys":{},"master_keys":{},"self_signing_keys":{},"user_signing_keys":{}}`))
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// ownerConfirmsAfterBot confirms on the owner's side without letting it
// read the bot's MAC first, the order the upstream helper signs in.
func (x *crossUserSAS) ownerConfirmsAfterBot(txn id.VerificationTransactionID) {
	x.t.Helper()
	x.wait(SASConfirmed)
	held := x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID]
	x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID] = nil
	if err := x.owner.helper.ConfirmSAS(x.ctx, txn); err != nil {
		x.t.Fatal("owner confirm failed")
	}
	x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID] = append(held, x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID]...)
}

// An owner whose MAC names only its device leaves the bot's attempt
// failed with reason unsigned: the device is verified, the user is not.
func TestStartUserWithoutMasterKeyInMACEndsUnsigned(t *testing.T) {
	x := newCrossUserSAS(t, true, false, "")
	x.hideOwnerIdentity()
	txn := x.toShowing()
	if err := x.s.Confirm(context.Background(), txn, true); err != nil {
		t.Fatalf("bot confirm: %v", err)
	}
	x.wait(SASConfirmed)
	held := x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID]
	x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID] = nil
	if err := x.owner.helper.ConfirmSAS(x.ctx, txn); err != nil {
		t.Fatal("owner confirm failed")
	}
	x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID] = held
	x.toBot() // the owner's MAC; the bot trusts the device and sends done
	// The upstream owner cannot sign the bot without keys of its own and
	// would cancel, so its done is written here.
	done := sasFollowUps(txn)[5]
	done.Sender = sasOwner
	x.bot.Handlers().Dispatch(context.Background(), done)
	if got := x.wait(SASFailed); got.Reason != "unsigned" || got.MasterKey != "" {
		t.Fatalf("snapshot = %+v, want failed/unsigned", got)
	}
	if ident, err := x.bot.UserIdentity(context.Background(), sasOwner); err != nil || ident.SignedByUs {
		t.Fatalf("the owner's identity was signed without a MAC naming it: %+v, %v", ident, err)
	}
}

// A master key swapped on the server between the MAC check and done ends
// the attempt identity_changed rather than recording the old key as current.
func TestStartUserSwapBeforeDoneEndsIdentityChanged(t *testing.T) {
	x := newCrossUserSAS(t, true, true, "")
	txn := x.toShowing()
	if err := x.owner.helper.ConfirmSAS(x.ctx, txn); err != nil {
		t.Fatal("owner confirm failed")
	}
	x.toBot()
	if err := x.s.Confirm(context.Background(), txn, true); err != nil {
		t.Fatalf("bot confirm: %v", err)
	}
	x.toOwner()
	publishIdentity(t, x.h, sasOwner)
	x.toBot()
	if got := x.wait(SASFailed); got.Reason != "identity_changed" || got.MasterKey != "" {
		t.Fatalf("snapshot = %+v, want failed/identity_changed", got)
	}
}

// One MAC is admitted per attempt. A second, held or not, cancels.
func TestStartUserSecondMACCancels(t *testing.T) {
	x := newCrossUserSAS(t, true, true, "")
	txn := x.toShowing()
	if err := x.owner.helper.ConfirmSAS(x.ctx, txn); err != nil {
		t.Fatal("owner confirm failed")
	}
	macs := macEvents(x.toBot())
	if len(macs) != 1 {
		t.Fatal("the owner's MAC did not reach the bot")
	}
	x.bot.Handlers().Dispatch(context.Background(), &macs[0])
	if got := x.wait(SASCancelled); got.Reason != "cancelled" {
		t.Fatalf("snapshot = %+v", got)
	}
	if err := x.s.Confirm(context.Background(), txn, true); !errors.Is(err, ErrSASStale) {
		t.Fatalf("confirm after cancellation = %v", err)
	}
	if ident, err := x.bot.UserIdentity(context.Background(), sasOwner); err != nil || ident.SignedByUs {
		t.Fatal("a cancelled attempt signed the owner")
	}
}

// Behind a held MAC the gate keeps one done and drops repeats, so a peer
// cannot grow the queue while the local person decides. The attempt still
// completes from what was kept.
func TestStartUserHoldsOneDoneBehindTheMAC(t *testing.T) {
	x := newCrossUserSAS(t, true, true, "")
	txn := x.toShowing()
	if err := x.owner.helper.ConfirmSAS(x.ctx, txn); err != nil {
		t.Fatal("owner confirm failed")
	}
	macs := macEvents(x.toBot())
	for range 100 {
		done := sasFollowUps(txn)[5]
		done.Sender = sasOwner
		x.bot.Handlers().Dispatch(context.Background(), done)
	}
	x.s.gate.mu.Lock()
	held := len(x.s.gate.held)
	x.s.gate.mu.Unlock()
	if held != 2 {
		t.Fatalf("held %d events behind the MAC, want the MAC and one done", held)
	}
	if err := x.s.Confirm(context.Background(), txn, true); err != nil {
		t.Fatalf("bot confirm: %v", err)
	}
	x.toOwner()
	x.toBot()
	x.checkCompleted(txn, macs)
}

// The owner's cancellation reason never reaches a snapshot.
func TestStartUserCancellationKeepsRemoteReasonOut(t *testing.T) {
	x := newCrossUserSAS(t, true, true, "")
	txn := x.toShowing()
	if err := x.owner.helper.CancelVerification(x.ctx, txn, event.VerificationCancelCodeUser, "remote words"); err != nil {
		t.Fatal("owner cancel failed")
	}
	x.toBot()
	if got := x.wait(SASCancelled); got.Reason != "rejected" || len(got.Emoji) != 0 || got.OtherUser != sasOwner {
		t.Fatalf("snapshot = %+v", got)
	}
	if bytes.Contains(x.logs.Bytes(), []byte("remote words")) {
		t.Fatal("the remote reason reached the logs")
	}
}

// verifyUserRun runs VerifyUser against the owner in the background and
// drives the owner's side up to both showing emoji.
type verifyUserRun struct {
	key      id.Ed25519
	err      error
	done     chan struct{}
	confirms atomic.Int32
}

func (x *crossUserSAS) startVerifyUser(confirm func([]SASEmoji) bool) (*verifyUserRun, id.VerificationTransactionID) {
	x.t.Helper()
	run := &verifyUserRun{done: make(chan struct{})}
	go func() {
		defer close(run.done)
		run.key, run.err = x.bot.VerifyUser(context.Background(), sasOwner, func(emoji []SASEmoji) bool {
			run.confirms.Add(1)
			return confirm(emoji)
		})
	}()
	sasWait(x.t, func() bool {
		x.bot.connectOnce.Lock()
		defer x.bot.connectOnce.Unlock()
		return x.bot.sas != nil
	})
	x.s = x.bot.sas
	x.wait(SASSent)
	txn := x.s.Snapshot().TransactionID
	x.toOwner()
	if err := x.owner.helper.AcceptVerification(x.ctx, txn); err != nil {
		x.t.Fatal("owner accept failed")
	}
	x.toBot() // ready
	x.wait(SASAccepted)
	x.toOwner() // start; owner sends accept
	x.toBot()   // accept; bot sends key
	x.toOwner() // key; owner sends key and shows emoji
	return run, txn
}

func (r *verifyUserRun) wait(t *testing.T) {
	t.Helper()
	sasWait(t, func() bool {
		select {
		case <-r.done:
			return true
		default:
			return false
		}
	})
}

// VerifyUser refuses a state directory something else syncs on, before
// sending anything.
func TestVerifyUserRefusesARunningSync(t *testing.T) {
	x := newCrossUserSAS(t, true, true, "")
	before := x.sends.Load()
	if _, err := x.bot.VerifyUser(context.Background(), sasOwner, func([]SASEmoji) bool { t.Fatal("confirm called"); return false }); !errors.Is(err, ErrSyncInProgress) {
		t.Fatalf("VerifyUser during Sync = %v, want ErrSyncInProgress", err)
	}
	if x.sends.Load() != before {
		t.Fatal("a refused VerifyUser sent something")
	}
	if _, err := x.bot.VerifyUser(context.Background(), testUser, nil); !errors.Is(err, ErrOwnUser) {
		t.Fatalf("VerifyUser of this account = %v, want ErrOwnUser", err)
	}
}

// VerifyUser returns the owner's master key once both sides confirmed,
// with confirm asked exactly once, and the owner signed and recorded.
func TestVerifyUserReturnsTheSignedMasterKey(t *testing.T) {
	x := newCrossUserFixture(t, true, true, "")
	var shown []SASEmoji
	run, txn := x.startVerifyUser(func(emoji []SASEmoji) bool { shown = emoji; return true })
	x.toBot() // key; the bot shows emoji and confirm says yes
	// The owner confirms once the bot's operator has, so the bot's MAC is
	// read after the owner's own, the order the upstream helper signs in.
	sasWait(t, func() bool { return x.s.Snapshot().State == SASConfirmed })
	held := x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID]
	x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID] = nil
	if err := x.owner.helper.ConfirmSAS(x.ctx, txn); err != nil {
		t.Fatal("owner confirm failed")
	}
	x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID] = append(held, x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID]...)
	x.toBot()   // the owner's MAC; the bot signs and sends done
	x.toOwner() // the bot's MAC and done
	x.toBot()   // the owner's done
	run.wait(t)
	if run.err != nil || run.key != x.ownerKey {
		t.Fatalf("VerifyUser = %v, %v; want the owner's key", run.key == x.ownerKey, run.err)
	}
	if run.confirms.Load() != 1 || len(shown) != 7 {
		t.Fatalf("confirm called %d times", run.confirms.Load())
	}
	if ident, err := x.bot.UserIdentity(context.Background(), sasOwner); err != nil || !ident.SignedByUs {
		t.Fatal("the owner is not signed after VerifyUser")
	}
	if !x.ownerSignedBot() {
		t.Fatal("the owner did not sign the bot")
	}
}

// A mismatch reported by confirm cancels without the bot sending a MAC,
// and VerifyUser returns ErrSASMismatch.
func TestVerifyUserMismatchSendsNoMAC(t *testing.T) {
	x := newCrossUserFixture(t, true, true, "")
	run, _ := x.startVerifyUser(func([]SASEmoji) bool { return false })
	x.toBot() // key; the bot shows emoji and confirm says no
	run.wait(t)
	if !errors.Is(run.err, ErrSASMismatch) || run.key != "" {
		t.Fatalf("VerifyUser = %v", run.err)
	}
	for _, ev := range x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID] {
		if ev.Type == event.ToDeviceVerificationMAC {
			t.Fatal("the bot sent a MAC after a mismatch")
		}
	}
	x.toOwner()
	cancelled := false
	for _, ev := range x.owner.drain() {
		cancelled = cancelled || ev.cancelled == event.VerificationCancelCodeSASMismatch
	}
	if !cancelled {
		t.Fatal("the owner was not told the emoji did not match")
	}
}

// The owner cancelling ends VerifyUser with ErrSASCancelled, without
// confirm being asked.
func TestVerifyUserPeerCancellation(t *testing.T) {
	x := newCrossUserFixture(t, true, true, "")
	run, txn := x.startVerifyUser(func([]SASEmoji) bool { t.Error("confirm called after cancellation"); return true })
	if err := x.owner.helper.CancelVerification(x.ctx, txn, event.VerificationCancelCodeUser, "no"); err != nil {
		t.Fatal("owner cancel failed")
	}
	// Deliver only the cancellation: the owner's key is still queued
	// behind it from the exchange, and must not reach the bot first.
	inbox := x.h.ms.DeviceInbox[x.bot.UserID][x.bot.DeviceID]
	x.h.ms.DeviceInbox[x.bot.UserID][x.bot.DeviceID] = nil
	for i := range inbox {
		if inbox[i].Type == event.ToDeviceVerificationCancel {
			x.bot.Handlers().Dispatch(context.Background(), &inbox[i])
		}
	}
	run.wait(t)
	if !errors.Is(run.err, ErrSASCancelled) {
		t.Fatalf("VerifyUser = %v, want ErrSASCancelled", run.err)
	}
}

// VerifyUser reports a peer whose MAC named no master key as
// ErrSASUnsigned, not success.
func TestVerifyUserUnsigned(t *testing.T) {
	x := newCrossUserFixture(t, true, false, "")
	x.hideOwnerIdentity()
	run, txn := x.startVerifyUser(func([]SASEmoji) bool { return true })
	x.toBot() // key; the bot shows emoji and confirms
	x.ownerConfirmsAfterBot(txn)
	x.toBot() // the owner's MAC; the bot trusts the device and sends done
	done := sasFollowUps(txn)[5]
	done.Sender = sasOwner
	x.bot.Handlers().Dispatch(context.Background(), done)
	run.wait(t)
	if !errors.Is(run.err, ErrSASUnsigned) || run.key != "" {
		t.Fatalf("VerifyUser = %v, want ErrSASUnsigned", run.err)
	}
}

// VerifyUser reports a master key swapped on the server before done as
// ErrMasterKeyMismatch.
func TestVerifyUserIdentityChanged(t *testing.T) {
	x := newCrossUserFixture(t, true, true, "")
	run, txn := x.startVerifyUser(func([]SASEmoji) bool { return true })
	x.toBot() // key; the bot shows emoji and confirms
	x.ownerConfirmsAfterBot(txn)
	x.toBot()   // the owner's MAC; the bot signs and sends done
	x.toOwner() // the bot's MAC and done
	publishIdentity(t, x.h, sasOwner)
	x.toBot() // the owner's done
	run.wait(t)
	if !errors.Is(run.err, ErrMasterKeyMismatch) || run.key != "" {
		t.Fatalf("VerifyUser = %v, want ErrMasterKeyMismatch", run.err)
	}
}
