package rihma

// Tests for incoming to-device SAS from the users listed in
// SASOptions.Peers, run between a rihma bot and a bare mautrix helper
// acting as its owner on the mock server. See
// docs/cross-user-verification.md. The fixtures come from sas_user_test.go;
// the helpers here are prefixed incoming so they stay apart from the
// same-account SAS helpers.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// incomingPeerSAS is newCrossUserFixture with the bot's controller enabled
// with opts and the bot syncing. botSends counts only the bot's to-device
// sends.
func incomingPeerSAS(t *testing.T, botIdentity, ownerIdentity bool, opts SASOptions) (*crossUserSAS, *atomic.Int32) {
	t.Helper()
	x := newCrossUserFixture(t, botIdentity, ownerIdentity, "")
	botSends := new(atomic.Int32)
	inner := x.h.ms.Server.Config.Handler
	x.h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sendToDevice/") && r.Header.Get("Authorization") == "Bearer "+x.bot.AccessToken {
			botSends.Add(1)
		}
		inner.ServeHTTP(w, r)
	})
	s, err := x.bot.EnableSASWith(opts)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	x.s = s
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- x.bot.Sync(ctx) }()
	sasWait(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.started })
	t.Cleanup(func() { cancel(); <-done })
	x.h.awaitSyncRequests(t, 1)
	return x, botSends
}

func ownerPeers() SASOptions { return SASOptions{Peers: []id.UserID{sasOwner}} }

// incomingRequest has the owner ask the bot to verify, delivers the
// request, and waits for the bot to publish it.
func (x *crossUserSAS) incomingRequest() id.VerificationTransactionID {
	x.t.Helper()
	txn, err := x.owner.helper.StartVerification(x.ctx, testUser)
	if err != nil || txn == "" {
		x.t.Fatal("owner request failed")
	}
	x.toBot()
	got := x.wait(SASRequested)
	if got.TransactionID != txn || got.OtherUser != sasOwner || got.OtherDevice != x.owner.client.DeviceID || got.Room != "" || got.MasterKey != "" {
		x.t.Fatalf("requested snapshot = %+v", got)
	}
	return txn
}

// incomingToShowing runs an owner's request, accepted by the bot, until
// both sides show the same emoji.
func (x *crossUserSAS) incomingToShowing() id.VerificationTransactionID {
	x.t.Helper()
	txn := x.incomingRequest()
	if err := x.s.Accept(context.Background(), txn); err != nil {
		x.t.Fatalf("accept: %v", err)
	}
	x.wait(SASAccepted)
	x.toOwner() // ready
	if err := x.owner.helper.StartSAS(x.ctx, txn); err != nil {
		x.t.Fatal("owner SAS start failed")
	}
	x.toBot()   // start; bot sends accept
	x.toOwner() // accept; owner sends key
	x.toBot()   // key; bot sends key and shows emoji
	x.toOwner() // key; owner shows emoji
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

// gateCounts reads how many attempts the gate admitted and how many ids it
// remembers.
func (x *crossUserSAS) gateCounts() (attempts, remembered int) {
	x.s.gate.mu.Lock()
	defer x.s.gate.mu.Unlock()
	return x.s.gate.attempts, len(x.s.gate.recent)
}

// The owner asks, the bot's person confirms after the owner's MAC has
// arrived, and each side signs the other.
func TestIncomingPeerSASCompletesWhenTheBotConfirmsSecond(t *testing.T) {
	x, _ := incomingPeerSAS(t, true, true, ownerPeers())
	txn := x.incomingToShowing()
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

// The bot's person confirms before the owner's MAC arrives.
func TestIncomingPeerSASCompletesWhenTheBotConfirmsFirst(t *testing.T) {
	x, _ := incomingPeerSAS(t, true, true, ownerPeers())
	txn := x.incomingToShowing()
	if err := x.s.Confirm(context.Background(), txn, true); err != nil {
		t.Fatalf("bot confirm: %v", err)
	}
	x.ownerConfirmsAfterBot(txn)
	macs := macEvents(x.toBot()) // the owner's MAC; the bot signs and sends done
	x.toOwner()                  // the bot's MAC and done
	x.toBot()                    // the owner's done
	x.checkCompleted(txn, macs)
}

// A request from a user who is not listed, or from anyone but this account
// under the zero options, reaches no helper: no transaction, attempt,
// remembered id, reply or snapshot change.
func TestIncomingPeerSASDropsUnlistedUsers(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts SASOptions
	}{
		{"zero options", SASOptions{}},
		{"owner not listed", SASOptions{Peers: []id.UserID{"@someone:localhost"}}},
		{"owner listed", ownerPeers()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, botSends := incomingPeerSAS(t, true, true, tc.opts)
			stranger := newUpstreamPeer(t, x.ctx, x.h.ms, "@stranger:localhost", "STRANGERDEVICE")
			if _, err := stranger.machine.FetchKeys(x.ctx, []id.UserID{testUser}, true); err != nil {
				t.Fatal("stranger key fetch failed")
			}
			senders := []*upstreamPeer{stranger}
			if tc.opts.Peers == nil || tc.opts.Peers[0] != sasOwner {
				senders = append(senders, x.owner)
			}
			revision := x.s.Snapshot().Revision
			for _, p := range senders {
				if _, err := p.helper.StartVerification(x.ctx, testUser); err != nil {
					t.Fatal("request failed")
				}
			}
			for i, device := range []id.DeviceID{"PEER", x.bot.DeviceID, ""} {
				sasRequest(x.bot, id.VerificationTransactionID("mallory-"+string(rune('a'+i))), "@mallory:localhost", device, time.Now().Add(time.Minute))
			}
			if n := len(x.toBot()); n != len(senders) {
				t.Fatalf("delivered %d requests, want %d", n, len(senders))
			}
			if all, _ := x.s.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
				t.Fatal("an unlisted user's request entered the helper")
			}
			if attempts, remembered := x.gateCounts(); attempts != 0 || remembered != 0 {
				t.Fatalf("an unlisted request was counted: %d attempts, %d ids", attempts, remembered)
			}
			if got := x.s.Snapshot(); got.State != SASIdle || got.Revision != revision {
				t.Fatalf("an unlisted request changed the snapshot: %+v", got)
			}
			if botSends.Load() != 0 {
				t.Fatal("the bot replied to an unlisted user")
			}
			if len(x.h.ms.DeviceInbox[stranger.client.UserID][stranger.client.DeviceID]) != 0 {
				t.Fatal("the stranger received something")
			}
		})
	}
}

// One attempt at a time: a listed user's request while another attempt is
// active is dropped, whoever the active attempt is with.
func TestIncomingPeerSASDropsRequestsWhileBusy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		active func(x *crossUserSAS) id.VerificationTransactionID
	}{
		{"same-account request", func(x *crossUserSAS) id.VerificationTransactionID {
			sasRequest(x.bot, "own", testUser, "OTHER", time.Now().Add(time.Minute))
			x.wait(SASRequested)
			return "own"
		}},
		{"owner request", func(x *crossUserSAS) id.VerificationTransactionID { return x.incomingRequest() }},
		{"owner request accepted", func(x *crossUserSAS) id.VerificationTransactionID {
			txn := x.incomingRequest()
			if err := x.s.Accept(context.Background(), txn); err != nil {
				x.t.Fatalf("accept: %v", err)
			}
			return txn
		}},
		{"StartUser", func(x *crossUserSAS) id.VerificationTransactionID {
			txn, err := x.s.StartUser(context.Background(), sasOwner)
			if err != nil {
				x.t.Fatalf("start user: %v", err)
			}
			return txn
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, botSends := incomingPeerSAS(t, true, true, ownerPeers())
			active := tc.active(x)
			before, sends := x.s.Snapshot(), botSends.Load()
			attempts, remembered := x.gateCounts()
			sasRequest(x.bot, "second", sasOwner, "OWNERTWO", time.Now().Add(time.Minute))
			sasRequest(x.bot, "second-own", testUser, "OTHER", time.Now().Add(time.Minute))
			all, _ := x.s.store.GetAllVerificationTransactions(context.Background())
			if len(all) != 1 || all[0].TransactionID != active {
				t.Fatal("a request while busy entered the helper")
			}
			if a, r := x.gateCounts(); a != attempts || r != remembered {
				t.Fatal("a request while busy was counted")
			}
			if got := x.s.Snapshot(); got.Revision != before.Revision || got.TransactionID != active {
				t.Fatalf("a request while busy changed the snapshot: %+v", got)
			}
			if botSends.Load() != sends {
				t.Fatal("the bot replied to a request while busy")
			}
		})
	}
}

// Accept checks the prerequisites before replying to another user. A
// failed check returns its sentinel, sends the owner one cancellation and
// no ready, and ends the attempt cancelled.
func TestIncomingPeerSASAcceptChecksPrerequisites(t *testing.T) {
	for _, tc := range []struct {
		name          string
		botIdentity   bool
		ownerIdentity bool
		prepare       func(x *crossUserSAS)
		want          error
	}{
		{"no keys held", false, true, nil, ErrNoCrossSigningKeys},
		{"another identity published", true, true, func(x *crossUserSAS) { publishIdentity(x.t, x.h, testUser) }, ErrNoCrossSigningKeys},
		{"no peer identity", true, false, nil, ErrNoUserIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, botSends := incomingPeerSAS(t, tc.botIdentity, tc.ownerIdentity, ownerPeers())
			if tc.prepare != nil {
				tc.prepare(x)
			}
			txn := x.incomingRequest()
			x.owner.drain()
			if err := x.s.Accept(context.Background(), txn); !errors.Is(err, tc.want) {
				t.Fatalf("Accept = %v, want %v", err, tc.want)
			}
			if got := x.s.Snapshot(); got.State != SASCancelled || got.Reason != "cancelled" || got.TransactionID != txn || got.OtherUser != sasOwner {
				t.Fatalf("snapshot after a failed check = %+v", got)
			}
			if botSends.Load() != 1 {
				t.Fatalf("the bot sent %d to-device messages, want one cancellation", botSends.Load())
			}
			for _, ev := range x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID] {
				if ev.Type != event.ToDeviceVerificationCancel {
					t.Fatalf("the owner received %s before the check", ev.Type.Type)
				}
			}
			x.toOwner()
			cancelled := false
			for _, ev := range x.owner.drain() {
				if ev.ready {
					t.Fatal("the owner saw a ready")
				}
				cancelled = cancelled || (ev.txn == txn && ev.cancelled == event.VerificationCancelCodeUser)
			}
			if !cancelled {
				t.Fatal("the owner was not told the attempt ended")
			}
			if all, _ := x.s.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
				t.Fatal("a refused attempt stayed in the helper")
			}
			if err := x.s.Accept(context.Background(), txn); !errors.Is(err, ErrSASStale) {
				t.Fatalf("a second Accept = %v, want ErrSASStale", err)
			}
		})
	}
}

// A caller that gives up while Accept's checks are on the network leaves
// the request pending and sends nothing, and a later Accept succeeds.
func TestIncomingPeerSASAcceptCallerCancelledDuringCheck(t *testing.T) {
	x, botSends := incomingPeerSAS(t, true, true, ownerPeers())
	txn := x.incomingRequest()
	var block atomic.Bool
	block.Store(true)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	inner := x.h.ms.Server.Config.Handler
	x.h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if block.Load() && strings.HasSuffix(r.URL.Path, "/keys/query") && r.Header.Get("Authorization") == "Bearer "+x.bot.AccessToken {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
		inner.ServeHTTP(w, r)
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- x.s.Accept(ctx, txn) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not query keys")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Accept = %v, want context.Canceled", err)
	}
	block.Store(false)
	close(release)
	if got := x.s.Snapshot(); got.State != SASRequested || got.TransactionID != txn {
		t.Fatalf("a cancelled Accept changed the attempt: %+v", got)
	}
	if botSends.Load() != 0 {
		t.Fatal("a cancelled Accept sent something")
	}
	if err := x.s.Accept(context.Background(), txn); err != nil {
		t.Fatalf("a later Accept: %v", err)
	}
	x.wait(SASAccepted)
}

// Device ids are scoped to their user. A listed user's request from a
// device sharing this device's id passes the gate, but mautrix v0.31.0
// still ignores it (upstream behavior 4, pinned by
// TestUpstreamIgnoresPeerDeviceSharingTheLocalDeviceID). This account's
// own request from this device is still dropped by the gate.
func TestIncomingPeerSASPeerDeviceSharingTheLocalID(t *testing.T) {
	const twin = id.UserID("@twin:localhost")
	x, botSends := incomingPeerSAS(t, true, true, SASOptions{Peers: []id.UserID{twin}})
	sasRequest(x.bot, "self", testUser, x.bot.DeviceID, time.Now().Add(time.Minute))
	if attempts, remembered := x.gateCounts(); attempts != 0 || remembered != 0 {
		t.Fatal("the gate admitted this device's own request")
	}
	sasRequest(x.bot, "twin", twin, x.bot.DeviceID, time.Now().Add(time.Minute))
	x.s.gate.mu.Lock()
	_, passed := x.s.gate.recent["twin"]
	x.s.gate.mu.Unlock()
	if !passed {
		t.Fatal("the gate dropped a listed user's device that shares this device's id")
	}
	if all, _ := x.s.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
		t.Fatal("upstream now admits a peer device sharing the local id; revisit behavior 4 in docs/cross-user-verification.md")
	}
	if x.s.Snapshot().State != SASIdle || botSends.Load() != 0 {
		t.Fatal("an ignored request changed the attempt or sent something")
	}
}

// The options a controller was made with are fixed: equal sets return it,
// anything else is refused, and a refused call creates no controller.
func TestEnableSASWithOptions(t *testing.T) {
	h := newTestHS(t)
	c := openAs(t, h, testUser, t.TempDir(), nil)
	for _, tc := range []struct {
		opts SASOptions
		want error
	}{
		{SASOptions{Peers: []id.UserID{testUser}}, ErrOwnUser},
		{SASOptions{Peers: []id.UserID{testUser}, InRoom: true}, ErrOwnUser},
		{SASOptions{Peers: []id.UserID{"owner"}}, ErrInvalidSASPeer},
		{SASOptions{Peers: []id.UserID{"@owner"}}, ErrInvalidSASPeer},
		{SASOptions{Peers: []id.UserID{""}}, ErrInvalidSASPeer},
		{SASOptions{Peers: []id.UserID{id.UserID("@" + strings.Repeat("a", 250) + ":localhost")}}, ErrInvalidSASPeer},
	} {
		if _, err := c.EnableSASWith(tc.opts); !errors.Is(err, tc.want) {
			t.Fatalf("EnableSASWith(%+v) = %v, want %v", tc.opts, err, tc.want)
		}
	}
	c.connectOnce.Lock()
	created := c.sas != nil
	c.connectOnce.Unlock()
	if created {
		t.Fatal("a refused EnableSASWith created a controller")
	}

	peers := []id.UserID{sasOwner, "@second:localhost", sasOwner}
	s, err := c.EnableSASWith(SASOptions{Peers: peers})
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	peers[0] = "@mallory:localhost"
	if same, err := c.EnableSASWith(SASOptions{Peers: []id.UserID{"@second:localhost", sasOwner}}); err != nil || same != s {
		t.Fatalf("equal peers in another order = %v", err)
	}
	if !s.gate.admitsRequestFrom(testUser, sasOwner) || s.gate.admitsRequestFrom(testUser, "@mallory:localhost") {
		t.Fatal("the controller follows the caller's slice")
	}
	for _, opts := range []SASOptions{{}, {Peers: []id.UserID{sasOwner}}, {Peers: []id.UserID{sasOwner, "@second:localhost", "@third:localhost"}}, {Peers: []id.UserID{sasOwner, "@second:localhost"}, InRoom: true}} {
		if _, err := c.EnableSASWith(opts); !errors.Is(err, ErrSASUnavailable) {
			t.Fatalf("differing options %+v = %v, want ErrSASUnavailable", opts, err)
		}
	}
	if _, err := c.EnableSAS(); !errors.Is(err, ErrSASUnavailable) {
		t.Fatalf("EnableSAS on a controller with peers = %v", err)
	}
	// AwaitSAS accepts any request it sees, so neither one-shot wrapper runs
	// on a controller that admits other users.
	if err := c.AwaitSAS(context.Background(), func([]SASEmoji) bool { return false }); !errors.Is(err, ErrSASUnavailable) {
		t.Fatalf("AwaitSAS on a controller with peers = %v", err)
	}
	if _, err := c.VerifyUser(context.Background(), sasOwner, func([]SASEmoji) bool { return false }); !errors.Is(err, ErrSASUnavailable) {
		t.Fatalf("VerifyUser on a controller with peers = %v", err)
	}

	// EnableSAS is EnableSASWith(SASOptions{}).
	other := openAs(t, h, testUser, t.TempDir(), nil)
	zero, err := other.EnableSAS()
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	for _, opts := range []SASOptions{{}, {Peers: []id.UserID{}}} {
		if same, err := other.EnableSASWith(opts); err != nil || same != zero {
			t.Fatalf("EnableSASWith(%+v) after EnableSAS = %v", opts, err)
		}
	}
	if _, err := other.EnableSASWith(ownerPeers()); !errors.Is(err, ErrSASUnavailable) {
		t.Fatalf("peers after EnableSAS = %v", err)
	}
	if _, err := other.EnableSASWith(SASOptions{InRoom: true}); !errors.Is(err, ErrSASUnavailable) {
		t.Fatalf("InRoom after EnableSAS = %v", err)
	}

	// InRoom is part of the options: equal ones return the controller, and
	// a call without it is refused.
	third := openAs(t, h, testUser, t.TempDir(), nil)
	inRoom, err := third.EnableSASWith(SASOptions{Peers: []id.UserID{sasOwner}, InRoom: true})
	if err != nil {
		t.Fatalf("enable in-room: %v", err)
	}
	if same, err := third.EnableSASWith(SASOptions{Peers: []id.UserID{sasOwner, sasOwner}, InRoom: true}); err != nil || same != inRoom {
		t.Fatalf("equal in-room options = %v", err)
	}
	if _, err := third.EnableSASWith(ownerPeers()); !errors.Is(err, ErrSASUnavailable) {
		t.Fatalf("options without InRoom = %v", err)
	}
}

// A peer that cancels, or a request that expires, while Accept's checks
// are on the network ends the attempt: Accept sends no ready, and returns
// ErrSASStale, or the check's error when it fails, without sending a
// second cancellation. The helper's cancelled callback sets the snapshot.
func TestIncomingPeerSASPeerCancelsDuringAccept(t *testing.T) {
	for _, ownerIdentity := range []bool{true, false} {
		t.Run(fmt.Sprintf("owner identity %v", ownerIdentity), func(t *testing.T) {
			x, botSends := incomingPeerSAS(t, true, ownerIdentity, ownerPeers())
			txn := x.incomingRequest()
			entered, release := inRoomBlockKeys(x.h, x.bot)
			result := make(chan error, 1)
			go func() { result <- x.s.Accept(context.Background(), txn) }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("Accept did not query keys")
			}
			if err := x.owner.helper.CancelVerification(x.ctx, txn, event.VerificationCancelCodeUser, "no"); err != nil {
				t.Fatal("owner cancel failed")
			}
			x.toBot()
			close(release)
			want := ErrSASStale
			if !ownerIdentity {
				want = ErrNoUserIdentity
			}
			if err := <-result; !errors.Is(err, want) {
				t.Fatalf("Accept = %v, want %v", err, want)
			}
			x.wait(SASCancelled)
			if botSends.Load() != 0 {
				t.Fatal("the bot sent something to a cancelled attempt")
			}
			if all, _ := x.s.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
				t.Fatal("a cancelled attempt stayed in the helper")
			}
		})
	}
}

// Stopping Sync while Accept's checks are on the network returns
// ErrSASUnavailable and sends nothing.
func TestIncomingPeerSASShutdownDuringAccept(t *testing.T) {
	x := newCrossUserFixture(t, true, true, "")
	s, err := x.bot.EnableSASWith(ownerPeers())
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	x.s = s
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- x.bot.Sync(ctx) }()
	sasWait(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.started })
	txn := x.incomingRequest()
	entered, release := inRoomBlockKeys(x.h, x.bot)
	defer close(release)
	before := len(x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID])
	result := make(chan error, 1)
	go func() { result <- s.Accept(context.Background(), txn) }()
	<-entered
	cancel()
	<-done
	if err := <-result; !errors.Is(err, ErrSASUnavailable) {
		t.Fatalf("Accept during shutdown = %v", err)
	}
	if got := s.Snapshot(); got.State != SASStopped {
		t.Fatalf("snapshot after shutdown = %+v", got)
	}
	if len(x.h.ms.DeviceInbox[sasOwner][x.owner.client.DeviceID]) != before {
		t.Fatal("the bot sent the owner something during shutdown")
	}
}
