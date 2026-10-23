//go:build e2e

package rihma

import (
	"context"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// In-room SAS on Synapse between two rihma clients of different users in
// an encrypted DM, both enabled with InRoom and listing each other. One
// starts with StartInRoom, and the other admits the request because the
// starter is in its Peers, in each direction on fresh accounts. The side
// that accepted confirms first, so its MAC is held until the starter's
// person confirms; afterwards each side has signed the other's master key.
// mautrix's helper cannot drive the peer here: it does not route in-room
// follow-ups (TestUpstreamInRoomFollowUpsMissTheirTransaction). Logs are
// captured at trace and never printed; no signature or recovery key may
// appear in them.
func TestE2EInRoomSAS(t *testing.T) {
	hs := e2eHomeserver(t)
	u, err := url.Parse(hs)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || os.Getenv("RIHMA_E2E_DISPOSABLE") != "1" {
		t.Skip("owned loopback fixture required")
	}
	t.Run("bot starts", func(t *testing.T) { liveInRoomSAS(t, hs, true, false) })
	t.Run("owner starts", func(t *testing.T) { liveInRoomSAS(t, hs, false, false) })
	// Element sends its in-room verification events unencrypted even in an
	// encrypted DM; the bot admits them and still encrypts its own.
	t.Run("bot starts, owner sends unencrypted", func(t *testing.T) { liveInRoomSAS(t, hs, true, true) })
	t.Run("owner starts, owner sends unencrypted", func(t *testing.T) { liveInRoomSAS(t, hs, false, true) })
}

func liveInRoomSAS(t *testing.T, hs string, botStarts, ownerPlain bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tag := e2eTag()
	pw := "pw-in-room"
	logs := &lockedBuffer{}
	open := func(name string) (*Client, string) {
		register(t, ctx, hs, name, pw)
		opts := e2eOptions(t, hs, name, pw, t.TempDir())
		opts.Logger = zerolog.New(logs).Level(zerolog.TraceLevel)
		c, err := Open(ctx, opts)
		if err != nil {
			t.Fatal("open failed")
		}
		t.Cleanup(func() { c.Close() })
		recovery, err := c.CreateRecoveryKey(ctx, pw)
		if err != nil {
			t.Fatal("identity creation failed")
		}
		return c, recovery
	}
	bot, botRecovery := open("irbot-" + tag)
	owner, ownerRecovery := open("irowner-" + tag)
	botKey, err := bot.OwnMasterKey(ctx)
	if err != nil {
		t.Fatal("bot key failed")
	}
	ownerKey, err := owner.OwnMasterKey(ctx)
	if err != nil {
		t.Fatal("owner key failed")
	}

	// The owner's DM with the bot, encrypted, as Element creates it.
	created, err := owner.CreateRoom(ctx, &mautrix.ReqCreateRoom{Preset: "trusted_private_chat", IsDirect: true, Invite: []id.UserID{bot.UserID}, InitialState: []*event.Event{{Type: event.StateEncryption, Content: event.Content{Parsed: &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}}}}})
	if err != nil {
		t.Fatal("DM creation failed")
	}
	dm := created.RoomID
	if _, err := bot.JoinRoomByID(ctx, dm); err != nil {
		t.Fatal("join failed")
	}
	botS, err := bot.EnableSASWith(SASOptions{Peers: []id.UserID{owner.UserID}, InRoom: true})
	if err != nil {
		t.Fatal("bot controller failed")
	}
	ownerS, err := owner.EnableSASWith(SASOptions{Peers: []id.UserID{bot.UserID}, InRoom: true})
	if err != nil {
		t.Fatal("owner controller failed")
	}
	var mu sync.Mutex
	seen := map[id.EventID]bool{}
	for _, c := range []*Client{bot, owner} {
		c.Handlers().OnEventType(event.EventMessage, func(_ context.Context, ev *event.Event) {
			if ev.Mautrix.WasEncrypted {
				mu.Lock()
				seen[ev.ID] = true
				mu.Unlock()
			}
		})
	}
	// How each side's verification events arrived at the other.
	arrived := map[id.UserID]map[bool]int{}
	for _, c := range []*Client{bot, owner} {
		for _, kind := range []event.Type{event.EventMessage, event.InRoomVerificationReady, event.InRoomVerificationStart, event.InRoomVerificationAccept, event.InRoomVerificationKey, event.InRoomVerificationMAC, event.InRoomVerificationDone} {
			c.Handlers().OnEventType(kind, func(_ context.Context, ev *event.Event) {
				if msg, ok := ev.Content.Parsed.(*event.MessageEventContent); ok && msg.MsgType != event.MsgVerificationRequest {
					return
				}
				mu.Lock()
				if arrived[ev.Sender] == nil {
					arrived[ev.Sender] = map[bool]int{}
				}
				arrived[ev.Sender][ev.Mautrix.WasEncrypted]++
				mu.Unlock()
			})
		}
	}
	runPolicySync(t, bot)
	runPolicySync(t, owner)
	for _, s := range []*SASController{botS, ownerS} {
		liveSASWait(t, ctx, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.started })
	}
	liveSASWait(t, ctx, func() bool { return bot.sasRoomUsable(ctx, dm) && owner.sasRoomUsable(ctx, dm) })
	// Each side reads the other's message first, so both track each
	// other's devices and room keys flow before the request.
	for _, pair := range [][2]*Client{{owner, bot}, {bot, owner}} {
		sent, err := pair[0].SendText(ctx, dm, "synthetic in-room verification fixture")
		if err != nil {
			t.Fatal("warm-up send failed")
		}
		liveSASWait(t, ctx, func() bool { mu.Lock(); defer mu.Unlock(); return seen[sent.EventID] })
	}
	if ownerPlain {
		// Only SendMessageEvent reads Crypto; the owner still decrypts.
		owner.Client.Crypto = nil
	}

	starter, starterS, starterKey, receiver, receiverS, receiverKey := bot, botS, botKey, owner, ownerS, ownerKey
	if !botStarts {
		starter, starterS, starterKey, receiver, receiverS, receiverKey = owner, ownerS, ownerKey, bot, botS, botKey
	}
	txn, err := starterS.StartInRoom(ctx, dm, receiver.UserID)
	if err != nil {
		t.Fatalf("start in room: %v", err)
	}
	liveSASWait(t, ctx, func() bool { got := receiverS.Snapshot(); return got.State == SASRequested && got.TransactionID == txn })
	if got := receiverS.Snapshot(); got.OtherUser != starter.UserID || got.Room != dm || got.OtherDevice != starter.DeviceID {
		t.Fatal("the requested snapshot does not name the starter's device in the DM")
	}
	if err := receiverS.Accept(ctx, txn); err != nil {
		t.Fatalf("accept: %v", err)
	}
	for _, s := range []*SASController{starterS, receiverS} {
		liveSASWait(t, ctx, func() bool {
			st := s.Snapshot().State
			return st == SASShowing || st == SASCancelled || st == SASFailed
		})
	}
	a, b := starterS.Snapshot(), receiverS.Snapshot()
	if a.State != SASShowing || b.State != SASShowing || len(a.Emoji) != 7 || len(b.Emoji) != 7 {
		t.Fatalf("emoji not shown on both sides: %v/%s, %v/%s", a.State, a.Reason, b.State, b.Reason)
	}
	for i := range a.Emoji {
		if a.Emoji[i] != b.Emoji[i] {
			t.Fatal("the emoji differ between the sides")
		}
	}
	if err := receiverS.Confirm(ctx, txn, true); err != nil {
		t.Fatalf("receiver confirm: %v", err)
	}
	// Give the receiver's MAC time to reach the starter, where it is held.
	time.Sleep(2 * time.Second)
	if got := starterS.Snapshot(); got.State != SASShowing {
		t.Fatalf("the receiver's MAC changed the attempt before the starter confirmed: %v", got.State)
	}
	if err := starterS.Confirm(ctx, txn, true); err != nil {
		t.Fatalf("starter confirm: %v", err)
	}
	for _, side := range []struct {
		s   *SASController
		key id.Ed25519
	}{{starterS, receiverKey}, {receiverS, starterKey}} {
		liveSASWait(t, ctx, func() bool {
			st := side.s.Snapshot().State
			return st == SASDone || st == SASFailed || st == SASCancelled
		})
		if got := side.s.Snapshot(); got.State != SASDone || got.MasterKey != side.key || got.Room != dm {
			t.Fatalf("outcome = %v/%s, master key matches: %v", got.State, got.Reason, got.MasterKey == side.key)
		}
	}
	mu.Lock()
	ownerPlainCount, ownerSealed, botPlain, botSealed := arrived[owner.UserID][false], arrived[owner.UserID][true], arrived[bot.UserID][false], arrived[bot.UserID][true]
	mu.Unlock()
	if botPlain != 0 || botSealed == 0 {
		t.Fatalf("the bot's verification events arrived %d unencrypted, %d encrypted", botPlain, botSealed)
	}
	if ownerPlain && (ownerSealed != 0 || ownerPlainCount == 0) || !ownerPlain && (ownerPlainCount != 0 || ownerSealed == 0) {
		t.Fatalf("the owner's verification events arrived %d unencrypted, %d encrypted", ownerPlainCount, ownerSealed)
	}
	for _, pair := range [][2]*Client{{bot, owner}, {owner, bot}} {
		if ident, err := pair[0].UserIdentity(ctx, pair[1].UserID); err != nil || !ident.SignedByUs {
			t.Fatalf("one side did not sign the other: %v", err)
		}
	}
	// A server shows a user-signing signature only to its maker, so each
	// side reads its own.
	for _, pair := range [][2]*Client{{bot, owner}, {owner, bot}} {
		resp, err := pair[0].QueryKeys(ctx, &mautrix.ReqQueryKeys{DeviceKeys: mautrix.DeviceKeysRequest{pair[0].UserID: {}, pair[1].UserID: {}}})
		if err != nil {
			t.Fatal("key query failed")
		}
		usk := resp.UserSigningKeys[pair[0].UserID]
		signature := resp.MasterKeys[pair[1].UserID].Signatures[pair[0].UserID][id.NewKeyID(id.KeyAlgorithmEd25519, usk.FirstKey().String())]
		if signature == "" {
			t.Fatal("the server holds no user-signing signature")
		}
		if logs.contains(signature) {
			t.Fatal("a signature reached the logs")
		}
	}
	if logs.contains(botRecovery) || logs.contains(ownerRecovery) || logs.contains("synthetic in-room verification fixture") {
		t.Fatal("a recovery key or message text reached the logs")
	}
}
