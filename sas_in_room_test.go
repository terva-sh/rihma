package rihma

// Tests for in-room SAS with another user (SASOptions.InRoom and
// StartInRoom), run between two rihma clients on the mock server. See
// docs/cross-user-verification.md. The mock has no rooms, so
// inRoomTransport stands in for megolm and the room timeline: it records
// what each client sends to a room and delivers it to a client as sync
// would, decrypted and marked as having arrived encrypted. Helpers here are
// prefixed inRoom so they stay apart from the to-device SAS helpers.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/mockserver"
)

const inRoomDM = id.RoomID("!dm:localhost")

// inRoomEvent is one event a client sent to a room.
type inRoomEvent struct {
	room      id.RoomID
	sender    id.UserID
	id        id.EventID
	kind      string
	content   json.RawMessage
	encrypted bool
}

// inRoomTransport records room sends on the mock and replays them. Its
// Encrypt keeps the plaintext and returns a megolm-shaped placeholder that
// names it; a client wired to it sends that placeholder.
type inRoomTransport struct {
	t       *testing.T
	mu      sync.Mutex
	plain   []inRoomEvent // what was handed to Encrypt, by index
	log     []inRoomEvent
	cursor  map[id.UserID]int
	tokens  map[string]id.UserID
	toSend  map[id.UserID]*atomic.Int32 // to-device sends per user
	reenc   int                         // Encrypt calls given already-encrypted content
	encrypt int
	// plainFrom delivers a user's events as having arrived unencrypted, as
	// Element sends in-room verification events even in an encrypted room.
	plainFrom map[id.UserID]bool
	// onSend, when set, sees each room event after it is recorded and
	// before the sender gets its event id.
	onSend func(inRoomEvent)
}

func newInRoomTransport(t *testing.T, ms *mockserver.MockServer) *inRoomTransport {
	tr := &inRoomTransport{t: t, cursor: map[id.UserID]int{}, tokens: map[string]id.UserID{}, toSend: map[id.UserID]*atomic.Int32{}, plainFrom: map[id.UserID]bool{}}
	inner := ms.Server.Config.Handler
	ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tr.mu.Lock()
		sender, known := tr.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		tr.mu.Unlock()
		if known && strings.Contains(r.URL.Path, "/sendToDevice/") {
			tr.toSend[sender].Add(1)
		}
		if r.Method != http.MethodPut || !strings.Contains(r.URL.Path, "/rooms/") || !strings.Contains(r.URL.Path, "/send/") {
			inner.ServeHTTP(w, r)
			return
		}
		parts := strings.Split(r.URL.Path, "/")
		var room id.RoomID
		var kind string
		for i, part := range parts {
			if part == "rooms" && i+3 < len(parts) {
				room, kind = id.RoomID(parts[i+1]), parts[i+3]
			}
		}
		var body bytes.Buffer
		body.ReadFrom(r.Body)
		ev := tr.record(room, sender, kind, body.Bytes())
		if tr.onSend != nil {
			ev.room, ev.sender = room, sender
			tr.onSend(ev)
		}
		w.Write([]byte(fmt.Sprintf(`{"event_id":%q}`, ev.id)))
	})
	return tr
}

func (tr *inRoomTransport) record(room id.RoomID, sender id.UserID, kind string, body []byte) inRoomEvent {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	ev := inRoomEvent{room: room, sender: sender, kind: kind, content: append(json.RawMessage(nil), body...)}
	if kind == event.EventEncrypted.Type {
		var wire struct {
			Ciphertext string `json:"ciphertext"`
		}
		n, err := -1, json.Unmarshal(body, &wire)
		if err == nil && strings.HasPrefix(wire.Ciphertext, "plain-") {
			n, _ = strconv.Atoi(strings.TrimPrefix(wire.Ciphertext, "plain-"))
		}
		if n < 0 || n >= len(tr.plain) {
			tr.t.Error("an encrypted room event the transport cannot read")
			return inRoomEvent{id: "$unreadable"}
		}
		ev.kind, ev.content, ev.encrypted = tr.plain[n].kind, tr.plain[n].content, true
	}
	ev.id = id.EventID(fmt.Sprintf("$ev%d:localhost", len(tr.log)))
	tr.log = append(tr.log, ev)
	return ev
}

// attach routes c's encryption and room sends through the transport.
func (tr *inRoomTransport) attach(c *Client) {
	tr.t.Helper()
	if err := c.Connect(context.Background()); err != nil {
		tr.t.Fatal("connect failed")
	}
	tr.mu.Lock()
	tr.tokens[c.AccessToken] = c.UserID
	tr.toSend[c.UserID] = new(atomic.Int32)
	tr.mu.Unlock()
	c.Crypto = &inRoomCrypto{CryptoHelper: c.Crypto, tr: tr}
}

type inRoomCrypto struct {
	mautrix.CryptoHelper
	tr *inRoomTransport
}

func (c *inRoomCrypto) Encrypt(_ context.Context, _ id.RoomID, kind event.Type, content any) (*event.EncryptedEventContent, error) {
	c.tr.mu.Lock()
	defer c.tr.mu.Unlock()
	c.tr.encrypt++
	if _, again := content.(*event.EncryptedEventContent); again {
		c.tr.reenc++
	}
	raw, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}
	c.tr.plain = append(c.tr.plain, inRoomEvent{kind: kind.Type, content: raw})
	return &event.EncryptedEventContent{Algorithm: id.AlgorithmMegolmV1, MegolmCiphertext: []byte(fmt.Sprintf("plain-%d", len(c.tr.plain)-1))}, nil
}

// deliver dispatches to c every room event sent since its last delivery,
// its own included, as sync does, and returns them.
func (tr *inRoomTransport) deliver(c *Client) []inRoomEvent {
	tr.t.Helper()
	tr.mu.Lock()
	pending := append([]inRoomEvent(nil), tr.log[tr.cursor[c.UserID]:]...)
	tr.cursor[c.UserID] = len(tr.log)
	for i := range pending {
		pending[i].encrypted = pending[i].encrypted && !tr.plainFrom[pending[i].sender]
	}
	tr.mu.Unlock()
	for _, re := range pending {
		c.Handlers().Dispatch(context.Background(), re.event(tr.t))
	}
	return pending
}

func (re inRoomEvent) event(t *testing.T) *event.Event {
	t.Helper()
	ev := &event.Event{Type: event.Type{Type: re.kind, Class: event.MessageEventType}, Sender: re.sender, RoomID: re.room, ID: re.id, Timestamp: time.Now().UnixMilli(), Content: event.Content{VeryRaw: re.content}}
	if err := ev.Content.ParseRaw(ev.Type); err != nil {
		t.Fatalf("parse %s: %v", re.kind, err)
	}
	ev.Mautrix.WasEncrypted = re.encrypted
	return ev
}

// roomSends counts the room events sender sent.
func (tr *inRoomTransport) roomSends(sender id.UserID) (n int) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	for _, ev := range tr.log {
		if ev.sender == sender {
			n++
		}
	}
	return n
}

func (tr *inRoomTransport) sentBy(sender id.UserID) []inRoomEvent {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	var out []inRoomEvent
	for _, ev := range tr.log {
		if ev.sender == sender {
			out = append(out, ev)
		}
	}
	return out
}

// inRoomJoin records in c's state store that room is encrypted when asked
// and that members have joined it.
func inRoomJoin(t *testing.T, c *Client, room id.RoomID, encrypted bool, members ...id.UserID) {
	t.Helper()
	ctx := context.Background()
	if encrypted {
		if err := c.StateStore.SetEncryptionEvent(ctx, room, &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}); err != nil {
			t.Fatal("room state failed")
		}
	}
	for _, user := range members {
		if err := c.StateStore.SetMembership(ctx, room, user, event.MembershipJoin); err != nil {
			t.Fatal("room state failed")
		}
	}
}

// inRoomSAS is a bot and its owner, both rihma clients with cross-signing
// identities, sharing the encrypted DM inRoomDM and syncing.
type inRoomSAS struct {
	t                *testing.T
	h                *testHS
	tr               *inRoomTransport
	bot, owner       *Client
	botS, ownerS     *SASController
	botKey, ownerKey id.Ed25519
	botLogs          *bytes.Buffer
}

func newInRoomSAS(t *testing.T, botOpts, ownerOpts SASOptions, ownerIdentity bool) *inRoomSAS {
	t.Helper()
	x := &inRoomSAS{t: t, h: newTestHS(t), botLogs: &bytes.Buffer{}}
	keepSignatures(x.h)
	x.tr = newInRoomTransport(t, x.h.ms)
	x.bot = openAs(t, x.h, testUser, t.TempDir(), func(o *Options) { o.Logger = zerolog.New(x.botLogs).Level(zerolog.TraceLevel) })
	x.owner = openAs(t, x.h, sasOwner, t.TempDir(), func(o *Options) { o.Logger = zerolog.Nop() })
	x.botKey = createIdentity(t, x.bot)
	if ownerIdentity {
		x.ownerKey = createIdentity(t, x.owner)
	}
	for _, c := range []*Client{x.bot, x.owner} {
		x.tr.attach(c)
		inRoomJoin(t, c, inRoomDM, true, testUser, sasOwner)
	}
	x.botS = inRoomSync(t, x.bot, botOpts)
	x.ownerS = inRoomSync(t, x.owner, ownerOpts)
	return x
}

func inRoomSync(t *testing.T, c *Client, opts SASOptions) *SASController {
	t.Helper()
	s, err := c.EnableSASWith(opts)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Sync(ctx) }()
	sasWait(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.started })
	t.Cleanup(func() { cancel(); <-done })
	return s
}

func inRoomBoth(peer id.UserID) SASOptions {
	return SASOptions{Peers: []id.UserID{peer}, InRoom: true}
}

func inRoomWait(t *testing.T, s *SASController, state SASState) SASSnapshot {
	t.Helper()
	sasWait(t, func() bool { return s.Snapshot().State == state })
	return s.Snapshot()
}

// inRoomToShowing has from start an in-room request to the other side,
// which accepts it, and runs the exchange until both show the same emoji.
func (x *inRoomSAS) inRoomToShowing(from *Client) id.VerificationTransactionID {
	x.t.Helper()
	to := x.bot
	fromS, toS := x.ownerS, x.botS
	if from == x.bot {
		to, fromS, toS = x.owner, x.botS, x.ownerS
	}
	txn, err := fromS.StartInRoom(context.Background(), inRoomDM, to.UserID)
	if err != nil {
		x.t.Fatalf("start in room: %v", err)
	}
	if got := fromS.Snapshot(); got.State != SASSent || got.TransactionID != txn || got.Room != inRoomDM || got.OtherUser != to.UserID {
		x.t.Fatalf("snapshot after StartInRoom = %+v", got)
	}
	x.tr.deliver(to) // request
	got := inRoomWait(x.t, toS, SASRequested)
	if got.TransactionID != txn || got.OtherUser != from.UserID || got.Room != inRoomDM || got.OtherDevice != from.DeviceID {
		x.t.Fatalf("requested snapshot = %+v", got)
	}
	if err := toS.Accept(context.Background(), txn); err != nil {
		x.t.Fatalf("accept: %v", err)
	}
	inRoomWait(x.t, toS, SASAccepted)
	x.tr.deliver(from) // its own request, and ready; it sends start
	inRoomWait(x.t, fromS, SASAccepted)
	x.tr.deliver(to)   // start; it sends accept
	x.tr.deliver(from) // accept; it sends key
	x.tr.deliver(to)   // key; it sends key and shows emoji
	x.tr.deliver(from) // key; it shows emoji
	a, b := inRoomWait(x.t, fromS, SASShowing), inRoomWait(x.t, toS, SASShowing)
	if len(a.Emoji) != 7 || len(b.Emoji) != 7 {
		x.t.Fatal("emoji not shown on both sides")
	}
	for i := range a.Emoji {
		if a.Emoji[i] != b.Emoji[i] {
			x.t.Fatal("emoji differ between the sides")
		}
	}
	return txn
}

// inRoomComplete has first confirm, then second, delivering between them
// so that second holds first's MAC, and checks both sides end done with
// the other's master key signed.
func (x *inRoomSAS) inRoomComplete(txn id.VerificationTransactionID, first, second *Client) {
	x.t.Helper()
	ctl := func(c *Client) *SASController {
		if c == x.bot {
			return x.botS
		}
		return x.ownerS
	}
	if err := ctl(first).Confirm(context.Background(), txn, true); err != nil {
		x.t.Fatalf("first confirm: %v", err)
	}
	x.tr.deliver(second) // first's MAC, held
	if got := ctl(second).Snapshot(); got.State != SASShowing {
		x.t.Fatalf("a held MAC changed the attempt: %+v", got)
	}
	if err := ctl(second).Confirm(context.Background(), txn, true); err != nil {
		x.t.Fatalf("second confirm: %v", err)
	}
	x.tr.deliver(first)  // second's MAC and done
	x.tr.deliver(second) // first's done
	for _, side := range []struct {
		c   *Client
		key id.Ed25519
		of  id.UserID
	}{{x.bot, x.ownerKey, sasOwner}, {x.owner, x.botKey, testUser}} {
		got := inRoomWait(x.t, ctl(side.c), SASDone)
		if got.TransactionID != txn || got.MasterKey != side.key || got.Room != inRoomDM || got.OtherUser != side.of {
			x.t.Fatalf("done snapshot = %+v", got)
		}
		ident, err := side.c.UserIdentity(context.Background(), side.of)
		if err != nil || !ident.SignedByUs || ident.MasterKey != side.key {
			x.t.Fatalf("identity after SAS = %+v, %v", ident, err)
		}
	}
	for _, ev := range x.tr.sentBy(testUser) {
		if !ev.encrypted {
			x.t.Fatalf("the bot sent %s to the room unencrypted", ev.kind)
		}
	}
	if x.tr.toSend[testUser].Load() != 0 {
		x.t.Fatal("an in-room attempt sent to-device messages")
	}
}

// The owner asks in the DM, as Element does, and the bot admits it
// because the owner is listed; each side signs the other.
func TestInRoomSASIncomingCompletes(t *testing.T) {
	x := newInRoomSAS(t, inRoomBoth(sasOwner), SASOptions{InRoom: true}, true)
	txn := x.inRoomToShowing(x.owner)
	x.inRoomComplete(txn, x.owner, x.bot)
}

// The bot asks with StartInRoom, and confirms first.
func TestInRoomSASOutgoingCompletes(t *testing.T) {
	x := newInRoomSAS(t, SASOptions{InRoom: true}, inRoomBoth(testUser), true)
	txn := x.inRoomToShowing(x.bot)
	x.inRoomComplete(txn, x.bot, x.owner)
}

// Element sends in-room verification events unencrypted even in an
// encrypted DM. Whoever starts, the bot admits the owner's unencrypted
// request and follow-ups, keeps encrypting its own, and completes.
func TestInRoomSASUnencryptedPeerCompletes(t *testing.T) {
	for _, botStarts := range []bool{false, true} {
		t.Run(fmt.Sprintf("bot starts %v", botStarts), func(t *testing.T) {
			x := newInRoomSAS(t, inRoomBoth(sasOwner), inRoomBoth(testUser), true)
			x.tr.plainFrom[sasOwner] = true
			if botStarts {
				x.inRoomComplete(x.inRoomToShowing(x.bot), x.owner, x.bot)
			} else {
				x.inRoomComplete(x.inRoomToShowing(x.owner), x.owner, x.bot)
			}
		})
	}
}

// If the request is out but its transaction cannot be saved, the peer is
// told at once: StartInRoom sends a cancellation referencing the request,
// because no helper path could end it later.
func TestInRoomSASStartCancelsWhenTheSaveFails(t *testing.T) {
	x := newInRoomSAS(t, SASOptions{InRoom: true}, inRoomBoth(testUser), true)
	x.tr.onSend = func(ev inRoomEvent) {
		if ev.sender == testUser && ev.kind == event.EventMessage.Type {
			x.botS.store.close()
		}
	}
	if _, err := x.botS.StartInRoom(context.Background(), inRoomDM, sasOwner); !errors.Is(err, ErrSASOperation) {
		t.Fatalf("StartInRoom with a failing save = %v", err)
	}
	if got := x.botS.Snapshot(); got.State != SASFailed || got.Reason != "operation_failed" {
		t.Fatalf("snapshot = %+v", got)
	}
	sent := x.tr.sentBy(testUser)
	if len(sent) != 2 || sent[1].kind != event.InRoomVerificationCancel.Type || !sent[1].encrypted {
		t.Fatalf("no cancellation followed the request: %+v", sent)
	}
	var cancel event.VerificationCancelEventContent
	if err := json.Unmarshal(sent[1].content, &cancel); err != nil || cancel.RelatesTo == nil || cancel.RelatesTo.EventID != sent[0].id {
		t.Fatal("the cancellation does not reference the request")
	}
	x.tr.deliver(x.owner)
	if all, _ := x.ownerS.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
		t.Fatal("the owner still holds the request")
	}
}

// inRoomRequestEvent is an in-room request from from to to in room, sent
// at sent, marked as having arrived encrypted when asked.
func inRoomRequestEvent(from, to id.UserID, room id.RoomID, eventID id.EventID, sent time.Time, encrypted bool) *event.Event {
	ev := inRoomRequest(from, to, room, eventID)
	ev.Timestamp = sent.UnixMilli()
	ev.Mautrix.WasEncrypted = encrypted
	return ev
}

// Every in-room request that fails a rule is dropped before the helper,
// with no transaction, attempt, remembered id, reply or snapshot change,
// and a debug line naming the reason. Arriving unencrypted is not a
// reason: Element sends its requests that way.
func TestInRoomSASDropsRequests(t *testing.T) {
	x := newInRoomSAS(t, inRoomBoth(sasOwner), SASOptions{InRoom: true}, true)
	inRoomJoin(t, x.bot, "!plain:localhost", false, testUser, sasOwner)
	if err := x.bot.StateStore.SetEncryptionEvent(context.Background(), "!left:localhost", &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}); err != nil {
		t.Fatal("room state failed")
	}
	now := time.Now()
	revision := x.botS.Snapshot().Revision
	for _, ev := range []*event.Event{
		inRoomRequestEvent(sasOwner, testUser, "!left:localhost", "$unjoined", now, true),
		inRoomRequestEvent(sasOwner, testUser, "!plain:localhost", "$unencrypted-room", now, true),
		inRoomRequestEvent(sasOwner, "@someone:localhost", inRoomDM, "$to-another", now, true),
		inRoomRequestEvent(sasOwner, testUser, "!plain:localhost", "$unencrypted-room-plain", now, false),
		inRoomRequestEvent("@stranger:localhost", testUser, inRoomDM, "$stranger", now, true),
		inRoomRequestEvent("@stranger:localhost", testUser, inRoomDM, "$stranger-plain", now, false),
		inRoomRequestEvent(testUser, testUser, inRoomDM, "$own", now, true),
		inRoomRequestEvent(sasOwner, testUser, inRoomDM, "$old", now.Add(-11*time.Minute), true),
		inRoomRequestEvent(sasOwner, testUser, inRoomDM, "$future", now.Add(2*time.Minute), true),
		inRoomRequestEvent(sasOwner, testUser, inRoomDM, "", now, true),
	} {
		x.bot.Handlers().Dispatch(context.Background(), ev)
	}
	if all, _ := x.botS.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
		t.Fatalf("a refused request entered the helper: %s", all[0].TransactionID)
	}
	x.botS.gate.mu.Lock()
	attempts, remembered := x.botS.gate.attempts, len(x.botS.gate.recent)
	x.botS.gate.mu.Unlock()
	if attempts != 0 || remembered != 0 {
		t.Fatalf("a refused request was counted: %d attempts, %d ids", attempts, remembered)
	}
	if got := x.botS.Snapshot(); got.State != SASIdle || got.Revision != revision {
		t.Fatalf("a refused request changed the snapshot: %+v", got)
	}
	if x.tr.roomSends(testUser) != 0 || x.tr.toSend[testUser].Load() != 0 {
		t.Fatal("the bot replied to a refused request")
	}
	// Each drop is logged at debug with its reason and no content.
	for _, reason := range []string{sasDropRoom, sasDropNotForUs, sasDropUnlisted, sasDropOwnEvent, sasDropStale, sasDropMalformed} {
		if !bytes.Contains(x.botLogs.Bytes(), []byte(`"reason":"`+reason+`"`)) {
			t.Fatalf("no log line gives the reason %q", reason)
		}
	}
	if bytes.Contains(x.botLogs.Bytes(), []byte("verification request")) {
		t.Fatal("a request's body reached the logs")
	}
	// The same request, admissible, is admitted, also unencrypted, as
	// Element sends it.
	x.bot.Handlers().Dispatch(context.Background(), inRoomRequestEvent(sasOwner, testUser, inRoomDM, "$good", now, false))
	if got := inRoomWait(t, x.botS, SASRequested); got.TransactionID != "$good" || got.Room != inRoomDM {
		t.Fatalf("an admissible request = %+v", got)
	}
}

// Without InRoom a controller registers no in-room handler, whoever lists
// the sender.
func TestInRoomSASNeedsInRoom(t *testing.T) {
	x := newInRoomSAS(t, ownerPeers(), SASOptions{InRoom: true}, true)
	x.bot.Handlers().Dispatch(context.Background(), inRoomRequestEvent(sasOwner, testUser, inRoomDM, "$req", time.Now(), true))
	if all, _ := x.botS.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 || x.botS.Snapshot().State != SASIdle {
		t.Fatal("an in-room request reached a controller without InRoom")
	}
	if _, err := x.botS.StartInRoom(context.Background(), inRoomDM, sasOwner); !errors.Is(err, ErrSASUnavailable) {
		t.Fatalf("StartInRoom without InRoom = %v", err)
	}
}

// inRoomFollowUp is a follow-up of kind in room from sender referencing
// request.
func inRoomFollowUp(kind event.Type, sender id.UserID, room id.RoomID, request id.EventID, encrypted bool) *event.Event {
	rel := &event.RelatesTo{Type: event.RelReference, EventID: request}
	var parsed any
	switch kind {
	case event.InRoomVerificationReady:
		parsed = &event.VerificationReadyEventContent{InRoomVerificationEvent: event.InRoomVerificationEvent{RelatesTo: rel}, FromDevice: "OWNERDEVICE", Methods: []event.VerificationMethod{event.VerificationMethodSAS}}
	default:
		parsed = &event.VerificationCancelEventContent{InRoomVerificationEvent: event.InRoomVerificationEvent{RelatesTo: rel}, Code: event.VerificationCancelCodeUser}
	}
	ev := &event.Event{Type: kind, Sender: sender, RoomID: room, ID: id.EventID(fmt.Sprintf("$f-%d", time.Now().UnixNano())), Timestamp: time.Now().UnixMilli(), Content: event.Content{Parsed: parsed}}
	ev.Mautrix.WasEncrypted = encrypted
	return ev
}

// Follow-ups bound to the attempt: only an event in its room, from its
// user, referencing its request reaches the helper, encrypted or not. A to-device
// event naming the in-room transaction does not either.
func TestInRoomSASDropsForeignFollowUps(t *testing.T) {
	x := newInRoomSAS(t, SASOptions{InRoom: true}, inRoomBoth(testUser), true)
	inRoomJoin(t, x.bot, "!other:localhost", true, testUser, sasOwner)
	txn, err := x.botS.StartInRoom(context.Background(), inRoomDM, sasOwner)
	if err != nil {
		t.Fatalf("start in room: %v", err)
	}
	revision := x.botS.Snapshot().Revision
	for _, kind := range []event.Type{event.InRoomVerificationCancel, event.InRoomVerificationReady} {
		for _, ev := range []*event.Event{
			inRoomFollowUp(kind, sasOwner, "!other:localhost", id.EventID(txn), true),
			inRoomFollowUp(kind, sasOwner, inRoomDM, "$another-request", true),
			inRoomFollowUp(kind, "@mallory:localhost", inRoomDM, id.EventID(txn), true),
			inRoomFollowUp(kind, testUser, inRoomDM, id.EventID(txn), true),
			inRoomFollowUp(kind, "@mallory:localhost", inRoomDM, id.EventID(txn), false),
			inRoomFollowUp(kind, sasOwner, inRoomDM, "", true),
		} {
			x.bot.Handlers().Dispatch(context.Background(), ev)
		}
	}
	for _, ev := range sasFollowUps(txn) {
		ev.Sender = sasOwner
		x.bot.Handlers().Dispatch(context.Background(), ev)
	}
	sasReady(x.bot, txn, sasOwner, "OWNERDEVICE", event.VerificationMethodSAS)
	if got := x.botS.Snapshot(); got.State != SASSent || got.Revision != revision {
		t.Fatalf("a foreign follow-up changed the attempt: %+v", got)
	}
	if x.tr.roomSends(testUser) != 1 || x.tr.toSend[testUser].Load() != 0 {
		t.Fatal("the bot answered a foreign follow-up")
	}
	for _, reason := range []string{sasDropWrongRoom, sasDropUnknown, sasDropWrongUser, sasDropOwnEvent, sasDropNoRef, sasDropInRoomTxn} {
		if !bytes.Contains(x.botLogs.Bytes(), []byte(`"reason":"`+reason+`"`)) {
			t.Fatalf("no log line gives the reason %q", reason)
		}
	}
	// The owner's ready, unencrypted as Element sends it, is admitted.
	ready := inRoomFollowUp(event.InRoomVerificationReady, sasOwner, inRoomDM, id.EventID(txn), false)
	ready.Content.Parsed.(*event.VerificationReadyEventContent).FromDevice = x.owner.DeviceID
	x.bot.Handlers().Dispatch(context.Background(), ready)
	if got := inRoomWait(t, x.botS, SASAccepted); got.OtherDevice != x.owner.DeviceID {
		t.Fatalf("the owner's ready was not admitted: %+v", got)
	}
}

// A peer's ready answers only a request this controller posted: on a
// request the owner made, the owner's own ready is dropped.
func TestInRoomSASDropsReadyForIncomingRequest(t *testing.T) {
	x := newInRoomSAS(t, inRoomBoth(sasOwner), SASOptions{InRoom: true}, true)
	x.bot.Handlers().Dispatch(context.Background(), inRoomRequestEvent(sasOwner, testUser, inRoomDM, "$req", time.Now(), true))
	revision := inRoomWait(t, x.botS, SASRequested).Revision
	x.bot.Handlers().Dispatch(context.Background(), inRoomFollowUp(event.InRoomVerificationReady, sasOwner, inRoomDM, "$req", true))
	if got := x.botS.Snapshot(); got.State != SASRequested || got.Revision != revision {
		t.Fatalf("a ready for an incoming request changed it: %+v", got)
	}
	all, _ := x.botS.store.GetAllVerificationTransactions(context.Background())
	if len(all) != 1 || all[0].VerificationState.String() != "requested" {
		t.Fatal("a ready for an incoming request reached the helper")
	}
}

// Cancel and a mismatch go to the room, encrypted, never to-device.
func TestInRoomSASCancellationGoesToTheRoom(t *testing.T) {
	x := newInRoomSAS(t, SASOptions{InRoom: true}, inRoomBoth(testUser), true)
	txn, err := x.botS.StartInRoom(context.Background(), inRoomDM, sasOwner)
	if err != nil {
		t.Fatalf("start in room: %v", err)
	}
	x.tr.deliver(x.owner)
	inRoomWait(t, x.ownerS, SASRequested)
	if err := x.botS.Cancel(context.Background(), txn); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	sent := x.tr.sentBy(testUser)
	if len(sent) != 2 || sent[1].kind != event.InRoomVerificationCancel.Type || !sent[1].encrypted || sent[1].room != inRoomDM {
		t.Fatalf("the cancellation did not go to the room: %+v", sent)
	}
	var cancel event.VerificationCancelEventContent
	if err := json.Unmarshal(sent[1].content, &cancel); err != nil || cancel.RelatesTo == nil || cancel.RelatesTo.EventID != id.EventID(txn) {
		t.Fatal("the cancellation does not reference the request")
	}
	if x.tr.toSend[testUser].Load() != 0 {
		t.Fatal("an in-room cancellation went to-device")
	}
	x.tr.deliver(x.owner)
	if got := inRoomWait(t, x.ownerS, SASCancelled); got.Reason != "rejected" || got.TransactionID != txn {
		t.Fatalf("the owner's snapshot after the bot cancelled = %+v", got)
	}

	// A mismatch from the owner on the next attempt also reaches the bot
	// through the room.
	txn = x.inRoomToShowing(x.bot)
	if err := x.ownerS.Confirm(context.Background(), txn, false); err != nil {
		t.Fatalf("owner mismatch: %v", err)
	}
	x.tr.deliver(x.bot)
	if got := inRoomWait(t, x.botS, SASCancelled); got.Reason != "mismatch" {
		t.Fatalf("snapshot after the owner's mismatch = %+v", got)
	}
}

// StartInRoom refuses before sending anything: a room that is unencrypted
// or not joined, this account, and a failed prerequisite.
func TestInRoomSASStartRefusals(t *testing.T) {
	x := newInRoomSAS(t, SASOptions{InRoom: true}, SASOptions{}, false)
	inRoomJoin(t, x.bot, "!plain:localhost", false, testUser, sasOwner)
	inRoomJoin(t, x.bot, "!invited:localhost", true, sasOwner)
	revision := x.botS.Snapshot().Revision
	for _, tc := range []struct {
		room id.RoomID
		user id.UserID
		want error
	}{
		{"!plain:localhost", sasOwner, ErrSASRoom},
		{"!invited:localhost", sasOwner, ErrSASRoom},
		{"!unknown:localhost", sasOwner, ErrSASRoom},
		{"", sasOwner, ErrSASRoom},
		{inRoomDM, testUser, ErrOwnUser},
		{inRoomDM, sasOwner, ErrNoUserIdentity},
	} {
		if _, err := x.botS.StartInRoom(context.Background(), tc.room, tc.user); !errors.Is(err, tc.want) {
			t.Fatalf("StartInRoom(%s, %s) = %v, want %v", tc.room, tc.user, err, tc.want)
		}
	}
	if x.tr.roomSends(testUser) != 0 || x.tr.toSend[testUser].Load() != 0 || x.botS.Snapshot().Revision != revision {
		t.Fatal("a refused StartInRoom sent something or changed the snapshot")
	}
}

// mautrix v0.31.0's StartInRoomVerification encrypts the request, then
// passes the ciphertext to SendMessageEvent, which encrypts it again in an
// encrypted room, so the room receives a request nobody can read. rihma's
// StartInRoom sends the request itself. When this fails, upstream encrypts
// once; StartInRoom can then use the helper.
func TestUpstreamStartInRoomVerificationEncryptsTwice(t *testing.T) {
	ctx, ms, bot, owner := upstreamPair(t)
	tr := newInRoomTransport(t, ms)
	tr.tokens[bot.client.AccessToken] = bot.client.UserID
	tr.toSend[bot.client.UserID] = new(atomic.Int32)
	bot.client.Crypto = &inRoomCrypto{CryptoHelper: bot.client.Crypto, tr: tr}
	if err := bot.client.StateStore.SetEncryptionEvent(ctx, inRoomDM, &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}); err != nil {
		t.Fatal("room state failed")
	}
	if _, err := bot.helper.StartInRoomVerification(ctx, inRoomDM, owner.client.UserID); err != nil {
		t.Fatalf("start in room: %v", err)
	}
	tr.mu.Lock()
	reenc, encrypt := tr.reenc, tr.encrypt
	tr.mu.Unlock()
	if encrypt == 1 && reenc == 0 {
		t.Fatal("upstream now encrypts the in-room request once; revisit StartInRoom's own send")
	}
	if encrypt != 2 || reenc != 1 {
		t.Fatalf("Encrypt called %d times, %d on ciphertext", encrypt, reenc)
	}
	sent := tr.sentBy(bot.client.UserID)
	if len(sent) != 1 || sent[0].kind != event.EventMessage.Type {
		t.Fatalf("sent %+v", sent)
	}
	// What a reader decrypts is an m.room.message carrying ciphertext, not
	// a verification request.
	var inner event.MessageEventContent
	if err := json.Unmarshal(sent[0].content, &inner); err == nil && inner.MsgType == event.MsgVerificationRequest {
		t.Fatal("the decrypted request is readable")
	}
}

// A peer that cancels while Accept's checks are on the network ends the
// attempt; Accept sends no ready and returns ErrSASStale, or the check's
// error when it fails, without a second cancellation.
func TestInRoomSASPeerCancelsDuringAccept(t *testing.T) {
	for _, ownerIdentity := range []bool{true, false} {
		t.Run(fmt.Sprintf("owner identity %v", ownerIdentity), func(t *testing.T) {
			x := newInRoomSAS(t, inRoomBoth(sasOwner), SASOptions{InRoom: true}, ownerIdentity)
			txn := id.VerificationTransactionID("$req")
			if ownerIdentity {
				var err error
				if txn, err = x.ownerS.StartInRoom(context.Background(), inRoomDM, testUser); err != nil {
					t.Fatalf("owner start: %v", err)
				}
				x.tr.deliver(x.bot)
			} else {
				// Without an identity of its own the owner cannot start; post
				// its request by hand.
				x.bot.Handlers().Dispatch(context.Background(), inRoomRequestEvent(sasOwner, testUser, inRoomDM, "$req", time.Now(), true))
			}
			inRoomWait(t, x.botS, SASRequested)
			entered, release := inRoomBlockKeys(x.h, x.bot)
			result := make(chan error, 1)
			go func() { result <- x.botS.Accept(context.Background(), txn) }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("Accept did not query keys")
			}
			x.bot.Handlers().Dispatch(context.Background(), inRoomFollowUp(event.InRoomVerificationCancel, sasOwner, inRoomDM, id.EventID(txn), true))
			close(release)
			want := ErrSASStale
			if !ownerIdentity {
				want = ErrNoUserIdentity
			}
			if err := <-result; !errors.Is(err, want) {
				t.Fatalf("Accept = %v, want %v", err, want)
			}
			inRoomWait(t, x.botS, SASCancelled)
			if x.tr.roomSends(testUser) != 0 || x.tr.toSend[testUser].Load() != 0 {
				t.Fatal("the bot sent something to a cancelled attempt")
			}
			if all, _ := x.botS.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
				t.Fatal("a cancelled attempt stayed in the helper")
			}
		})
	}
}

// inRoomBlockKeys holds c's key queries until release closes, and reports
// when one arrives.
func inRoomBlockKeys(h *testHS, c *Client) (entered, release chan struct{}) {
	entered, release = make(chan struct{}, 1), make(chan struct{})
	inner := h.ms.Server.Config.Handler
	h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/keys/query") && r.Header.Get("Authorization") == "Bearer "+c.AccessToken {
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
	return entered, release
}
