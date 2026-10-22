package rihma

// Tests for the cross-user verification design in
// docs/cross-user-verification.md. The first group proves that today's
// same-account gate refuses every cross-user, in-room, spoofed and stale
// combination before the upstream helper sees it. The second group pins
// four behaviors of the upstream helper that the cross-user slices must
// work around or document, so that a mautrix upgrade which changes them
// fails here and the workaround can be revisited.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/mockserver"
)

const crossUserPeer = id.UserID("@owner:example.org")

// sasFollowUps are the to-device verification events that carry a
// transaction id and are routed to the active transaction.
func sasFollowUps(txn id.VerificationTransactionID) []*event.Event {
	te := event.ToDeviceVerificationEvent{TransactionID: txn}
	return []*event.Event{
		{Type: event.ToDeviceVerificationCancel, Content: event.Content{Parsed: &event.VerificationCancelEventContent{ToDeviceVerificationEvent: te, Code: event.VerificationCancelCodeUser}}},
		{Type: event.ToDeviceVerificationStart, Content: event.Content{Parsed: &event.VerificationStartEventContent{ToDeviceVerificationEvent: te, FromDevice: "PEER", Method: event.VerificationMethodSAS}}},
		{Type: event.ToDeviceVerificationAccept, Content: event.Content{Parsed: &event.VerificationAcceptEventContent{ToDeviceVerificationEvent: te}}},
		{Type: event.ToDeviceVerificationKey, Content: event.Content{Parsed: &event.VerificationKeyEventContent{ToDeviceVerificationEvent: te}}},
		{Type: event.ToDeviceVerificationMAC, Content: event.Content{Parsed: &event.VerificationMACEventContent{ToDeviceVerificationEvent: te}}},
		{Type: event.ToDeviceVerificationDone, Content: event.Content{Parsed: &event.VerificationDoneEventContent{ToDeviceVerificationEvent: te}}},
	}
}

// A follow-up from another user that names the active transaction must
// not reach the helper. Upstream does not bind follow-ups to the
// transaction's user (see TestUpstreamFollowUpsAreNotBoundToTheirUser),
// so the gate's sender check is the only thing that stops a third party
// cancelling or steering an attempt.
func TestSASGateDropsFollowUpsFromAnotherUser(t *testing.T) {
	c, s, _, stop := sasTestClient(t)
	defer stop()
	sasRequest(c, "active", c.UserID, "OTHER", time.Now().Add(time.Minute))
	sasWait(t, func() bool { return s.Snapshot().State == SASRequested })
	before := s.Snapshot().Revision
	for _, ev := range sasFollowUps("active") {
		ev.Sender = crossUserPeer
		c.Handlers().Dispatch(context.Background(), ev)
	}
	if got := s.Snapshot(); got.State != SASRequested || got.Revision != before {
		t.Fatal("a follow-up from another user changed the attempt")
	}
	all, _ := s.store.GetAllVerificationTransactions(context.Background())
	if len(all) != 1 || all[0].TransactionID != "active" || all[0].VerificationState != verificationhelper.VerificationStateRequested {
		t.Fatal("a follow-up from another user changed the helper transaction")
	}
	// The same cancellation from the account itself still lands.
	cancel := sasFollowUps("active")[0]
	cancel.Sender = c.UserID
	c.Handlers().Dispatch(context.Background(), cancel)
	sasWait(t, func() bool { return s.Snapshot().State == SASCancelled })
}

// A cross-user request is dropped whatever it claims about its device,
// and leaves no helper transaction or timer behind.
func TestSASGateDropsCrossUserRequestsWhateverTheirDevice(t *testing.T) {
	c, s, _, stop := sasTestClient(t)
	defer stop()
	for i, device := range []id.DeviceID{"PEER", c.DeviceID, ""} {
		sasRequest(c, id.VerificationTransactionID("cross-"+string(rune('a'+i))), crossUserPeer, device, time.Now().Add(time.Minute))
	}
	if all, _ := s.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
		t.Fatal("a cross-user request entered the helper")
	}
	if s.Snapshot().State != SASIdle {
		t.Fatal("a cross-user request changed the snapshot")
	}
}

// Requests that are stale, malformed or oversized are dropped before the
// helper; the spec's ten-minute age bound and rihma's one-minute future
// bound both apply.
func TestSASGateDropsStaleAndMalformedRequests(t *testing.T) {
	c, s, _, stop := sasTestClient(t)
	defer stop()
	cases := []struct {
		txn     id.VerificationTransactionID
		device  id.DeviceID
		expires time.Time
	}{
		{"old", "OTHER", time.Now().Add(-time.Second)},                      // sent more than ten minutes ago
		{"future", "OTHER", time.Now().Add(10*time.Minute + 2*time.Minute)}, // sent two minutes from now
		{"", "OTHER", time.Now().Add(time.Minute)},                          // no transaction id
		{id.VerificationTransactionID(string(make([]byte, 257))), "OTHER", time.Now().Add(time.Minute)},
		{"long-device", id.DeviceID(string(make([]byte, 257))), time.Now().Add(time.Minute)},
		{"no-device", "", time.Now().Add(time.Minute)},
	}
	for _, tc := range cases {
		sasRequest(c, tc.txn, c.UserID, tc.device, tc.expires)
	}
	if all, _ := s.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
		t.Fatal("a stale or malformed request entered the helper")
	}
	if s.Snapshot().State != SASIdle {
		t.Fatal("a stale or malformed request changed the snapshot")
	}
}

// inRoomRequest is an m.room.message verification request, as Element
// sends to verify another user in a direct message.
func inRoomRequest(from, to id.UserID, room id.RoomID, eventID id.EventID) *event.Event {
	return &event.Event{
		Type: event.EventMessage, Sender: from, RoomID: room, ID: eventID, Timestamp: time.Now().UnixMilli(),
		Content: event.Content{Parsed: &event.MessageEventContent{MsgType: event.MsgVerificationRequest, Body: "verification request", FromDevice: "PEER", Methods: []event.VerificationMethod{event.VerificationMethodSAS}, To: to}},
	}
}

func inRoomCancel(from id.UserID, room id.RoomID, eventID, request id.EventID) *event.Event {
	content := &event.VerificationCancelEventContent{Code: event.VerificationCancelCodeUser}
	content.SetRelatesTo(&event.RelatesTo{Type: event.RelReference, EventID: request})
	return &event.Event{Type: event.InRoomVerificationCancel, Sender: from, RoomID: room, ID: eventID, Content: event.Content{Parsed: content}}
}

// The gate registers only to-device handlers, so an in-room request, even
// one from the account itself, never reaches the helper.
func TestSASGateIgnoresInRoomVerification(t *testing.T) {
	c, s, _, stop := sasTestClient(t)
	defer stop()
	for _, from := range []id.UserID{crossUserPeer, c.UserID} {
		c.Handlers().Dispatch(context.Background(), inRoomRequest(from, c.UserID, "!dm:example.org", id.EventID("$req-"+from.Localpart())))
		c.Handlers().Dispatch(context.Background(), inRoomCancel(from, "!dm:example.org", "$cancel", id.EventID("$req-"+from.Localpart())))
	}
	if all, _ := s.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
		t.Fatal("an in-room request entered the helper")
	}
	if s.Snapshot().State != SASIdle {
		t.Fatal("an in-room request changed the snapshot")
	}
}

// upstreamPeer is one user's bare mautrix client with a verification
// helper on the mock server, for characterizing the helper without
// rihma's gate.
type upstreamPeer struct {
	client    *mautrix.Client
	machine   *crypto.OlmMachine
	helper    *verificationhelper.VerificationHelper
	callbacks *sasCallbacks
}

func newUpstreamPeer(t *testing.T, ctx context.Context, ms *mockserver.MockServer, user id.UserID, device id.DeviceID) *upstreamPeer {
	t.Helper()
	client, _ := ms.Login(t, ctx, user, device)
	machine := client.Crypto.(*cryptohelper.CryptoHelper).Machine()
	quietLog := zerolog.Nop()
	machine.Log = &quietLog
	callbacks := &sasCallbacks{events: make(chan sasEvent, 32), overflow: make(chan struct{}, 1)}
	helper := verificationhelper.NewVerificationHelper(client, machine, verificationhelper.NewInMemoryVerificationStore(), callbacks, false, false, true)
	if err := helper.Init(ctx); err != nil {
		t.Fatal("helper init failed")
	}
	return &upstreamPeer{client: client, machine: machine, helper: helper, callbacks: callbacks}
}

// drain returns every callback the helper has posted so far.
func (p *upstreamPeer) drain() []sasEvent {
	var out []sasEvent
	for {
		select {
		case ev := <-p.callbacks.events:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func upstreamPair(t *testing.T) (context.Context, *mockserver.MockServer, *upstreamPeer, *upstreamPeer) {
	t.Helper()
	return upstreamPairWithDevices(t, "BOTDEVICE", "OWNERDEVICE")
}

func upstreamPairWithDevices(t *testing.T, botDevice, ownerDevice id.DeviceID) (context.Context, *mockserver.MockServer, *upstreamPeer, *upstreamPeer) {
	t.Helper()
	ctx := zerolog.Nop().WithContext(context.Background())
	ms := mockserver.Create(t)
	bot := newUpstreamPeer(t, ctx, ms, "@bot:example.org", botDevice)
	owner := newUpstreamPeer(t, ctx, ms, crossUserPeer, ownerDevice)
	for _, p := range []*upstreamPeer{bot, owner} {
		for _, q := range []*upstreamPeer{bot, owner} {
			if err := p.machine.CryptoStore.PutDevice(ctx, q.client.UserID, q.machine.OwnIdentity()); err != nil {
				t.Fatal("fixture devices failed")
			}
		}
	}
	return ctx, ms, bot, owner
}

// Upstream routes a to-device follow-up to its transaction by id alone:
// a third user who learns the id can cancel the attempt. rihma's gate
// must bind every follow-up's sender to the transaction's user.
func TestUpstreamFollowUpsAreNotBoundToTheirUser(t *testing.T) {
	ctx, _, bot, owner := upstreamPair(t)
	txn, err := bot.helper.StartVerification(ctx, owner.client.UserID)
	if err != nil || txn == "" {
		t.Fatal("start failed")
	}
	cancel := sasFollowUps(txn)[0]
	cancel.Sender = "@mallory:example.org"
	bot.client.Syncer.(*mautrix.DefaultSyncer).Dispatch(ctx, cancel)
	cancelled := false
	for _, ev := range bot.drain() {
		cancelled = cancelled || (ev.txn == txn && ev.cancelled != "")
	}
	if !cancelled {
		t.Fatal("upstream now binds follow-ups to their user; revisit the gate's sender binding")
	}
}

// Device ids are scoped to their user, so another user may publish a
// device whose id equals this device's. Upstream compares only the id:
// it ignores such a peer's request and leaves that device out of its own
// requests. rihma's gate must exclude only this account's own device,
// and the limitation stays until upstream compares the user too.
func TestUpstreamIgnoresPeerDeviceSharingTheLocalDeviceID(t *testing.T) {
	ctx, ms, bot, owner := upstreamPairWithDevices(t, "SHARED", "SHARED")
	req := &event.Event{Type: event.ToDeviceVerificationRequest, Sender: owner.client.UserID, Content: event.Content{Parsed: &event.VerificationRequestEventContent{
		ToDeviceVerificationEvent: event.ToDeviceVerificationEvent{TransactionID: "shared-id"},
		FromDevice:                "SHARED", Methods: []event.VerificationMethod{event.VerificationMethodSAS}, Timestamp: jsontime.UM(time.Now()),
	}}}
	bot.client.Syncer.(*mautrix.DefaultSyncer).Dispatch(ctx, req)
	for _, ev := range bot.drain() {
		if ev.requested {
			t.Fatal("upstream now admits a peer device sharing the local id; revisit the documented limitation")
		}
	}
	if _, err := bot.helper.StartVerification(ctx, owner.client.UserID); err != nil {
		t.Fatal("start failed")
	}
	if len(ms.DeviceInbox[owner.client.UserID]["SHARED"]) != 0 {
		t.Fatal("upstream now sends to a peer device sharing the local id; revisit the documented limitation")
	}
}

// Upstream looks an in-room follow-up up by the follow-up's own event id
// rather than by the request it references in m.relates_to, so an
// in-room transaction never advances. The in-room slice must route by
// the reference itself, or wait for an upstream fix.
func TestUpstreamInRoomFollowUpsMissTheirTransaction(t *testing.T) {
	ctx, _, bot, owner := upstreamPair(t)
	room := id.RoomID("!dm:example.org")
	syncer := bot.client.Syncer.(*mautrix.DefaultSyncer)
	syncer.Dispatch(ctx, inRoomRequest(owner.client.UserID, bot.client.UserID, room, "$request"))
	requested := false
	for _, ev := range bot.drain() {
		requested = requested || (ev.requested && ev.txn == "$request" && ev.from == owner.client.UserID)
	}
	if !requested {
		t.Fatal("upstream did not admit the in-room request")
	}
	syncer.Dispatch(ctx, inRoomCancel(owner.client.UserID, room, "$cancel", "$request"))
	for _, ev := range bot.drain() {
		if ev.cancelled != "" {
			t.Fatal("upstream now routes in-room follow-ups by reference; revisit the in-room slice's routing")
		}
	}
}

// signedByUSK reports whether p's crypto store holds a signature by p's
// user-signing key on q's master key, which is what SAS with another
// user is meant to leave behind. IsUserTrusted would also demand that
// p's own master key be trusted, which these fixtures do not set up.
func signedByUSK(t *testing.T, ctx context.Context, p, q *upstreamPeer) bool {
	t.Helper()
	own, err := p.machine.GetOwnCrossSigningPublicKeys(ctx)
	if err != nil || own == nil {
		t.Fatal("own cross-signing keys missing")
	}
	theirs, err := p.machine.GetCrossSigningPublicKeys(ctx, q.client.UserID)
	if err != nil || theirs == nil {
		t.Fatal("peer cross-signing keys missing")
	}
	signed, err := p.machine.CryptoStore.IsKeySignedBy(ctx, q.client.UserID, theirs.MasterKey, p.client.UserID, own.UserSigningKey)
	if err != nil {
		t.Fatal("signature lookup failed")
	}
	return signed
}

// sasToShowing runs an outgoing to-device SAS from bot to owner up to
// both sides showing the same emoji, and returns the transaction id.
func sasToShowing(t *testing.T, ctx context.Context, ms *mockserver.MockServer, bot, owner *upstreamPeer) id.VerificationTransactionID {
	t.Helper()
	deliver := func(p *upstreamPeer) { ms.DispatchToDevice(t, ctx, p.client) }
	txn, err := bot.helper.StartVerification(ctx, owner.client.UserID)
	if err != nil {
		t.Fatal("start failed")
	}
	deliver(owner)
	if err := owner.helper.AcceptVerification(ctx, txn); err != nil {
		t.Fatal("accept failed")
	}
	deliver(bot) // ready
	if err := bot.helper.StartSAS(ctx, txn); err != nil {
		t.Fatal("start SAS failed")
	}
	deliver(owner) // start; owner sends accept
	deliver(bot)   // accept; bot sends key
	deliver(owner) // key; owner sends key and shows SAS
	deliver(bot)   // key; bot shows SAS
	var botEmoji, ownerEmoji []SASEmoji
	for _, ev := range bot.drain() {
		if ev.emoji != nil {
			botEmoji = ev.emoji
		}
	}
	for _, ev := range owner.drain() {
		if ev.emoji != nil {
			ownerEmoji = ev.emoji
		}
	}
	if len(botEmoji) != 7 || len(ownerEmoji) != 7 {
		t.Fatal("SAS not shown on both sides")
	}
	for i := range botEmoji {
		if botEmoji[i] != ownerEmoji[i] {
			t.Fatal("SAS differs between the sides")
		}
	}
	return txn
}

// Cross-user to-device SAS completes through the upstream helper, and
// the side whose MAC check runs last signs the other user's master key
// with its user-signing key. But the side that confirms after already
// holding the peer's MAC fails: ConfirmSAS passes its own master key
// where the peer's is expected. The completion slice must make the
// local MAC check run after the local confirmation, and must record the
// signature through rihma's identity records, which upstream bypasses.
func TestUpstreamCrossUserSASSignsOnlyWhenLocalConfirmsFirst(t *testing.T) {
	ctx, ms, bot, owner := upstreamPair(t)
	for _, p := range []*upstreamPeer{bot, owner} {
		if _, _, err := p.machine.GenerateAndUploadCrossSigningKeys(ctx, nil, ""); err != nil {
			t.Fatal("cross-signing fixture failed")
		}
	}
	txn := sasToShowing(t, ctx, ms, bot, owner)
	// The owner confirms first, and the bot receives that MAC before the
	// person at the bot's terminal confirms.
	if err := owner.helper.ConfirmSAS(ctx, txn); err != nil {
		t.Fatal("first confirmation failed")
	}
	ms.DispatchToDevice(t, ctx, bot.client)
	err := bot.helper.ConfirmSAS(ctx, txn)
	if err == nil || !strings.Contains(err.Error(), "failed to trust keys") {
		t.Fatal("upstream now completes when the local side confirms second; revisit the completion slice's MAC ordering")
	}
	if signedByUSK(t, ctx, bot, owner) {
		t.Fatal("bot signed the owner despite the failed confirmation")
	}
	// The bot's MAC was sent before its trust step failed, so the owner,
	// which confirmed first, checks it last and signs the bot.
	ms.DispatchToDevice(t, ctx, owner.client)
	if !signedByUSK(t, ctx, owner, bot) {
		t.Fatal("the side that confirmed first did not sign the other user's master key")
	}
}

// The order rihma's completion slice will enforce: the local side
// confirms before it checks the peer's MAC, and so signs the peer.
func TestUpstreamCrossUserSASSignsPeerWhenItsMACArrivesAfterConfirm(t *testing.T) {
	ctx, ms, bot, owner := upstreamPair(t)
	for _, p := range []*upstreamPeer{bot, owner} {
		if _, _, err := p.machine.GenerateAndUploadCrossSigningKeys(ctx, nil, ""); err != nil {
			t.Fatal("cross-signing fixture failed")
		}
	}
	txn := sasToShowing(t, ctx, ms, bot, owner)
	if err := owner.helper.ConfirmSAS(ctx, txn); err != nil {
		t.Fatal("owner confirmation failed")
	}
	// Hold the owner's MAC, as the completion slice's gate will, until
	// the bot has confirmed.
	held := ms.DeviceInbox[bot.client.UserID][bot.client.DeviceID]
	ms.DeviceInbox[bot.client.UserID][bot.client.DeviceID] = nil
	if err := bot.helper.ConfirmSAS(ctx, txn); err != nil {
		t.Fatal("bot confirmation failed")
	}
	ms.DeviceInbox[bot.client.UserID][bot.client.DeviceID] = append(held, ms.DeviceInbox[bot.client.UserID][bot.client.DeviceID]...)
	ms.DispatchToDevice(t, ctx, bot.client)
	ms.DispatchToDevice(t, ctx, owner.client)
	ms.DispatchToDevice(t, ctx, bot.client)
	for _, pair := range [][2]*upstreamPeer{{bot, owner}, {owner, bot}} {
		if !signedByUSK(t, ctx, pair[0], pair[1]) {
			t.Fatal("a side did not sign the other user's master key")
		}
	}
	botDone := false
	for _, ev := range bot.drain() {
		botDone = botDone || ev.done
	}
	if !botDone {
		t.Fatal("the bot did not reach done")
	}
}
