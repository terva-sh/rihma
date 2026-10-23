package rihma

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/jsontime"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	ErrSASUnavailable = errors.New("rihma: verification is not running")
	ErrSASStale       = errors.New("rihma: verification transaction or state changed")
	ErrSASOperation   = errors.New("rihma: verification operation failed")
	ErrSASLimit       = errors.New("rihma: verification attempt limit reached")
	// ErrPeerDeviceIDConflict is returned by StartUser when the user
	// publishes a device whose id equals this device's. mautrix v0.31.0
	// compares devices by id alone and would leave that device out of the
	// request, so the person using it would never see it.
	ErrPeerDeviceIDConflict = errors.New("rihma: the user has a device with this device's id")
	// ErrInvalidSASPeer is returned by EnableSASWith when an entry of
	// SASOptions.Peers is not a Matrix user id.
	ErrInvalidSASPeer = errors.New("rihma: a SAS peer is not a valid Matrix user id")
	// ErrSASRoom is returned by StartInRoom when the room is not an
	// encrypted room this account has joined. Nothing is sent.
	ErrSASRoom = errors.New("rihma: in-room verification needs an encrypted room this account has joined")
)

// SASOptions widens what an SASController admits. The zero value is the
// same-account, to-device controller EnableSAS returns.
type SASOptions struct {
	// Peers are other users whose to-device verification requests are
	// admitted, for example a bot's owner. A request from anyone else who
	// is not this account is dropped without a reply. Order and duplicates
	// do not matter.
	Peers []id.UserID
	// InRoom also admits in-room requests from Peers, in an encrypted room
	// this account has joined, which is how Element verifies another user
	// from their DM, and lets StartInRoom post one.
	InRoom bool
}

// sasPeerSet checks opts and returns its peers as a set. It does not
// touch the network.
func (c *Client) sasPeerSet(opts SASOptions) (map[id.UserID]struct{}, error) {
	peers := make(map[id.UserID]struct{}, len(opts.Peers))
	for _, user := range opts.Peers {
		if user == c.UserID {
			return nil, ErrOwnUser
		}
		if _, _, err := user.Parse(); err != nil || len(user) > 255 {
			return nil, ErrInvalidSASPeer
		}
		peers[user] = struct{}{}
	}
	return peers, nil
}

type SASState string

const (
	SASIdle      SASState = "idle"
	SASSent      SASState = "sent"
	SASRequested SASState = "requested"
	SASAccepted  SASState = "accepted"
	SASShowing   SASState = "showing_sas"
	SASConfirmed SASState = "confirmed"
	SASDone      SASState = "done"
	SASCancelled SASState = "cancelled"
	SASFailed    SASState = "failed"
	SASStopped   SASState = "stopped"
)

// SASSnapshot is a safe value copy. It contains no keys or remote reason text.
// Transaction IDs identify attempts, and must accompany every user command.
type SASSnapshot struct {
	Revision      uint64
	State         SASState
	TransactionID id.VerificationTransactionID
	// OtherUser is the user being verified: this account for a
	// same-account attempt, the user named in StartUser, or the listed
	// peer whose request was admitted.
	OtherUser   id.UserID
	OtherDevice id.DeviceID
	// Room is the room an in-room attempt runs in. It is empty for
	// to-device attempts, which are the only kind today.
	Room  id.RoomID
	Emoji []SASEmoji
	// MasterKey is set on done for another user: the master key their MAC
	// named, which this account has signed and recorded.
	MasterKey id.Ed25519
	// Reason is a fixed local value: cancelled, mismatch, timeout, rejected,
	// operation_failed, overflow, unsigned or identity_changed. Never render
	// a server-supplied reason.
	Reason string
}

type sasCommand struct {
	ctx    context.Context
	txn    id.VerificationTransactionID
	action string
	match  bool
	user   id.UserID
	room   id.RoomID
	result chan sasResult
}

type sasResult struct {
	txn     id.VerificationTransactionID
	err     error
	expires time.Time
}

// SASController handles emoji verification through Client.Sync: to-device
// with this account's other devices, outgoing with another user, and
// incoming from the users listed in SASOptions.Peers; and, with
// SASOptions.InRoom, in a room with another user. It never starts sync. One controller lasts one Sync;
// attempts can repeat during that Sync. It does not persist pending attempts.
// Call EnableSAS or EnableSASWith before the client's first Sync. Stop Sync before closing stores.
type SASController struct {
	client    *Client
	helper    *verificationhelper.VerificationHelper
	store     *sasStore
	gate      *sasEventGate
	callbacks *sasCallbacks
	mu        sync.Mutex
	snapshot  SASSnapshot
	// peer, room and master fill the snapshot's OtherUser, Room and
	// MasterKey.
	peer   id.UserID
	room   id.RoomID
	master id.Ed25519
	// AwaitSAS follows its first observed transaction. Retain that value even
	// when later requests replace the public coalescing snapshot.
	awaitOne   bool
	awaitState SASSnapshot
	changed    chan struct{}
	commands   chan sasCommand
	done       chan struct{}
	runCtx     context.Context
	cancel     context.CancelFunc
	started    bool
	stopped    bool
	stopOnce   sync.Once
}

// EnableSAS opts into verification without making network requests.
// It returns the same controller on repeated calls, and must precede first Sync.
// Bot clients that do not opt in retain their existing behavior.
// It is EnableSASWith(SASOptions{}).
func (c *Client) EnableSAS() (*SASController, error) {
	return c.EnableSASWith(SASOptions{})
}

// EnableSASWith is EnableSAS with options. A bot that should accept its
// owner's verification request lists the owner in Peers; Accept then
// checks the prerequisites StartUser checks before replying. A second
// call returns the same controller if the options are equal, and
// ErrSASUnavailable if they differ, so EnableSAS, AwaitSAS and VerifyUser
// refuse a client whose controller lists peers. A peer equal to this
// account returns ErrOwnUser, and a malformed one ErrInvalidSASPeer.
// InRoom adds in-room verification: requests from Peers in an encrypted
// room this account has joined, and StartInRoom.
func (c *Client) EnableSASWith(opts SASOptions) (*SASController, error) {
	peers, err := c.sasPeerSet(opts)
	if err != nil {
		return nil, err
	}
	c.connectOnce.Lock()
	defer c.connectOnce.Unlock()
	if c.sas != nil {
		if !maps.Equal(c.sas.gate.peers, peers) || c.sas.gate.inRoom != opts.InRoom {
			return nil, ErrSASUnavailable
		}
		return c.sas, nil
	}
	if c.syncStarted {
		return nil, ErrSASUnavailable
	}
	s := newSASController(c)
	s.gate.peers, s.gate.inRoom = peers, opts.InRoom
	c.sas = s
	if c.connected {
		if err := s.init(context.Background()); err != nil {
			c.sas = nil
			return nil, err
		}
	}
	return s, nil
}

func newSASController(c *Client) *SASController {
	return &SASController{client: c, store: newSASStore(), gate: &sasEventGate{recent: make(map[id.VerificationTransactionID]time.Time)}, callbacks: &sasCallbacks{events: make(chan sasEvent, 32), overflow: make(chan struct{}, 1)}, snapshot: SASSnapshot{Revision: 1, State: SASIdle}, changed: make(chan struct{}, 1), commands: make(chan sasCommand, 16), done: make(chan struct{})}
}

// init runs under connectOnce before first Sync. Only Init reads Syncer;
// registration is gated while the helper keeps the original client for requests.
func (s *SASController) init(ctx context.Context) error { return s.initWithStore(ctx, s.store) }
func (s *SASController) initWithStore(ctx context.Context, store verificationhelper.VerificationStore) error {
	if s.helper != nil {
		return nil
	}
	original := s.client.Client.Syncer
	gateLog := s.client.opts.Logger.With().Str("component", "sas_gate").Logger()
	proxy := &sasHandlerSyncer{DefaultSyncer: s.client.Handlers(), underlying: s.client.Handlers(), gate: s.gate, user: s.client.UserID, device: s.client.DeviceID, roomUsable: s.client.sasRoomUsable, log: &gateLog, staged: true}
	s.client.Client.Syncer = proxy
	defer func() { s.client.Client.Syncer = original }()
	s.gate.store = s.store
	s.gate.callbacks = s.callbacks
	helper := verificationhelper.NewVerificationHelper(s.client.Client, s.client.OlmMachine(), store, s.callbacks, false, false, true)
	// Init may have registered some handlers before failing. Buffer registration
	// until success so retries neither reuse a failed helper nor duplicate handlers.
	if err := helper.Init(ctx); err != nil {
		return err
	}
	proxy.commit()
	s.helper = helper
	return nil
}

// Snapshot returns an independent value, including an independent emoji slice.
func (s *SASController) Snapshot() SASSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.snapshot
	out.Emoji = append([]SASEmoji(nil), out.Emoji...)
	return out
}

// Changed is a coalescing wakeup, not an event log. Read Snapshot after waking.
// It closes after the controller has quiesced. Multiple views should have one
// adapter fan out snapshots; this channel has a single consumer.
func (s *SASController) Changed() <-chan struct{} { return s.changed }

func (s *SASController) prepareAwait() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.stopped || s.awaitOne {
		return ErrSASUnavailable
	}
	s.awaitOne = true
	return nil
}

func (s *SASController) awaitSnapshot() SASSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.snapshot
	if s.awaitState.TransactionID != "" {
		out = s.awaitState
	}
	out.Emoji = append([]SASEmoji(nil), out.Emoji...)
	return out
}

// begin names the user and room of a new attempt and clears the last
// one's key.
func (s *SASController) begin(user id.UserID, room id.RoomID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peer, s.room, s.master = user, room, ""
}

func (s *SASController) set(state SASState, txn id.VerificationTransactionID, device id.DeviceID, emoji []SASEmoji, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var peer id.UserID
	var room id.RoomID
	if txn != "" {
		peer, room = s.peer, s.room
	}
	s.snapshot = SASSnapshot{Revision: s.snapshot.Revision + 1, State: state, TransactionID: txn, OtherUser: peer, OtherDevice: device, Room: room, Emoji: append([]SASEmoji(nil), emoji...), MasterKey: s.master, Reason: reason}
	if s.awaitOne && txn != "" && (s.awaitState.TransactionID == "" || s.awaitState.TransactionID == txn) {
		s.awaitState = s.snapshot
	}
	select {
	case s.changed <- struct{}{}:
	default:
	}
}
func (s *SASController) start(ctx context.Context) error {
	s.mu.Lock()
	if s.started || s.stopped {
		s.mu.Unlock()
		return ErrSASUnavailable
	}
	s.started = true
	s.runCtx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()
	s.gate.mu.Lock()
	s.gate.active = true
	s.gate.mu.Unlock()
	go s.run()
	return nil
}
func (s *SASController) stop() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.stopped = true
		started := s.started
		cancel := s.cancel
		s.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		// No new event can reach the helper; wait for already dispatched handlers.
		s.gate.mu.Lock()
		s.gate.active = false
		s.gate.mu.Unlock()
		s.gate.dropHeld()
		if started {
			<-s.done
		}
		// Timers may be asleep in mautrix. Revoke their in-memory transactions, then
		// acquire the helper lock via Dismiss to join any expiration already in flight.
		// Later timers get ErrUnknownVerificationTransaction and do no network I/O.
		s.store.close()
		if s.helper != nil {
			_ = s.helper.DismissVerification(context.Background(), "")
		}
		s.set(SASStopped, "", "", nil, "")
		close(s.changed)
	})
}

// Accept answers a requested attempt. For a request from another user it
// first checks, as StartUser does, that this device holds the account's
// cross-signing keys and the server still publishes them
// (ErrNoCrossSigningKeys) and that the user publishes a master key
// (ErrNoUserIdentity), refreshing their devices. A failed check sends the
// user a cancellation, ends the attempt cancelled, and returns its error.
func (s *SASController) Accept(ctx context.Context, txn id.VerificationTransactionID) error {
	return s.command(ctx, txn, "accept", false)
}
func (s *SASController) Confirm(ctx context.Context, txn id.VerificationTransactionID, match bool) error {
	return s.command(ctx, txn, "confirm", match)
}
func (s *SASController) Cancel(ctx context.Context, txn id.VerificationTransactionID) error {
	return s.command(ctx, txn, "cancel", false)
}

// Start requests SAS verification from the other devices of this account.
// The first eligible device to accept becomes the peer. It requires an active
// Sync, permits only one active attempt, and shares the controller attempt limit.
// Cancellation may return after a request was sent; inspect Snapshot for its state.
func (s *SASController) Start(ctx context.Context) (id.VerificationTransactionID, error) {
	result := s.submit(ctx, "", "start", false, s.client.UserID, "")
	return result.txn, result.err
}

// StartUser asks every device user publishes, over to-device messages, to
// verify this account with emoji. Naming the user is the consent. Before
// sending anything it checks that this device holds the account's
// cross-signing keys and the server still publishes them
// (ErrNoCrossSigningKeys), that user publishes a master key
// (ErrNoUserIdentity), refreshing their devices, and that none of their
// devices shares this device's id (ErrPeerDeviceIDConflict). A failed check
// sends nothing and leaves the snapshot unchanged. Otherwise it behaves as
// Start. When both sides confirm, the controller signs user's master key
// with this account's user-signing key, records it as SignUserIdentity
// does, and reaches done with Snapshot().MasterKey set.
func (s *SASController) StartUser(ctx context.Context, user id.UserID) (id.VerificationTransactionID, error) {
	if user == s.client.UserID {
		return "", ErrOwnUser
	}
	if user == "" {
		return "", ErrNoUserIdentity
	}
	result := s.submit(ctx, "", "start", false, user, "")
	return result.txn, result.err
}

// StartInRoom asks user to verify this account with emoji in room, which
// must be an encrypted room this account has joined (ErrSASRoom), such as
// their DM. It needs a controller enabled with SASOptions.InRoom
// (ErrSASUnavailable). It makes StartUser's checks except
// ErrPeerDeviceIDConflict, which does not apply to a request posted in a
// room, and a failed check sends nothing. The transaction id is the
// request event's id, and follow-ups must be encrypted events in room from
// user that reference it. Completion is as for StartUser.
func (s *SASController) StartInRoom(ctx context.Context, room id.RoomID, user id.UserID) (id.VerificationTransactionID, error) {
	if user == s.client.UserID {
		return "", ErrOwnUser
	}
	if user == "" {
		return "", ErrNoUserIdentity
	}
	if !s.gate.inRoom {
		return "", ErrSASUnavailable
	}
	if room == "" {
		return "", ErrSASRoom
	}
	result := s.submit(ctx, "", "start", false, user, room)
	return result.txn, result.err
}

func (s *SASController) command(ctx context.Context, txn id.VerificationTransactionID, action string, match bool) error {
	return s.submit(ctx, txn, action, match, "", "").err
}
func (s *SASController) submit(ctx context.Context, txn id.VerificationTransactionID, action string, match bool, user id.UserID, room id.RoomID) sasResult {
	if err := ctx.Err(); err != nil {
		return sasResult{err: err}
	}
	if txn == "" && action != "start" {
		return sasResult{err: ErrSASStale}
	}
	s.mu.Lock()
	running := s.started && !s.stopped
	runCtx := s.runCtx
	s.mu.Unlock()
	if !running {
		return sasResult{err: ErrSASUnavailable}
	}
	cmd := sasCommand{ctx: ctx, txn: txn, action: action, match: match, user: user, room: room, result: make(chan sasResult, 1)}
	select {
	case s.commands <- cmd:
	case <-ctx.Done():
		return sasResult{err: ctx.Err()}
	case <-runCtx.Done():
		return sasResult{err: ErrSASUnavailable}
	}
	select {
	case result := <-cmd.result:
		return result
	case <-ctx.Done():
		return sasResult{err: ctx.Err()}
	case <-runCtx.Done():
		return sasResult{err: ErrSASUnavailable}
	}
}
func sasActive(state SASState) bool {
	return state == SASSent || state == SASRequested || state == SASAccepted || state == SASShowing || state == SASConfirmed
}
func (s *SASController) run() {
	defer close(s.done)
	// Upstream expiry sends to TheirDeviceID even before a peer is selected.
	// Own outgoing expiry so pending requests cancel all recipients and terminate
	// locally even if a homeserver rejects that upstream empty-device send.
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	var expiry <-chan time.Time
	var expiryTxn id.VerificationTransactionID
	for {
		select {
		case <-s.runCtx.Done():
			return
		case <-expiry:
			expiry = nil
			s.handle(sasEvent{txn: expiryTxn, expired: true})
		case <-s.callbacks.overflow:
			current := s.Snapshot()
			all, _ := s.store.GetAllVerificationTransactions(s.runCtx)
			for _, txn := range all {
				_ = s.helper.DismissVerification(s.runCtx, txn.TransactionID)
			}
			for len(s.callbacks.events) > 0 {
				<-s.callbacks.events
			}
			s.gate.dropHeld()
			s.set(SASFailed, current.TransactionID, current.OtherDevice, nil, "overflow")
		case ev := <-s.callbacks.events:
			s.handle(ev)
		case cmd := <-s.commands:
			if cmd.action == "start" {
				result := s.executeStart(cmd.ctx, cmd.user, cmd.room)
				if result.err == nil {
					timer.Reset(time.Until(result.expires))
					expiry = timer.C
					expiryTxn = result.txn
				}
				cmd.result <- result
			} else {
				cmd.result <- sasResult{err: s.execute(cmd)}
			}
		}
		if expiry != nil && !sasActive(s.Snapshot().State) {
			timer.Stop()
			expiry = nil
		}
	}
}
func (s *SASController) handle(ev sasEvent) {
	current := s.Snapshot()
	if ev.requested {
		own := ev.from == s.client.UserID
		if !s.gate.admitsRequestFrom(s.client.UserID, ev.from) || (own && ev.fromDevice == s.client.DeviceID) || sasActive(current.State) {
			_ = s.helper.DismissVerification(s.runCtx, ev.txn)
			return
		}
		// Ignore a request whose expiry/cancellation raced its callback delivery.
		txn, err := s.store.GetVerificationTransaction(s.runCtx, ev.txn)
		if err != nil {
			// A cancelled/expired request may have been removed before its queued
			// request callback is consumed. The one-attempt bot wrapper must still
			// observe that first cancellation rather than wait for another request.
			s.mu.Lock()
			awaitOne := s.awaitOne
			s.mu.Unlock()
			if awaitOne {
				s.set(SASCancelled, ev.txn, ev.fromDevice, nil, "cancelled")
			}
			return
		}
		s.begin(ev.from, txn.RoomID)
		s.set(SASRequested, ev.txn, ev.fromDevice, nil, "")
		return
	}
	if ev.txn != current.TransactionID || !sasActive(current.State) {
		return
	}
	switch {
	case ev.expired:
		ctx := zerolog.Nop().WithContext(s.runCtx)
		s.gate.dropHeld()
		_ = s.helper.CancelVerification(ctx, ev.txn, event.VerificationCancelCodeTimeout, "Verification timed out")
		_ = s.helper.DismissVerification(ctx, ev.txn)
		s.set(SASCancelled, ev.txn, current.OtherDevice, nil, "timeout")
	case ev.extraMAC:
		ctx := zerolog.Nop().WithContext(s.runCtx)
		s.gate.dropHeld()
		_ = s.helper.CancelVerification(ctx, ev.txn, event.VerificationCancelCodeUnexpectedMessage, "Unexpected second MAC")
		_ = s.helper.DismissVerification(ctx, ev.txn)
		s.set(SASCancelled, ev.txn, current.OtherDevice, nil, "cancelled")
	case ev.ready:
		if current.State == SASSent {
			s.startReady(ev)
		}
	case ev.emoji != nil:
		if current.State == SASAccepted {
			s.set(SASShowing, ev.txn, current.OtherDevice, ev.emoji, "")
		}
	case ev.cancelled != "":
		s.gate.dropHeld()
		_ = s.helper.DismissVerification(s.runCtx, ev.txn)
		s.set(SASCancelled, ev.txn, current.OtherDevice, nil, safeSASReason(ev.cancelled))
	case ev.done:
		s.complete(ev.txn, current)
	}
}

// complete finishes a done attempt. For another user, the helper has
// already signed the master key their MAC named, bypassing rihma's identity
// records, so SignUserIdentity records it (without a second upload) and
// refuses if the server now publishes another key. Device trust the helper
// stored stays either way; a published signature cannot be taken back.
func (s *SASController) complete(txn id.VerificationTransactionID, current SASSnapshot) {
	s.mu.Lock()
	peer := s.peer
	s.mu.Unlock()
	if peer == s.client.UserID {
		s.set(SASDone, txn, current.OtherDevice, nil, "")
		return
	}
	key := s.gate.macMasterKey(txn)
	if key == "" {
		s.set(SASFailed, txn, current.OtherDevice, nil, "unsigned")
		return
	}
	err := s.client.SignUserIdentity(zerolog.Nop().WithContext(s.runCtx), peer, key)
	switch {
	case errors.Is(err, ErrMasterKeyMismatch):
		s.set(SASFailed, txn, current.OtherDevice, nil, "identity_changed")
	case err != nil:
		s.set(SASFailed, txn, current.OtherDevice, nil, "operation_failed")
	default:
		s.mu.Lock()
		s.master = key
		s.mu.Unlock()
		s.set(SASDone, txn, current.OtherDevice, nil, "")
	}
}

// checkPeer runs the prerequisites for verifying another user, before
// StartUser sends a request and before Accept answers one. It makes network
// requests, so it runs before the gate is locked.
func (s *SASController) checkPeer(ctx context.Context, user id.UserID) error {
	if _, err := s.client.OwnMasterKey(ctx); errors.Is(err, ErrMasterKeyMismatch) {
		return fmt.Errorf("%w: the server publishes another identity", ErrNoCrossSigningKeys)
	} else if err != nil {
		return err
	}
	_, err := s.client.UserIdentity(ctx, user)
	return err
}

// checkIncomingPeer runs StartUser's prerequisites before Accept replies
// to another user's request. ErrPeerDeviceIDConflict does not apply: the
// request came from a device the helper accepts. Nothing has been sent to
// the peer yet; a failed check cancels the attempt, so the peer's client
// is told at once, and returns the check's error. A caller that gave up
// during the check leaves the request pending.
func (s *SASController) checkIncomingPeer(ctx context.Context, cmd sasCommand, current SASSnapshot) error {
	err := s.checkPeer(ctx, current.OtherUser)
	if cmd.ctx.Err() != nil {
		return cmd.ctx.Err()
	}
	if s.runCtx.Err() != nil {
		return ErrSASUnavailable
	}
	if err == nil {
		// The peer may have cancelled, or the request expired, during the
		// check; that callback then reports it.
		if _, err := s.store.GetVerificationTransaction(ctx, cmd.txn); err != nil {
			return ErrSASStale
		}
		return nil
	}
	_ = s.helper.CancelVerification(ctx, cmd.txn, event.VerificationCancelCodeUser, "Verification prerequisites are not met")
	_ = s.helper.DismissVerification(ctx, cmd.txn)
	s.set(SASCancelled, cmd.txn, current.OtherDevice, nil, "cancelled")
	return err
}

func (s *SASController) executeStart(caller context.Context, user id.UserID, room id.RoomID) sasResult {
	ctx, cancel := context.WithCancel(zerolog.Nop().WithContext(caller))
	defer cancel()
	stop := context.AfterFunc(s.runCtx, cancel)
	defer stop()
	cross := user != s.client.UserID
	if room != "" && !s.client.sasRoomUsable(ctx, room) {
		return sasResult{err: ErrSASRoom}
	}
	if cross {
		if sasActive(s.Snapshot().State) {
			return sasResult{err: ErrSASStale}
		}
		if err := s.checkPeer(ctx, user); err != nil {
			if caller.Err() != nil {
				return sasResult{err: caller.Err()}
			}
			return sasResult{err: err}
		}
	}
	// StartVerification saves only after sending. Hold admission until that save
	// and our snapshot update finish, including when a peer replies immediately.
	s.gate.mu.Lock()
	defer s.gate.mu.Unlock()
	if ctx.Err() != nil {
		return sasResult{err: ctx.Err()}
	}
	all, _ := s.store.GetAllVerificationTransactions(ctx)
	if sasActive(s.Snapshot().State) || len(all) != 0 {
		return sasResult{err: ErrSASStale}
	}
	if s.gate.attempts >= 64 {
		return sasResult{err: ErrSASLimit}
	}
	if room != "" {
		return s.startInRoom(ctx, caller, user, room)
	}
	devices, err := s.client.OlmMachine().CryptoStore.GetDevices(ctx, user)
	if err == nil && len(devices) == 0 {
		var keys map[id.UserID]map[id.DeviceID]*id.Device
		keys, err = s.client.OlmMachine().FetchKeys(ctx, []id.UserID{user}, true)
		devices = keys[user]
	}
	if _, shared := devices[s.client.DeviceID]; err == nil && cross && shared {
		return sasResult{err: ErrPeerDeviceIDConflict}
	}
	peer := false
	for device := range devices {
		if device != s.client.DeviceID && device != "" {
			peer = true
		}
	}
	if err != nil || !peer {
		s.set(SASFailed, "", "", nil, "operation_failed")
		if caller.Err() != nil {
			return sasResult{err: caller.Err()}
		}
		return sasResult{err: ErrSASOperation}
	}
	// Failed sends also create upstream expiration workers. Count attempts before
	// calling upstream, independently of the successfully saved transaction IDs.
	s.gate.attempts++
	expires := time.Now().Add(10 * time.Minute)
	s.begin(user, "")
	txn, err := s.helper.StartVerification(ctx, user)
	if txn != "" {
		s.gate.recent[txn] = time.Now().Add(10 * time.Minute)
	}
	if err != nil {
		_ = s.helper.DismissVerification(ctx, txn)
		s.set(SASFailed, txn, "", nil, "operation_failed")
		if caller.Err() != nil {
			return sasResult{err: caller.Err()}
		}
		return sasResult{err: ErrSASOperation}
	}
	s.set(SASSent, txn, "", nil, "")
	return sasResult{txn: txn, expires: expires}
}

// startInRoom posts an in-room request and records its transaction, under
// the gate lock. mautrix v0.31.0's StartInRoomVerification encrypts the
// request and then hands the ciphertext to SendMessageEvent, which encrypts
// it again in an encrypted room, so no client can read it (pinned by
// TestUpstreamStartInRoomVerificationEncryptsTwice). rihma sends the
// request itself, encrypted once, and saves the transaction the helper
// would have saved. Its expiry is this controller's own timer.
func (s *SASController) startInRoom(ctx, caller context.Context, user id.UserID, room id.RoomID) sasResult {
	s.gate.attempts++
	expires := time.Now().Add(10 * time.Minute)
	s.begin(user, room)
	content := &event.MessageEventContent{
		MsgType:    event.MsgVerificationRequest,
		Body:       fmt.Sprintf("%s is asking to verify with emoji, which this client does not support.", s.client.UserID),
		FromDevice: s.client.DeviceID,
		Methods:    []event.VerificationMethod{event.VerificationMethodSAS},
		To:         user,
	}
	resp, err := s.client.SendMessageEvent(ctx, room, event.EventMessage, content)
	var txn id.VerificationTransactionID
	if err == nil {
		txn = id.VerificationTransactionID(resp.EventID)
		s.gate.recent[txn] = expires
		err = s.store.SaveVerificationTransaction(ctx, verificationhelper.VerificationTransaction{
			ExpirationTime:    jsontime.UM(expires),
			RoomID:            room,
			VerificationState: verificationhelper.VerificationStateRequested,
			TransactionID:     txn,
			TheirUserID:       user,
		})
	}
	if err != nil && txn != "" {
		// The request is out but cannot be tracked, so no helper path can
		// end it; tell the peer here, even if the caller has gone.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		end := &event.VerificationCancelEventContent{Code: event.VerificationCancelCodeUser, Reason: "Verification could not be started"}
		end.SetRelatesTo(&event.RelatesTo{Type: event.RelReference, EventID: id.EventID(txn)})
		_, _ = s.client.SendMessageEvent(cleanup, room, event.InRoomVerificationCancel, end)
	}
	if err != nil || txn == "" {
		s.set(SASFailed, txn, "", nil, "operation_failed")
		if caller.Err() != nil {
			return sasResult{err: caller.Err()}
		}
		return sasResult{err: ErrSASOperation}
	}
	s.gate.outgoing = txn
	s.set(SASSent, txn, "", nil, "")
	return sasResult{txn: txn, expires: expires}
}

// sasRoomUsable reports whether room is an encrypted room this account has
// joined, from the local state store.
func (c *Client) sasRoomUsable(ctx context.Context, room id.RoomID) bool {
	if encrypted, err := c.StateStore.IsEncrypted(ctx, room); err != nil || !encrypted {
		return false
	}
	member, err := c.StateStore.GetMember(ctx, room, c.UserID)
	return err == nil && member != nil && member.Membership == event.MembershipJoin
}

func (s *SASController) startReady(ev sasEvent) {
	ctx := zerolog.Nop().WithContext(s.runCtx)
	s.gate.mu.Lock()
	defer s.gate.mu.Unlock()
	txn, err := s.store.GetVerificationTransaction(ctx, ev.txn)
	if err != nil {
		// Cancellation/expiry can delete the transaction before callback delivery.
		return
	}
	if !ev.supportsSAS {
		_ = s.helper.CancelVerification(ctx, ev.txn, event.VerificationCancelCodeUnknownMethod, "SAS is required")
		err = ErrSASOperation
	} else if txn.StartEventContent == nil {
		// If a peer's start already arrived, use it instead of sending a second.
		err = s.helper.StartSAS(ctx, ev.txn)
	}
	if err != nil {
		_ = s.helper.DismissVerification(ctx, ev.txn)
		s.set(SASFailed, ev.txn, ev.fromDevice, nil, "operation_failed")
		return
	}
	s.set(SASAccepted, ev.txn, ev.fromDevice, nil, "")
}
func safeSASReason(code event.VerificationCancelCode) string {
	switch code {
	case event.VerificationCancelCodeTimeout:
		return "timeout"
	case event.VerificationCancelCodeSASMismatch:
		return "mismatch"
	case event.VerificationCancelCodeUser:
		return "rejected"
	default:
		return "cancelled"
	}
}
func (s *SASController) execute(cmd sasCommand) error {
	if err := cmd.ctx.Err(); err != nil {
		return err
	}
	current := s.Snapshot()
	if current.TransactionID != cmd.txn || !sasActive(current.State) {
		return ErrSASStale
	}
	ctx, cancel := context.WithCancel(zerolog.Nop().WithContext(cmd.ctx))
	defer cancel()
	stop := context.AfterFunc(s.runCtx, cancel)
	defer stop()
	var err error
	switch cmd.action {
	case "accept":
		if current.State != SASRequested {
			return ErrSASStale
		}
		if current.OtherUser != s.client.UserID {
			if err := s.checkIncomingPeer(ctx, cmd, current); err != nil {
				return err
			}
		}
		err = s.helper.AcceptVerification(ctx, cmd.txn)
		if err == nil {
			s.set(SASAccepted, cmd.txn, current.OtherDevice, nil, "")
		}
	case "confirm":
		if current.State != SASShowing {
			return ErrSASStale
		}
		if cmd.match {
			err = s.helper.ConfirmSAS(ctx, cmd.txn)
			if err == nil {
				s.set(SASConfirmed, cmd.txn, current.OtherDevice, nil, "")
				// Our MAC is sent, so the peer's MAC is checked second, the
				// order in which the helper signs another user.
				s.gate.releaseHeld(zerolog.Nop().WithContext(s.runCtx), cmd.txn)
			}
		} else {
			s.gate.dropHeld()
			err = s.helper.CancelVerification(ctx, cmd.txn, event.VerificationCancelCodeSASMismatch, "Emoji did not match")
			_ = s.helper.DismissVerification(ctx, cmd.txn)
			s.set(SASCancelled, cmd.txn, current.OtherDevice, nil, "mismatch")
		}
	case "cancel":
		s.gate.dropHeld()
		err = s.helper.CancelVerification(ctx, cmd.txn, event.VerificationCancelCodeUser, "User cancelled")
		_ = s.helper.DismissVerification(ctx, cmd.txn)
		s.set(SASCancelled, cmd.txn, current.OtherDevice, nil, "cancelled")
	}
	if err != nil {
		s.gate.dropHeld()
		_ = s.helper.DismissVerification(ctx, cmd.txn)
		if cmd.action != "cancel" && !(cmd.action == "confirm" && !cmd.match) {
			s.set(SASFailed, cmd.txn, current.OtherDevice, nil, "operation_failed")
		}
		if cmd.ctx.Err() != nil {
			return cmd.ctx.Err()
		}
		return ErrSASOperation
	}
	return nil
}

// Handler registration remains on the existing crypto-aware syncer. Excluding
// unsupported in-room events and requests from unlisted users here prevents
// helper transactions/timers for them, rather than merely hiding their UI
// callbacks.
type sasEventGate struct {
	mu        sync.Mutex
	active    bool
	store     *sasStore
	callbacks *sasCallbacks
	recent    map[id.VerificationTransactionID]time.Time
	attempts  int
	// peers are the other users whose requests are admitted, and inRoom
	// whether in-room events are. Both are set before the controller is
	// published and never changed, so read without mu.
	peers  map[id.UserID]struct{}
	inRoom bool
	// outgoing is the in-room transaction this controller started, the only
	// one a peer's in-room ready may answer.
	outgoing id.VerificationTransactionID
	// For an attempt with another user: the MACs admitted so far, the master
	// key the admitted one named, and the events held until our MAC is sent.
	macTxn    id.VerificationTransactionID
	macs      int
	macMaster id.Ed25519
	held      []heldEvent
}

type heldEvent struct {
	ev      *event.Event
	handler mautrix.EventHandler
}

type sasHandlerSyncer struct {
	*mautrix.DefaultSyncer
	underlying *mautrix.DefaultSyncer
	gate       *sasEventGate
	user       id.UserID
	device     id.DeviceID
	// roomUsable reports whether a room is encrypted and joined. In-room
	// requests are dropped when it is nil.
	roomUsable func(context.Context, id.RoomID) bool
	// log, when set, receives a debug line for each verification event the
	// gate drops or holds: its kind, the reason, and public ids only.
	log           *zerolog.Logger
	staged        bool
	registrations []sasRegistration
}

// Reasons the gate gives for not passing an event to the helper. They are
// fixed strings, so a log line never carries event content.
const (
	sasDropUnlisted   = "sender not listed"
	sasDropOwnDevice  = "this device"
	sasDropOwnEvent   = "this account's own event"
	sasDropMalformed  = "malformed"
	sasDropStale      = "too old or in the future"
	sasDropNotForUs   = "addressed to another user"
	sasDropRoom       = "room not encrypted or not joined"
	sasDropBusy       = "another attempt is active"
	sasDropReused     = "transaction id already used"
	sasDropLimit      = "attempt limit reached"
	sasDropNoRef      = "no reference to a request"
	sasDropUnknown    = "unknown transaction"
	sasDropWrongRoom  = "transaction is in another room"
	sasDropWrongUser  = "sender is not the transaction's user"
	sasDropInRoomTxn  = "names an in-room transaction"
	sasDropReady      = "ready not expected"
	sasDropExtraMAC   = "second MAC"
	sasHeldUntilMAC   = "held until the local confirmation"
	sasDropRepeatDone = "repeated done behind a held MAC"
)

// OnEventType wraps the helper's handlers in the gate. To-device handlers
// are always registered; in-room ones only for a controller with InRoom,
// so a controller without it never lets an in-room event reach the helper.
// admit returns the event to pass on, or nil and the reason to drop it; an
// empty reason is an event that is not verification at all.
func (s *sasHandlerSyncer) OnEventType(kind event.Type, handler mautrix.EventHandler) {
	var admit func(context.Context, *event.Event) (*event.Event, string)
	switch {
	case kind == event.ToDeviceVerificationRequest:
		admit = s.admitRequest
	case kind.Class == event.ToDeviceEventType:
		admit = func(ctx context.Context, ev *event.Event) (*event.Event, string) {
			if reason := s.admitFollowUp(ctx, kind, ev, handler); reason != "" {
				return nil, reason
			}
			return ev, ""
		}
	case !s.gate.inRoom:
		return
	case kind == event.EventMessage:
		admit = s.admitRoomRequest
	default:
		admit = func(ctx context.Context, ev *event.Event) (*event.Event, string) {
			return s.admitRoomFollowUp(ctx, kind, ev, handler)
		}
	}
	wrapped := func(ctx context.Context, ev *event.Event) {
		s.gate.mu.Lock()
		defer s.gate.mu.Unlock()
		if !s.gate.active || ctx.Err() != nil {
			return
		}
		passed, reason := admit(ctx, ev)
		if passed == nil {
			if reason != "" && s.log != nil {
				s.log.Debug().Str("event_type", ev.Type.Type).Stringer("sender", ev.Sender).Stringer("room_id", ev.RoomID).Bool("was_encrypted", ev.Mautrix.WasEncrypted).Str("reason", reason).Msg("SAS gate did not pass a verification event")
			}
			return
		}
		handler(zerolog.Nop().WithContext(ctx), passed)
	}
	if s.staged {
		s.registrations = append(s.registrations, sasRegistration{kind, wrapped})
	} else {
		s.underlying.OnEventType(kind, wrapped)
	}
}

// admitRequest admits a to-device request. It runs under the gate lock.
func (s *sasHandlerSyncer) admitRequest(ctx context.Context, ev *event.Event) (*event.Event, string) {
	if !s.gate.admitsRequestFrom(s.user, ev.Sender) {
		return nil, sasDropUnlisted
	}
	req := ev.Content.AsVerificationRequest()
	// Device ids are scoped to their user: compare with this device only
	// for this account's own devices.
	switch {
	case ev.Sender == s.user && req.FromDevice == s.device:
		return nil, sasDropOwnDevice
	case req.FromDevice == "" || len(req.FromDevice) > 256 || req.TransactionID == "" || len(req.TransactionID) > 256:
		return nil, sasDropMalformed
	case !sasRequestFresh(req.Timestamp.Time):
		return nil, sasDropStale
	}
	if reason := s.gate.admitNew(ctx, req.TransactionID, req.Timestamp.Add(10*time.Minute)); reason != "" {
		return nil, reason
	}
	return ev, ""
}

// admitRoomRequest admits an in-room request, an m.room.message with
// msgtype m.key.verification.request as Element sends to verify another
// user in a DM. The sender must be a listed peer and the request addressed
// to this account, in an encrypted room this account has joined. Element
// sends the request unencrypted even in an encrypted room, so how it
// arrived is not checked: the homeserver asserts the sender here as it does
// for to-device events, and SAS authenticates the keys whatever carried
// them. Every other message is dropped before the helper, which would
// ignore it anyway. Runs under the gate lock.
func (s *sasHandlerSyncer) admitRoomRequest(ctx context.Context, ev *event.Event) (*event.Event, string) {
	content := ev.Content.AsMessage()
	switch {
	case content.MsgType != event.MsgVerificationRequest:
		return nil, ""
	case ev.Sender == s.user:
		return nil, sasDropOwnEvent
	case !s.gate.admitsRequestFrom(s.user, ev.Sender):
		return nil, sasDropUnlisted
	case content.To != s.user:
		return nil, sasDropNotForUs
	case ev.RoomID == "" || ev.ID == "" || len(ev.ID) > 256 || content.FromDevice == "" || len(content.FromDevice) > 256:
		return nil, sasDropMalformed
	}
	sent := time.UnixMilli(ev.Timestamp)
	if !sasRequestFresh(sent) {
		return nil, sasDropStale
	}
	if s.roomUsable == nil || !s.roomUsable(ctx, ev.RoomID) {
		return nil, sasDropRoom
	}
	if reason := s.gate.admitNew(ctx, id.VerificationTransactionID(ev.ID), sent.Add(10*time.Minute)); reason != "" {
		return nil, reason
	}
	return ev, ""
}

// sasRequestFresh applies the age bounds: sent at most ten minutes ago and
// at most one minute in the future.
func sasRequestFresh(sent time.Time) bool {
	now := time.Now()
	return !sent.After(now.Add(time.Minute)) && sent.Add(10*time.Minute).After(now)
}

// admitNew applies the bounds every new request shares: one active
// attempt, transaction ids never reused, and at most 64 attempts. It
// returns the reason to drop, or "". It runs under the gate lock.
func (g *sasEventGate) admitNew(ctx context.Context, txn id.VerificationTransactionID, expires time.Time) string {
	if g.store == nil {
		return ""
	}
	if all, _ := g.store.GetAllVerificationTransactions(ctx); len(all) > 0 {
		return sasDropBusy
	}
	// Remember IDs for the whole controller lifetime. An expiration worker
	// can be delayed beyond its deadline, so time alone cannot make reuse safe.
	if _, reused := g.recent[txn]; reused {
		return sasDropReused
	}
	if g.attempts >= 64 {
		return sasDropLimit
	}
	g.recent[txn] = expires
	g.attempts++
	return ""
}

// admitsRequestFrom reports whether a request from sender may reach the
// helper: it comes from this account (own) or a listed peer.
func (g *sasEventGate) admitsRequestFrom(own, sender id.UserID) bool {
	if sender == own {
		return true
	}
	_, listed := g.peers[sender]
	return listed
}

// admitFollowUp binds a to-device follow-up to its transaction's user,
// because the helper routes follow-ups by transaction id alone. A follow-up
// naming no known transaction reaches the helper only from this account, as
// before cross-user support, so another user cannot make this device reply,
// and one naming an in-room transaction never does. It returns the reason
// to drop, or "". It runs under the gate lock.
func (s *sasHandlerSyncer) admitFollowUp(ctx context.Context, kind event.Type, ev *event.Event, handler mautrix.EventHandler) string {
	own := func() string {
		if ev.Sender == s.user {
			return ""
		}
		return sasDropUnknown
	}
	if s.gate.store == nil {
		return own()
	}
	content, ok := ev.Content.Parsed.(event.VerificationTransactionable)
	if !ok {
		return own()
	}
	txn, err := s.gate.store.GetVerificationTransaction(ctx, content.GetTransactionID())
	if err != nil {
		if kind == event.ToDeviceVerificationReady {
			return sasDropUnknown
		}
		return own()
	}
	if ev.Sender != txn.TheirUserID {
		return sasDropWrongUser
	}
	if txn.RoomID != "" {
		return sasDropInRoomTxn
	}
	return s.admitStep(kind.Type, txn, ev, handler)
}

// admitRoomFollowUp admits an in-room follow-up: an event in the
// transaction's room, from its user, that references its request event.
// As for requests, how it arrived is not checked; Element sends follow-ups
// unencrypted too. mautrix v0.31.0 looks an in-room follow-up up by its own
// event id rather than the reference (pinned by
// TestUpstreamInRoomFollowUpsMissTheirTransaction), so the helper is given
// a copy whose id is the request's. That stays right once upstream routes
// by the reference, which the copy keeps. Runs under the gate lock.
func (s *sasHandlerSyncer) admitRoomFollowUp(ctx context.Context, kind event.Type, ev *event.Event, handler mautrix.EventHandler) (*event.Event, string) {
	if ev.Sender == s.user {
		// Our own events come back through sync.
		return nil, sasDropOwnEvent
	}
	if s.gate.store == nil || ev.RoomID == "" {
		return nil, sasDropMalformed
	}
	relatable, ok := ev.Content.Parsed.(interface{ OptionalGetRelatesTo() *event.RelatesTo })
	if !ok {
		return nil, sasDropMalformed
	}
	ref := relatable.OptionalGetRelatesTo()
	if ref == nil || ref.Type != event.RelReference || ref.EventID == "" {
		return nil, sasDropNoRef
	}
	txn, err := s.gate.store.GetVerificationTransaction(ctx, id.VerificationTransactionID(ref.EventID))
	switch {
	case err != nil:
		return nil, sasDropUnknown
	case txn.RoomID != ev.RoomID:
		return nil, sasDropWrongRoom
	case ev.Sender != txn.TheirUserID:
		return nil, sasDropWrongUser
	}
	routed := *ev
	routed.ID = ref.EventID
	if reason := s.admitStep(kind.Type, txn, &routed, handler); reason != "" {
		return nil, reason
	}
	return &routed, ""
}

// admitStep applies the per-step rules to a follow-up already bound to txn,
// whatever its route. It returns the reason not to pass it now, or "". It
// runs under the gate lock.
func (s *sasHandlerSyncer) admitStep(step string, txn verificationhelper.VerificationTransaction, ev *event.Event, handler mautrix.EventHandler) string {
	switch step {
	case event.ToDeviceVerificationReady.Type:
		// Device ids are scoped to their user: compare with this device only
		// for this account's own devices. A to-device ready must come from a
		// device the request went to; an in-room one may come from any of the
		// peer's devices, but only for a request this controller posted.
		ready := ev.Content.AsVerificationReady()
		if ready.FromDevice == "" || len(ready.FromDevice) > 256 {
			return sasDropMalformed
		}
		if (ev.Sender == s.user && ready.FromDevice == s.device) || txn.VerificationState != verificationhelper.VerificationStateRequested {
			return sasDropReady
		}
		if txn.RoomID != "" {
			if s.gate.outgoing != txn.TransactionID {
				return sasDropReady
			}
		} else if !slices.Contains(txn.SentToDeviceIDs, ready.FromDevice) {
			return sasDropReady
		}
	case event.ToDeviceVerificationMAC.Type:
		if ev.Sender != s.user {
			return s.gate.admitPeerMAC(txn, ev, handler)
		}
	case event.ToDeviceVerificationDone.Type:
		// A done that overtakes a held MAC would find the helper short of
		// the MAC exchange and cancel; keep their order. Only the held MAC
		// and one done are kept, and repeated dones are dropped, so a peer
		// cannot grow the queue while the local person decides.
		if len(s.gate.held) > 0 && s.gate.macTxn == txn.TransactionID {
			if len(s.gate.held) == 1 {
				s.gate.held = append(s.gate.held, heldEvent{ev, handler})
				return sasHeldUntilMAC
			}
			return sasDropRepeatDone
		}
	}
	return ""
}

// admitPeerMAC handles another user's MAC. mautrix v0.31.0 signs the other
// user only when it checks their MAC after sending ours, so a MAC that
// arrives before the local person confirms is held until then. One MAC is
// admitted per attempt; a second cancels it. It returns why the MAC is not
// passed now, or "". Runs under the gate lock.
func (g *sasEventGate) admitPeerMAC(txn verificationhelper.VerificationTransaction, ev *event.Event, handler mautrix.EventHandler) string {
	if g.macTxn != txn.TransactionID {
		g.macTxn, g.macs, g.macMaster, g.held = txn.TransactionID, 0, "", nil
	}
	g.macs++
	if g.macs > 1 {
		g.held = nil
		if g.callbacks != nil {
			g.callbacks.post(sasEvent{txn: txn.TransactionID, extraMAC: true})
		}
		return sasDropExtraMAC
	}
	g.macMaster = ""
	for keyID := range ev.Content.AsVerificationMAC().MAC {
		if _, key := keyID.Parse(); key != txn.TheirDeviceID.String() {
			g.macMaster = id.Ed25519(key)
		}
	}
	if !txn.SentOurMAC {
		g.held = append(g.held, heldEvent{ev, handler})
		return sasHeldUntilMAC
	}
	return ""
}

// releaseHeld passes events held for txn to the helper, in arrival order.
func (g *sasEventGate) releaseHeld(ctx context.Context, txn id.VerificationTransactionID) {
	g.mu.Lock()
	defer g.mu.Unlock()
	held := g.held
	g.held = nil
	if !g.active || g.macTxn != txn {
		return
	}
	for _, h := range held {
		h.handler(ctx, h.ev)
	}
}

// dropHeld discards held events when an attempt ends without our MAC.
func (g *sasEventGate) dropHeld() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.held = nil
}

// macMasterKey is the master key named by the MAC admitted for txn.
func (g *sasEventGate) macMasterKey(txn id.VerificationTransactionID) id.Ed25519 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.macTxn != txn {
		return ""
	}
	return g.macMaster
}

type sasRegistration struct {
	kind    event.Type
	handler mautrix.EventHandler
}

func (s *sasHandlerSyncer) commit() {
	for _, registration := range s.registrations {
		s.underlying.OnEventType(registration.kind, registration.handler)
	}
	s.registrations = nil
	s.staged = false
}

// sasStore bounds active secret-bearing transactions and can revoke access
// independently of the helper's sleeping expiration goroutines.
type sasStore struct {
	mu     sync.Mutex
	store  *verificationhelper.InMemoryVerificationStore
	closed bool
}

func newSASStore() *sasStore {
	return &sasStore{store: verificationhelper.NewInMemoryVerificationStore()}
}
func (s *sasStore) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.store = verificationhelper.NewInMemoryVerificationStore()
}
func (s *sasStore) DeleteVerification(ctx context.Context, txn id.VerificationTransactionID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return verificationhelper.ErrUnknownVerificationTransaction
	}
	return s.store.DeleteVerification(ctx, txn)
}
func (s *sasStore) GetVerificationTransaction(ctx context.Context, txn id.VerificationTransactionID) (verificationhelper.VerificationTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return verificationhelper.VerificationTransaction{}, verificationhelper.ErrUnknownVerificationTransaction
	}
	return s.store.GetVerificationTransaction(ctx, txn)
}
func (s *sasStore) SaveVerificationTransaction(ctx context.Context, txn verificationhelper.VerificationTransaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return verificationhelper.ErrUnknownVerificationTransaction
	}
	all, _ := s.store.GetAllVerificationTransactions(ctx)
	if len(all) > 0 && all[0].TransactionID != txn.TransactionID {
		return ErrSASStale
	}
	return s.store.SaveVerificationTransaction(ctx, txn)
}
func (s *sasStore) FindVerificationTransactionForUserDevice(ctx context.Context, user id.UserID, device id.DeviceID) (verificationhelper.VerificationTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return verificationhelper.VerificationTransaction{}, verificationhelper.ErrUnknownVerificationTransaction
	}
	return s.store.FindVerificationTransactionForUserDevice(ctx, user, device)
}
func (s *sasStore) GetAllVerificationTransactions(ctx context.Context) ([]verificationhelper.VerificationTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil
	}
	return s.store.GetAllVerificationTransactions(ctx)
}
