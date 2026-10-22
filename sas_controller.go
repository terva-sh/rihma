package rihma

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog"

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
)

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
	// same-account attempt, or the user named in StartUser.
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
	result chan sasResult
}

type sasResult struct {
	txn     id.VerificationTransactionID
	err     error
	expires time.Time
}

// SASController handles to-device emoji verification through Client.Sync:
// with this account's other devices, and outgoing with another user. It never starts sync. One controller lasts one Sync;
// attempts can repeat during that Sync. It does not persist pending attempts.
// Call EnableSAS before the client's first Sync. Stop Sync before closing stores.
type SASController struct {
	client    *Client
	helper    *verificationhelper.VerificationHelper
	store     *sasStore
	gate      *sasEventGate
	callbacks *sasCallbacks
	mu        sync.Mutex
	snapshot  SASSnapshot
	// peer and master fill the snapshot's OtherUser and MasterKey.
	peer   id.UserID
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
func (c *Client) EnableSAS() (*SASController, error) {
	c.connectOnce.Lock()
	defer c.connectOnce.Unlock()
	if c.sas != nil {
		return c.sas, nil
	}
	if c.syncStarted {
		return nil, ErrSASUnavailable
	}
	s := newSASController(c)
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
	proxy := &sasHandlerSyncer{DefaultSyncer: s.client.Handlers(), underlying: s.client.Handlers(), gate: s.gate, user: s.client.UserID, device: s.client.DeviceID, staged: true}
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

// begin names the user of a new attempt and clears the last one's key.
func (s *SASController) begin(user id.UserID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peer, s.master = user, ""
}

func (s *SASController) set(state SASState, txn id.VerificationTransactionID, device id.DeviceID, emoji []SASEmoji, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var peer id.UserID
	if txn != "" {
		peer = s.peer
	}
	s.snapshot = SASSnapshot{Revision: s.snapshot.Revision + 1, State: state, TransactionID: txn, OtherUser: peer, OtherDevice: device, Emoji: append([]SASEmoji(nil), emoji...), MasterKey: s.master, Reason: reason}
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
	result := s.submit(ctx, "", "start", false, s.client.UserID)
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
	result := s.submit(ctx, "", "start", false, user)
	return result.txn, result.err
}

func (s *SASController) command(ctx context.Context, txn id.VerificationTransactionID, action string, match bool) error {
	return s.submit(ctx, txn, action, match, "").err
}
func (s *SASController) submit(ctx context.Context, txn id.VerificationTransactionID, action string, match bool, user id.UserID) sasResult {
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
	cmd := sasCommand{ctx: ctx, txn: txn, action: action, match: match, user: user, result: make(chan sasResult, 1)}
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
				result := s.executeStart(cmd.ctx, cmd.user)
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
		if ev.from != s.client.UserID || ev.fromDevice == s.client.DeviceID || sasActive(current.State) {
			_ = s.helper.DismissVerification(s.runCtx, ev.txn)
			return
		}
		// Ignore a request whose expiry/cancellation raced its callback delivery.
		if _, err := s.store.GetVerificationTransaction(s.runCtx, ev.txn); err != nil {
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
		s.begin(s.client.UserID)
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

// checkPeer runs StartUser's prerequisites. It makes network requests, so
// it runs before the gate is locked.
func (s *SASController) checkPeer(ctx context.Context, user id.UserID) error {
	if _, err := s.client.OwnMasterKey(ctx); errors.Is(err, ErrMasterKeyMismatch) {
		return fmt.Errorf("%w: the server publishes another identity", ErrNoCrossSigningKeys)
	} else if err != nil {
		return err
	}
	_, err := s.client.UserIdentity(ctx, user)
	return err
}

func (s *SASController) executeStart(caller context.Context, user id.UserID) sasResult {
	ctx, cancel := context.WithCancel(zerolog.Nop().WithContext(caller))
	defer cancel()
	stop := context.AfterFunc(s.runCtx, cancel)
	defer stop()
	cross := user != s.client.UserID
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
	s.begin(user)
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
// in-room requests and requests from other users here prevents helper
// transactions/timers for unsupported requests, rather than merely hiding
// their UI callbacks.
type sasEventGate struct {
	mu        sync.Mutex
	active    bool
	store     *sasStore
	callbacks *sasCallbacks
	recent    map[id.VerificationTransactionID]time.Time
	attempts  int
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
	underlying    *mautrix.DefaultSyncer
	gate          *sasEventGate
	user          id.UserID
	device        id.DeviceID
	staged        bool
	registrations []sasRegistration
}

func (s *sasHandlerSyncer) OnEventType(kind event.Type, handler mautrix.EventHandler) {
	if kind.Class != event.ToDeviceEventType {
		return
	}
	wrapped := func(ctx context.Context, ev *event.Event) {
		s.gate.mu.Lock()
		defer s.gate.mu.Unlock()
		if !s.gate.active || ctx.Err() != nil {
			return
		}
		if kind == event.ToDeviceVerificationRequest {
			if ev.Sender != s.user {
				return
			}
			req := ev.Content.AsVerificationRequest()
			now := time.Now()
			if req.FromDevice == s.device || req.FromDevice == "" || len(req.FromDevice) > 256 || req.TransactionID == "" || len(req.TransactionID) > 256 || req.Timestamp.Time.After(now.Add(time.Minute)) || !req.Timestamp.Add(10*time.Minute).After(now) {
				return
			}
			if s.gate.store != nil {
				all, _ := s.gate.store.GetAllVerificationTransactions(ctx)
				if len(all) > 0 {
					return
				}
				// Remember IDs for the whole controller lifetime. An expiration worker
				// can be delayed beyond its deadline, so time alone cannot make reuse safe.
				if _, reused := s.gate.recent[req.TransactionID]; reused || s.gate.attempts >= 64 {
					return
				}
				s.gate.recent[req.TransactionID] = req.Timestamp.Add(10 * time.Minute)
				s.gate.attempts++
			}
		} else if !s.admitFollowUp(ctx, kind, ev, handler) {
			return
		}
		handler(zerolog.Nop().WithContext(ctx), ev)
	}
	if s.staged {
		s.registrations = append(s.registrations, sasRegistration{kind, wrapped})
	} else {
		s.underlying.OnEventType(kind, wrapped)
	}
}

// admitFollowUp binds a follow-up to its transaction's user, because the
// helper routes follow-ups by transaction id alone. A follow-up naming no
// known transaction reaches the helper only from this account, as before
// cross-user support, so another user cannot make this device reply. It
// runs under the gate lock.
func (s *sasHandlerSyncer) admitFollowUp(ctx context.Context, kind event.Type, ev *event.Event, handler mautrix.EventHandler) bool {
	if s.gate.store == nil {
		return ev.Sender == s.user
	}
	content, ok := ev.Content.Parsed.(event.VerificationTransactionable)
	if !ok {
		return ev.Sender == s.user
	}
	txn, err := s.gate.store.GetVerificationTransaction(ctx, content.GetTransactionID())
	if err != nil {
		return ev.Sender == s.user && kind != event.ToDeviceVerificationReady
	}
	if ev.Sender != txn.TheirUserID {
		return false
	}
	switch kind {
	case event.ToDeviceVerificationReady:
		// Device ids are scoped to their user: compare with this device only
		// for this account's own devices.
		ready := ev.Content.AsVerificationReady()
		if ready.FromDevice == "" || (ev.Sender == s.user && ready.FromDevice == s.device) || len(ready.FromDevice) > 256 || txn.VerificationState != verificationhelper.VerificationStateRequested || !slices.Contains(txn.SentToDeviceIDs, ready.FromDevice) {
			return false
		}
	case event.ToDeviceVerificationMAC:
		if ev.Sender != s.user {
			return s.gate.admitPeerMAC(txn, ev, handler)
		}
	case event.ToDeviceVerificationDone:
		// A done that overtakes a held MAC would find the helper short of
		// the MAC exchange and cancel; keep their order. Only the held MAC
		// and one done are kept, and repeated dones are dropped, so a peer
		// cannot grow the queue while the local person decides.
		if len(s.gate.held) > 0 && s.gate.macTxn == txn.TransactionID {
			if len(s.gate.held) == 1 {
				s.gate.held = append(s.gate.held, heldEvent{ev, handler})
			}
			return false
		}
	}
	return true
}

// admitPeerMAC handles another user's MAC. mautrix v0.31.0 signs the other
// user only when it checks their MAC after sending ours, so a MAC that
// arrives before the local person confirms is held until then. One MAC is
// admitted per attempt; a second cancels it. Runs under the gate lock.
func (g *sasEventGate) admitPeerMAC(txn verificationhelper.VerificationTransaction, ev *event.Event, handler mautrix.EventHandler) bool {
	if g.macTxn != txn.TransactionID {
		g.macTxn, g.macs, g.macMaster, g.held = txn.TransactionID, 0, "", nil
	}
	g.macs++
	if g.macs > 1 {
		g.held = nil
		if g.callbacks != nil {
			g.callbacks.post(sasEvent{txn: txn.TransactionID, extraMAC: true})
		}
		return false
	}
	g.macMaster = ""
	for keyID := range ev.Content.AsVerificationMAC().MAC {
		if _, key := keyID.Parse(); key != txn.TheirDeviceID.String() {
			g.macMaster = id.Ed25519(key)
		}
	}
	if !txn.SentOurMAC {
		g.held = append(g.held, heldEvent{ev, handler})
		return false
	}
	return true
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
