package rihma

import (
	"context"
	"errors"
	"fmt"
	"time"

	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// SASEmoji is one of the seven emoji both devices show during an emoji
// verification.
type SASEmoji struct {
	Emoji       string
	Description string
}

var (
	// ErrSASMismatch is returned by AwaitSAS when confirm reports that
	// the emoji differ. The other device is told, and nothing is trusted.
	ErrSASMismatch = errors.New("rihma: the emoji did not match; verification cancelled")
	// ErrSASCancelled is wrapped by AwaitSAS when the other device
	// cancelled or the verification timed out on the server's side.
	ErrSASCancelled = errors.New("rihma: verification cancelled")
	// ErrSASUnsigned is returned by VerifyUser when the other user's
	// device completed the exchange without naming their master key, so
	// their device is verified but the user is not.
	ErrSASUnsigned = errors.New("rihma: the other user's verification did not cover their master key")
)

// AwaitSAS answers one emoji (SAS) verification that another device of
// this account starts, and returns nil once this device is verified.
// Requests from other users are declined; a bot verifies itself, from a
// client its operator controls.
//
// confirm is shown the emoji and reports whether the other device shows
// the same seven. It runs on AwaitSAS's goroutine and may block, for
// example on a terminal prompt.
//
// AwaitSAS syncs while it waits, because requests only arrive through
// sync, so it fails with ErrSyncInProgress while anything else syncs on
// this state directory, such as a running connector. Call it on a client
// that is not syncing, and bound the wait with ctx. A Client can answer
// only one verification in its lifetime.
func (c *Client) AwaitSAS(ctx context.Context, confirm func([]SASEmoji) bool) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	unlock, err := lockSync(c.opts.StateDir)
	if err != nil {
		return err
	}
	unlock() // only a check: Sync below takes it for real

	controller, err := c.EnableSAS()
	if err != nil {
		return err
	}
	if err := controller.prepareAwait(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	syncErr := make(chan error, 1)
	go func() { syncErr <- c.Sync(ctx) }()
	defer func() { cancel(); <-syncErr }()
	return awaitSAS(ctx, controller, syncErr, confirm)
}

// VerifyUser asks user to verify this account with emoji, and returns
// user's master key once both people have confirmed and this account has
// signed and recorded it, as SignUserIdentity does. It is the outgoing
// counterpart of AwaitSAS, for a bot whose operator compares the emoji
// over a channel the homeserver cannot change, such as the bot's
// terminal.
//
// The request goes over to-device messages to every device user
// publishes; StartUser lists the checks made before anything is sent.
// confirm is shown the emoji and reports whether user's device shows the
// same seven. It runs on VerifyUser's goroutine and may block. VerifyUser
// never confirms unless confirm returns true, and then returns
// ErrSASMismatch if it returned false and ErrSASCancelled if user
// cancels or the request times out. A peer whose device does not name
// their master key ends with ErrSASUnsigned, and a master key that changed
// on the server before completion with ErrMasterKeyMismatch.
//
// Element answers the request only from a user whose devices it already
// tracks, so the bot and user should share an encrypted room, such as
// their DM; otherwise Element drops it and VerifyUser ends with
// ErrSASCancelled when it times out.
//
// Like AwaitSAS it runs its own Sync, so it fails with ErrSyncInProgress
// while anything else syncs on this state directory, and a Client can run
// only one verification in its lifetime. Bound the wait with ctx.
func (c *Client) VerifyUser(ctx context.Context, user id.UserID, confirm func([]SASEmoji) bool) (id.Ed25519, error) {
	if user == c.UserID {
		return "", ErrOwnUser
	}
	if err := c.Connect(ctx); err != nil {
		return "", err
	}
	unlock, err := lockSync(c.opts.StateDir)
	if err != nil {
		return "", err
	}
	unlock() // only a check: Sync below takes it for real

	controller, err := c.EnableSAS()
	if err != nil {
		return "", err
	}
	if err := controller.prepareAwait(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	syncErr := make(chan error, 1)
	go func() { syncErr <- c.Sync(ctx) }()
	defer func() { cancel(); <-syncErr }()
	if err := waitSASStarted(ctx, controller, syncErr); err != nil {
		return "", err
	}
	txn, err := controller.StartUser(ctx, user)
	if err != nil {
		return "", err
	}
	return verifyUser(ctx, controller, syncErr, txn, confirm)
}

// waitSASStarted waits until Sync has started the controller, which it
// does before its first request.
func waitSASStarted(ctx context.Context, controller *SASController, syncErr chan error) error {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		controller.mu.Lock()
		started, stopped := controller.started, controller.stopped
		controller.mu.Unlock()
		if started && !stopped {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-syncErr:
			syncErr <- err
			return fmt.Errorf("rihma: sync stopped before verification: %w", err)
		case <-tick.C:
		}
	}
}

// verifyUser follows txn, VerifyUser's own attempt, to its end. It never
// accepts a request: an incoming one is someone else's attempt.
func verifyUser(ctx context.Context, controller *SASController, syncErr chan error, txn id.VerificationTransactionID, confirm func([]SASEmoji) bool) (id.Ed25519, error) {
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case err := <-syncErr:
			syncErr <- err
			return "", fmt.Errorf("rihma: sync stopped during verification: %w", err)
		case _, ok := <-controller.Changed():
			state := controller.awaitSnapshot()
			if state.TransactionID != txn {
				if !ok {
					return "", ErrSASUnavailable
				}
				continue
			}
			switch state.State {
			case SASShowing:
				match := confirm(state.Emoji)
				err := controller.Confirm(ctx, txn, match)
				if !match {
					return "", ErrSASMismatch
				}
				if err != nil {
					// The peer may have cancelled while confirm was deciding.
					if controller.awaitSnapshot().State == SASCancelled {
						return "", ErrSASCancelled
					}
					return "", err
				}
			case SASDone:
				return state.MasterKey, nil
			case SASCancelled:
				return "", ErrSASCancelled
			case SASFailed:
				switch state.Reason {
				case "unsigned":
					return "", ErrSASUnsigned
				case "identity_changed":
					return "", fmt.Errorf("%w: it changed before verification completed", ErrMasterKeyMismatch)
				}
				return "", ErrSASOperation
			}
			if !ok {
				return "", ErrSASUnavailable
			}
		}
	}
}

func awaitSAS(ctx context.Context, controller *SASController, syncErr chan error, confirm func([]SASEmoji) bool) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-syncErr:
			syncErr <- err
			return fmt.Errorf("rihma: sync stopped during verification: %w", err)
		case _, ok := <-controller.Changed():
			state := controller.awaitSnapshot()
			switch state.State {
			case SASRequested:
				if err := controller.Accept(ctx, state.TransactionID); err != nil {
					return err
				}
			case SASShowing:
				match := confirm(state.Emoji)
				err := controller.Confirm(ctx, state.TransactionID, match)
				if !match {
					return ErrSASMismatch
				}
				if err != nil {
					return err
				}
			case SASDone:
				return nil
			case SASCancelled:
				return ErrSASCancelled
			case SASFailed:
				return ErrSASOperation
			}
			if !ok {
				return ErrSASUnavailable
			}
		}
	}
}

// sasEvent is one callback from the verification helper, carried to
// AwaitSAS's goroutine. The helper fires some callbacks while holding its
// own lock, so they must not call back into it or block.
type sasEvent struct {
	txn         id.VerificationTransactionID
	requested   bool
	ready       bool
	expired     bool
	supportsSAS bool
	from        id.UserID
	fromDevice  id.DeviceID
	emoji       []SASEmoji
	cancelled   event.VerificationCancelCode
	done        bool
	// extraMAC reports a second MAC from another user in one attempt.
	extraMAC bool
}

type sasCallbacks struct {
	events   chan sasEvent
	overflow chan struct{}
}

func (s *sasCallbacks) post(ev sasEvent) {
	select {
	case s.events <- ev:
	default:
		select {
		case s.overflow <- struct{}{}:
		default:
		}
	}
}

func (s *sasCallbacks) VerificationRequested(_ context.Context, txn id.VerificationTransactionID, from id.UserID, fromDevice id.DeviceID) {
	s.post(sasEvent{txn: txn, requested: true, from: from, fromDevice: fromDevice})
}

// Callbacks only enqueue: upstream may hold its lock and save after returning.
func (s *sasCallbacks) VerificationReady(_ context.Context, txn id.VerificationTransactionID, device id.DeviceID, supportsSAS bool, _ bool, _ *verificationhelper.QRCode) {
	s.post(sasEvent{txn: txn, ready: true, fromDevice: device, supportsSAS: supportsSAS})
}

func (s *sasCallbacks) VerificationCancelled(_ context.Context, txn id.VerificationTransactionID, code event.VerificationCancelCode, reason string) {
	s.post(sasEvent{txn: txn, cancelled: code})
}

func (s *sasCallbacks) VerificationDone(_ context.Context, txn id.VerificationTransactionID, _ event.VerificationMethod) {
	s.post(sasEvent{txn: txn, done: true})
}

func (s *sasCallbacks) ShowSAS(_ context.Context, txn id.VerificationTransactionID, emojis []rune, descriptions []string, _ []int) {
	if len(emojis) != 7 || len(descriptions) != 7 {
		s.post(sasEvent{txn: txn, cancelled: event.VerificationCancelCodeInvalidMessage})
		return
	}
	out := make([]SASEmoji, len(emojis))
	for i, e := range emojis {
		out[i] = SASEmoji{Emoji: string(e), Description: descriptions[i]}
	}
	s.post(sasEvent{txn: txn, emoji: out})
}
