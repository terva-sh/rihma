package rihma

import (
	"context"
	"errors"
	"fmt"

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

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cb := &sasCallbacks{events: make(chan sasEvent, 16)}
	vh := verificationhelper.NewVerificationHelper(c.Client, c.OlmMachine(),
		verificationhelper.NewInMemoryVerificationStore(), cb, false, false, true)
	if err := vh.Init(ctx); err != nil {
		return fmt.Errorf("rihma: start verification helper: %w", err)
	}
	syncErr := make(chan error, 1)
	go func() { syncErr <- c.Sync(ctx) }()
	// Wait for the sync loop to exit before returning, so the caller can
	// Close the client safely.
	defer func() { cancel(); <-syncErr }()

	var txn id.VerificationTransactionID
	for {
		select {
		case <-ctx.Done():
			if txn != "" {
				_ = vh.CancelVerification(context.WithoutCancel(ctx), txn, event.VerificationCancelCodeTimeout, "timed out")
			}
			return ctx.Err()
		case err := <-syncErr:
			syncErr <- err // for the deferred wait
			return fmt.Errorf("rihma: sync stopped during verification: %w", err)
		case ev := <-cb.events:
			switch {
			case ev.requested:
				if txn != "" || ev.from != c.UserID || ev.fromDevice == c.DeviceID {
					_ = vh.DismissVerification(ctx, ev.txn)
					continue
				}
				txn = ev.txn
				if err := vh.AcceptVerification(ctx, txn); err != nil {
					return fmt.Errorf("rihma: accept verification: %w", err)
				}
			case ev.txn != txn:
				continue
			case ev.emoji != nil:
				if !confirm(ev.emoji) {
					_ = vh.CancelVerification(ctx, txn, event.VerificationCancelCodeSASMismatch, "the emoji did not match")
					return ErrSASMismatch
				}
				if err := vh.ConfirmSAS(ctx, txn); err != nil {
					return fmt.Errorf("rihma: confirm SAS: %w", err)
				}
			case ev.cancelled != "":
				return fmt.Errorf("%w: %s", ErrSASCancelled, ev.cancelled)
			case ev.done:
				return nil
			}
		}
	}
}

// sasEvent is one callback from the verification helper, carried to
// AwaitSAS's goroutine. The helper fires some callbacks while holding its
// own lock, so they must not call back into it or block.
type sasEvent struct {
	txn        id.VerificationTransactionID
	requested  bool
	from       id.UserID
	fromDevice id.DeviceID
	emoji      []SASEmoji
	cancelled  string
	done       bool
}

type sasCallbacks struct {
	events chan sasEvent
}

func (s *sasCallbacks) post(ev sasEvent) {
	select {
	case s.events <- ev:
	default: // AwaitSAS has returned or is far behind; never block the helper
	}
}

func (s *sasCallbacks) VerificationRequested(_ context.Context, txn id.VerificationTransactionID, from id.UserID, fromDevice id.DeviceID) {
	s.post(sasEvent{txn: txn, requested: true, from: from, fromDevice: fromDevice})
}

// VerificationReady needs nothing: the device that asked starts SAS.
func (s *sasCallbacks) VerificationReady(context.Context, id.VerificationTransactionID, id.DeviceID, bool, bool, *verificationhelper.QRCode) {
}

func (s *sasCallbacks) VerificationCancelled(_ context.Context, txn id.VerificationTransactionID, code event.VerificationCancelCode, reason string) {
	s.post(sasEvent{txn: txn, cancelled: fmt.Sprintf("%s (%s)", reason, code)})
}

func (s *sasCallbacks) VerificationDone(_ context.Context, txn id.VerificationTransactionID, _ event.VerificationMethod) {
	s.post(sasEvent{txn: txn, done: true})
}

func (s *sasCallbacks) ShowSAS(_ context.Context, txn id.VerificationTransactionID, emojis []rune, descriptions []string, _ []int) {
	out := make([]SASEmoji, len(emojis))
	for i, e := range emojis {
		out[i] = SASEmoji{Emoji: string(e), Description: descriptions[i]}
	}
	s.post(sasEvent{txn: txn, emoji: out})
}
