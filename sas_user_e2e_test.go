//go:build e2e

package rihma

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/id"
)

// A bot verifies its owner, another user, with StartUser on Synapse. The
// owner is driven by mautrix's helper solely as a test driver, and confirms
// first, so its MAC reaches the bot before the bot's person answers: the
// order the gate holds the MAC for. Afterwards each side has signed the
// other's master key. Logs are captured at trace and never printed; no
// signature or recovery key may appear in them.
func TestE2EStartUserSAS(t *testing.T) {
	hs := e2eHomeserver(t)
	u, err := url.Parse(hs)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || os.Getenv("RIHMA_E2E_DISPOSABLE") != "1" {
		t.Skip("owned loopback fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tag := e2eTag()
	botName, ownerName, pw := "sasbot-"+tag, "sasowner-"+tag, "pw-sas-user"
	register(t, ctx, hs, botName, pw)
	register(t, ctx, hs, ownerName, pw)

	logs := &lockedBuffer{}
	botOpts := e2eOptions(t, hs, botName, pw, t.TempDir())
	botOpts.Logger = zerolog.New(logs).Level(zerolog.TraceLevel)
	bot, err := Open(ctx, botOpts)
	if err != nil {
		t.Fatal("bot open failed")
	}
	t.Cleanup(func() { bot.Close() })
	ownerOpts := e2eOptions(t, hs, ownerName, pw, t.TempDir())
	ownerOpts.Logger = zerolog.Nop()
	owner, err := Open(ctx, ownerOpts)
	if err != nil {
		t.Fatal("owner open failed")
	}
	t.Cleanup(func() { owner.Close() })
	recovery, err := bot.CreateRecoveryKey(ctx, pw)
	if err != nil {
		t.Fatal("bot identity creation failed")
	}
	if _, err := owner.CreateRecoveryKey(ctx, pw); err != nil {
		t.Fatal("owner identity creation failed")
	}
	ownerKey, err := owner.OwnMasterKey(ctx)
	if err != nil {
		t.Fatal("owner key failed")
	}

	ownerCB := &sasPeerCallbacks{sasCallbacks: sasCallbacks{events: make(chan sasEvent, 32), overflow: make(chan struct{}, 1)}, ready: make(chan id.VerificationTransactionID, 4)}
	ownerHelper := verificationhelper.NewVerificationHelper(owner.Client, owner.OlmMachine(), verificationhelper.NewInMemoryVerificationStore(), ownerCB, false, false, true)
	if err := ownerHelper.Init(zerolog.Nop().WithContext(ctx)); err != nil {
		t.Fatal("owner helper failed")
	}
	var ownerEvents []sasEvent
	ownerSaw := func(match func(sasEvent) bool) sasEvent {
		t.Helper()
		for {
			for _, ev := range ownerEvents {
				if match(ev) {
					return ev
				}
			}
			select {
			case ev := <-ownerCB.events:
				ownerEvents = append(ownerEvents, ev)
			case <-ctx.Done():
				t.Fatal("the owner's helper did not reach the expected stage")
			}
		}
	}
	s, err := bot.EnableSAS()
	if err != nil {
		t.Fatal("controller preparation failed")
	}
	runPolicySync(t, owner)
	runPolicySync(t, bot)
	liveSASWait(t, ctx, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.started })

	txn, err := s.StartUser(ctx, owner.UserID)
	if err != nil {
		t.Fatalf("start user: %v", err)
	}
	ownerSaw(func(ev sasEvent) bool { return ev.requested && ev.txn == txn && ev.from == bot.UserID })
	quiet := zerolog.Nop().WithContext(ctx)
	if err := ownerHelper.AcceptVerification(quiet, txn); err != nil {
		t.Fatal("owner accept failed")
	}
	liveSASWait(t, ctx, func() bool { return s.Snapshot().State == SASShowing })
	ownerEmoji := ownerSaw(func(ev sasEvent) bool { return ev.txn == txn && ev.emoji != nil }).emoji
	shown := s.Snapshot()
	if shown.OtherUser != owner.UserID || len(shown.Emoji) != 7 || len(ownerEmoji) != 7 {
		t.Fatal("emoji were not shown on both sides")
	}
	for i := range ownerEmoji {
		if ownerEmoji[i] != shown.Emoji[i] {
			t.Fatal("the emoji differ between the sides")
		}
	}
	if err := ownerHelper.ConfirmSAS(quiet, txn); err != nil {
		t.Fatal("owner confirm failed")
	}
	// Give the owner's MAC time to reach the bot, where it is held.
	time.Sleep(2 * time.Second)
	if got := s.Snapshot(); got.State != SASShowing {
		t.Fatalf("the owner's MAC changed the attempt before the bot confirmed: %v", got.State)
	}
	if err := s.Confirm(ctx, txn, true); err != nil {
		t.Fatalf("bot confirm: %v", err)
	}
	liveSASWait(t, ctx, func() bool { st := s.Snapshot().State; return st == SASDone || st == SASFailed || st == SASCancelled })
	if got := s.Snapshot(); got.State != SASDone || got.MasterKey != ownerKey {
		t.Fatalf("bot outcome = %v/%s, master key matches: %v", got.State, got.Reason, got.MasterKey == ownerKey)
	}
	ownerSaw(func(ev sasEvent) bool { return ev.done && ev.txn == txn })

	ident, err := bot.UserIdentity(ctx, owner.UserID)
	if err != nil || !ident.SignedByUs || ident.MasterKey != ownerKey {
		t.Fatalf("the owner's identity after SAS: signed %v, %v", ident != nil && ident.SignedByUs, err)
	}
	if ident, err := owner.UserIdentity(ctx, bot.UserID); err != nil || !ident.SignedByUs {
		t.Fatalf("the bot's identity as the owner sees it: signed %v, %v", ident != nil && ident.SignedByUs, err)
	}
	resp, err := bot.QueryKeys(ctx, &mautrix.ReqQueryKeys{DeviceKeys: mautrix.DeviceKeysRequest{bot.UserID: {}, owner.UserID: {}}})
	if err != nil {
		t.Fatal("key query failed")
	}
	botUSK := resp.UserSigningKeys[bot.UserID]
	usk := id.NewKeyID(id.KeyAlgorithmEd25519, botUSK.FirstKey().String())
	signature := resp.MasterKeys[owner.UserID].Signatures[bot.UserID][usk]
	if signature == "" {
		t.Fatal("the server holds no signature by the bot's user-signing key")
	}
	if logs.contains(signature) || logs.contains(recovery) {
		t.Fatal("a signature or recovery key reached the logs")
	}
}

// VerifyUser on Synapse: the bot is stopped, runs its own Sync, and its
// operator's confirm answers only after the owner has confirmed, so the
// owner's MAC is held. It returns the owner's master key, signed.
func TestE2EVerifyUser(t *testing.T) {
	hs := e2eHomeserver(t)
	u, err := url.Parse(hs)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || os.Getenv("RIHMA_E2E_DISPOSABLE") != "1" {
		t.Skip("owned loopback fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tag := e2eTag()
	botName, ownerName, pw := "vubot-"+tag, "vuowner-"+tag, "pw-verify-user"
	register(t, ctx, hs, botName, pw)
	register(t, ctx, hs, ownerName, pw)
	open := func(name string) *Client {
		opts := e2eOptions(t, hs, name, pw, t.TempDir())
		opts.Logger = zerolog.Nop()
		c, err := Open(ctx, opts)
		if err != nil {
			t.Fatal("open failed")
		}
		t.Cleanup(func() { c.Close() })
		if _, err := c.CreateRecoveryKey(ctx, pw); err != nil {
			t.Fatal("identity creation failed")
		}
		return c
	}
	bot, owner := open(botName), open(ownerName)
	ownerKey, err := owner.OwnMasterKey(ctx)
	if err != nil {
		t.Fatal("owner key failed")
	}
	ownerCB := &sasPeerCallbacks{sasCallbacks: sasCallbacks{events: make(chan sasEvent, 32), overflow: make(chan struct{}, 1)}, ready: make(chan id.VerificationTransactionID, 4)}
	ownerHelper := verificationhelper.NewVerificationHelper(owner.Client, owner.OlmMachine(), verificationhelper.NewInMemoryVerificationStore(), ownerCB, false, false, true)
	quiet := zerolog.Nop().WithContext(ctx)
	if err := ownerHelper.Init(quiet); err != nil {
		t.Fatal("owner helper failed")
	}
	runPolicySync(t, owner)
	// The owner's side runs on its own goroutine: accept the request, and
	// report the emoji it shows.
	ownerEmoji := make(chan []SASEmoji, 1)
	accepted := make(chan id.VerificationTransactionID, 1)
	go func() {
		for {
			select {
			case ev := <-ownerCB.events:
				switch {
				case ev.requested && ev.from == bot.UserID:
					if ownerHelper.AcceptVerification(quiet, ev.txn) != nil {
						return
					}
					accepted <- ev.txn
				case ev.emoji != nil:
					ownerEmoji <- ev.emoji
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	confirms := 0
	key, err := bot.VerifyUser(ctx, owner.UserID, func(emoji []SASEmoji) bool {
		confirms++
		var theirs []SASEmoji
		var txn id.VerificationTransactionID
		select {
		case txn = <-accepted:
		case <-ctx.Done():
			return false
		}
		select {
		case theirs = <-ownerEmoji:
		case <-ctx.Done():
			return false
		}
		if len(emoji) != 7 || len(theirs) != 7 {
			return false
		}
		for i := range emoji {
			if emoji[i] != theirs[i] {
				return false
			}
		}
		if ownerHelper.ConfirmSAS(quiet, txn) != nil {
			return false
		}
		time.Sleep(2 * time.Second) // the owner's MAC reaches the bot first
		return true
	})
	if err != nil || key != ownerKey || confirms != 1 {
		t.Fatalf("VerifyUser = key matches %v, %v, confirms %d", key == ownerKey, err, confirms)
	}
	if ident, err := owner.UserIdentity(ctx, bot.UserID); err != nil || !ident.SignedByUs {
		t.Fatal("the owner did not sign the bot")
	}
	if ident, err := bot.UserIdentity(ctx, owner.UserID); err != nil || !ident.SignedByUs {
		t.Fatal("the bot did not sign the owner")
	}
}
