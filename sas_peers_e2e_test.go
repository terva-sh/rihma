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

// The owner, driven by mautrix's helper solely as a test driver, asks the
// bot to verify on Synapse. The bot admits the request because the owner
// is in SASOptions.Peers, and drops a stranger's request sent just before
// it without a reply. The owner confirms first, so its MAC is held until
// the bot's person confirms; afterwards each side has signed the other's
// master key. Logs are captured at trace and never printed; no signature
// or recovery key may appear in them.
func TestE2EIncomingPeerSAS(t *testing.T) {
	hs := e2eHomeserver(t)
	u, err := url.Parse(hs)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || os.Getenv("RIHMA_E2E_DISPOSABLE") != "1" {
		t.Skip("owned loopback fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	quiet := zerolog.Nop().WithContext(ctx)
	tag := e2eTag()
	botName, ownerName, strangerName, pw := "inbot-"+tag, "inowner-"+tag, "instranger-"+tag, "pw-incoming-peer"
	for _, name := range []string{botName, ownerName, strangerName} {
		register(t, ctx, hs, name, pw)
	}
	logs := &lockedBuffer{}
	open := func(name string, logger zerolog.Logger) *Client {
		opts := e2eOptions(t, hs, name, pw, t.TempDir())
		opts.Logger = logger
		c, err := Open(ctx, opts)
		if err != nil {
			t.Fatal("open failed")
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	bot := open(botName, zerolog.New(logs).Level(zerolog.TraceLevel))
	owner, stranger := open(ownerName, zerolog.Nop()), open(strangerName, zerolog.Nop())
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
	driver := func(c *Client) (*verificationhelper.VerificationHelper, *sasPeerCallbacks) {
		cb := &sasPeerCallbacks{sasCallbacks: sasCallbacks{events: make(chan sasEvent, 32), overflow: make(chan struct{}, 1)}, ready: make(chan id.VerificationTransactionID, 4)}
		helper := verificationhelper.NewVerificationHelper(c.Client, c.OlmMachine(), verificationhelper.NewInMemoryVerificationStore(), cb, false, false, true)
		if err := helper.Init(quiet); err != nil {
			t.Fatal("driver helper failed")
		}
		return helper, cb
	}
	ownerHelper, ownerCB := driver(owner)
	strangerHelper, strangerCB := driver(stranger)

	s, err := bot.EnableSASWith(SASOptions{Peers: []id.UserID{owner.UserID}})
	if err != nil {
		t.Fatal("controller preparation failed")
	}
	runPolicySync(t, owner)
	runPolicySync(t, stranger)
	runPolicySync(t, bot)
	liveSASWait(t, ctx, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.started })

	// The stranger's request is sent first, so the bot's sync handles it
	// before the owner's.
	strangerTxn, err := strangerHelper.StartVerification(quiet, bot.UserID)
	if err != nil {
		t.Fatal("stranger request failed")
	}
	txn, err := ownerHelper.StartVerification(quiet, bot.UserID)
	if err != nil {
		t.Fatal("owner request failed")
	}
	liveSASWait(t, ctx, func() bool { got := s.Snapshot(); return got.State == SASRequested && got.TransactionID == txn })
	if got := s.Snapshot(); got.OtherUser != owner.UserID || got.OtherDevice != owner.DeviceID {
		t.Fatal("the requested snapshot does not name the owner's device")
	}
	s.gate.mu.Lock()
	_, strangerAdmitted := s.gate.recent[strangerTxn]
	s.gate.mu.Unlock()
	if strangerAdmitted {
		t.Fatal("the stranger's request passed the gate")
	}
	if err := s.Accept(ctx, txn); err != nil {
		t.Fatalf("accept: %v", err)
	}
	select {
	case ready := <-ownerCB.ready:
		if ready != txn {
			t.Fatal("ready for another transaction")
		}
	case <-ctx.Done():
		t.Fatal("the owner did not see the bot's ready")
	}
	if err := ownerHelper.StartSAS(quiet, txn); err != nil {
		t.Fatal("owner SAS start failed")
	}
	var ownerEmoji []SASEmoji
	for ownerEmoji == nil {
		select {
		case ev := <-ownerCB.events:
			if ev.txn == txn && ev.emoji != nil {
				ownerEmoji = ev.emoji
			}
		case <-ctx.Done():
			t.Fatal("the owner did not show emoji")
		}
	}
	liveSASWait(t, ctx, func() bool { return s.Snapshot().State == SASShowing })
	shown := s.Snapshot()
	if len(shown.Emoji) != 7 || len(ownerEmoji) != 7 {
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
	if got := s.Snapshot(); got.State != SASDone || got.MasterKey != ownerKey || got.OtherUser != owner.UserID {
		t.Fatalf("bot outcome = %v/%s, master key matches: %v", got.State, got.Reason, got.MasterKey == ownerKey)
	}
	done := false
	for !done {
		select {
		case ev := <-ownerCB.events:
			done = ev.done && ev.txn == txn
		case <-ctx.Done():
			t.Fatal("the owner did not reach done")
		}
	}

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

	// The stranger, whose request reached the bot before the owner's, heard
	// nothing back in all that time.
	for {
		select {
		case ev := <-strangerCB.events:
			if ev.txn == strangerTxn {
				t.Fatal("the bot answered the stranger")
			}
			continue
		case <-strangerCB.ready:
			t.Fatal("the bot sent the stranger a ready")
		default:
		}
		break
	}
}
