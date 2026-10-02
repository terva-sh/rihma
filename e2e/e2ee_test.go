//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connproto"

	"terva.sh/rihma"
)

// openEncryptedDM has the human create an is_direct room with encryption
// on from the start and waits for the bot to join, because a sender
// shares the room key only with the devices it can see at send time.
func openEncryptedDM(t *testing.T, ctx context.Context, hu *human, bot id.UserID) id.RoomID {
	t.Helper()
	resp, err := hu.CreateRoom(ctx, &mautrix.ReqCreateRoom{
		Preset: "trusted_private_chat", IsDirect: true, Invite: []id.UserID{bot},
		InitialState: []*event.Event{{
			Type:    event.StateEncryption,
			Content: event.Content{Parsed: &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	waitJoined(t, ctx, hu.Client, resp.RoomID, bot)
	return resp.RoomID
}

// wireType is the event's type as the server stores it, read without
// decrypting: m.room.encrypted proves only ciphertext crossed the wire.
func wireType(t *testing.T, ctx context.Context, c *rihma.Client, room id.RoomID, evt id.EventID) string {
	t.Helper()
	got, err := c.GetEvent(ctx, room, evt)
	if err != nil {
		t.Fatal(err)
	}
	return got.Type.Type
}

func status(t *testing.T, home string) string {
	t.Helper()
	out, code := verb(t, home, "", "status")
	if code != 0 {
		t.Fatalf("status exited %d:\n%s", code, out)
	}
	return out
}

// recoveryKey reads the key setup printed once.
func recoveryKey(t *testing.T, setupOut string) string {
	t.Helper()
	_, after, ok := strings.Cut(setupOut, "recovery key (shown once")
	if !ok {
		t.Fatalf("setup printed no recovery key:\n%s", setupOut)
	}
	for _, line := range strings.Split(after, "\n")[1:] {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	t.Fatal("recovery key line is empty")
	return ""
}

// storedToken reads the bot's access token from config.json, which is
// plaintext here because the test TERVA_HOME has no sealing recipient.
func storedToken(t *testing.T, home string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home, "connectors", "rihma", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Session struct {
			AccessToken string `json:"access_token"`
		} `json:"session"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg.Session.AccessToken == "" {
		t.Fatalf("no access_token in config.json (%v)", err)
	}
	return cfg.Session.AccessToken
}

// TestEncryptedDMRoundTrip ports encrypted_dm_round_trip: setup's
// default creates the recovery key and verifies the device; messages both
// ways are ciphertext on the server; what arrived while the connector was
// down decrypts on reconnect; reset kills the token server-side.
func TestEncryptedDMRoundTrip(t *testing.T) {
	hs := homeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	tg := tag()
	botLocal := "encbot-" + tg
	bot := id.UserID("@" + botLocal + ":localhost")
	register(t, ctx, hs, botLocal, "bot-pw")
	home := t.TempDir()
	out := provision(t, home, hs, bot.String(), "bot-pw")
	recoveryKey(t, out)
	if !strings.Contains(out, "key backup: enabled, version ") {
		t.Fatalf("setup enabled no key backup:\n%s", out)
	}
	if st := status(t, home); !strings.Contains(st, "e2ee:        verified (as of setup)") || !strings.Contains(st, "key backup:  version ") {
		t.Fatalf("status after a default setup:\n%s", st)
	}
	hu := newHuman(t, ctx, hs, "encdrew-"+tg, "human-pw", bot)

	conn := spawn(t, home)
	conn.handshake()
	room := openEncryptedDM(t, ctx, hu, bot)

	helloID := hu.send(t, ctx, room, text("secret hello"))
	m := conn.expect("the decrypted message", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "message" && f["id"] == helloID.String()
	})
	if str(m, "text") != "secret hello" || str(m, "chat_kind") != "dm" {
		t.Fatalf("decrypted message = %v", m)
	}
	if typ := wireType(t, ctx, hu.Client, room, helloID); typ != "m.room.encrypted" {
		t.Fatalf("the human's message is %s on the server", typ)
	}

	conn.write(connproto.SendFromHost{Type: "send", ID: "enc-1", ChatID: room.String(), Text: "**classified** reply"})
	r := conn.expect("result enc-1", 30*time.Second, func(f map[string]any) bool { return f["type"] == "result" && f["id"] == "enc-1" })
	if str(r, "error") != "" {
		t.Fatalf("result enc-1 = %v", r)
	}
	botEvt := id.EventID(str(r, "message_id"))
	if got := hu.waitSeen(t, ctx, "the encrypted reply", func(s seenMsg) bool { return s.id == botEvt }); got.body != "**classified** reply" {
		t.Fatalf("reply body = %q", got.body)
	}
	if typ := wireType(t, ctx, hu.Client, room, botEvt); typ != "m.room.encrypted" {
		t.Fatalf("the bot's reply is %s on the server", typ)
	}
	conn.shutdown()

	missed := hu.send(t, ctx, room, text("encrypted while away"))
	conn = spawn(t, home)
	conn.handshake()
	m = conn.expect("the missed encrypted message", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "message" && f["id"] == missed.String()
	})
	if str(m, "text") != "encrypted while away" {
		t.Fatalf("missed message = %v", m)
	}
	fresh := hu.send(t, ctx, room, text("fresh encrypted"))
	conn.expect("a fresh encrypted message", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "message" && f["id"] == fresh.String() && f["text"] == "fresh encrypted"
	})
	conn.shutdown()

	// reset logs the device out on the server before wiping.
	token := storedToken(t, home)
	if out, code := verb(t, home, "", "reset"); code != 0 {
		t.Fatalf("reset exited %d:\n%s", code, out)
	}
	if _, code := verb(t, home, "", "configured"); code == 0 {
		t.Fatal("configured still true after reset")
	}
	old, err := mautrix.NewClient(hs, bot, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Whoami(ctx); !errors.Is(err, mautrix.MUnknownToken) {
		t.Fatalf("the old token after reset: %v, want M_UNKNOWN_TOKEN", err)
	}
}

func masterKey(t *testing.T, ctx context.Context, c *rihma.Client, user id.UserID) string {
	t.Helper()
	resp, err := c.QueryKeys(ctx, &mautrix.ReqQueryKeys{DeviceKeys: mautrix.DeviceKeysRequest{user: mautrix.DeviceIDList{}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range resp.MasterKeys[user].Keys {
		return k.String()
	}
	return ""
}

// TestSetupNeverReplacesAnIdentity: a second device's setup with the
// default [1] refuses to replace the account's identity and leaves the
// device unverified; [2] with the recovery key verifies it.
func TestSetupNeverReplacesAnIdentity(t *testing.T) {
	hs := homeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	tg := tag()
	botLocal := "idbot-" + tg
	bot := id.UserID("@" + botLocal + ":localhost")
	register(t, ctx, hs, botLocal, "bot-pw")
	key := recoveryKey(t, provision(t, t.TempDir(), hs, bot.String(), "bot-pw"))
	hu := newHuman(t, ctx, hs, "idwatch-"+tg, "human-pw", bot)
	before := masterKey(t, ctx, hu.Client, bot)
	if before == "" {
		t.Fatal("no master key after the first setup")
	}

	second := t.TempDir()
	out := provision(t, second, hs, bot.String(), "bot-pw", "1", "n")
	if !strings.Contains(out, "already has a cross-signing identity") || strings.Contains(out, "recovery key (shown once") {
		t.Fatalf("setup [1] on an account with an identity:\n%s", out)
	}
	if after := masterKey(t, ctx, hu.Client, bot); after != before {
		t.Fatalf("master key changed from %s to %s", before, after)
	}
	if st := status(t, second); !strings.Contains(st, "e2ee:        unverified (as of setup)") || !strings.Contains(st, "key backup:  none") {
		t.Fatalf("status after a refused create:\n%s", st)
	}

	third := t.TempDir()
	out = provision(t, third, hs, bot.String(), "bot-pw", "2", key)
	if strings.Contains(out, key) {
		t.Fatal("setup echoed the recovery key")
	}
	if !strings.Contains(out, ": verified") || !strings.Contains(out, "key backup: restored version ") {
		t.Fatalf("setup [2] with the recovery key:\n%s", out)
	}
	if st := status(t, third); !strings.Contains(st, "key backup:  version ") {
		t.Fatalf("status after a restore:\n%s", st)
	}
	if out, code := verb(t, third, "", "verify"); code != 0 || !strings.Contains(out, ": verified") {
		t.Fatalf("verify after restore exited %d:\n%s", code, out)
	}
}

// interactive runs a verb with a live stdin, for prompts.
type interactive struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	mu    sync.Mutex
	out   strings.Builder
	done  chan error
}

func startVerb(t *testing.T, home string, args ...string) *interactive {
	t.Helper()
	cmd := exec.Command(runSh(t), args...)
	cmd.Env = append(os.Environ(), "TERVA_HOME="+home)
	stdin, _ := cmd.StdinPipe()
	p := &interactive{cmd: cmd, stdin: stdin, done: make(chan error, 1)}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			p.mu.Lock()
			p.out.Write(buf[:n])
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	go func() { err := cmd.Wait(); pw.Close(); p.done <- err }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return p
}

func (p *interactive) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

func (p *interactive) waitFor(t *testing.T, substr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !strings.Contains(p.output(), substr) {
		if time.Now().After(deadline) {
			t.Fatalf("never saw %q in:\n%s", substr, p.output())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (p *interactive) answer(t *testing.T, line string) {
	t.Helper()
	if _, err := io.WriteString(p.stdin, line+"\n"); err != nil {
		t.Fatal(err)
	}
}

func (p *interactive) wait(t *testing.T, timeout time.Duration) int {
	t.Helper()
	select {
	case err := <-p.done:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	case <-time.After(timeout):
		t.Fatalf("the verb did not exit:\n%s", p.output())
		return -1
	}
}

// sasInitiator is another device on the bot's account, holding the
// cross-signing keys through the recovery key, that starts an emoji
// verification and confirms whatever it is shown.
type sasInitiator struct {
	vh    *verificationhelper.VerificationHelper
	mu    sync.Mutex
	emoji []string
	done  chan struct{}
}

func (s *sasInitiator) VerificationRequested(context.Context, id.VerificationTransactionID, id.UserID, id.DeviceID) {
}
func (s *sasInitiator) VerificationReady(ctx context.Context, txn id.VerificationTransactionID, _ id.DeviceID, sas, _ bool, _ *verificationhelper.QRCode) {
	go func() { _ = s.vh.StartSAS(context.WithoutCancel(ctx), txn) }()
}
func (s *sasInitiator) VerificationCancelled(context.Context, id.VerificationTransactionID, event.VerificationCancelCode, string) {
}
func (s *sasInitiator) VerificationDone(context.Context, id.VerificationTransactionID, event.VerificationMethod) {
	close(s.done)
}
func (s *sasInitiator) ShowSAS(ctx context.Context, txn id.VerificationTransactionID, emojis []rune, desc []string, _ []int) {
	s.mu.Lock()
	s.emoji = slices.Clone(desc)
	s.mu.Unlock()
	go func() { _ = s.vh.ConfirmSAS(context.WithoutCancel(ctx), txn) }()
}

func newSASInitiator(t *testing.T, ctx context.Context, hs, localpart, password, key string) *sasInitiator {
	t.Helper()
	dir := t.TempDir()
	c, err := rihma.Open(ctx, rihma.Options{
		Homeserver: hs,
		StateDir:   filepath.Join(dir, "state"),
		Sessions:   rihma.FileSessionStore{Path: filepath.Join(dir, "session.json")},
		Login: &mautrix.ReqLogin{
			Type:       mautrix.AuthTypePassword,
			Identifier: mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: localpart},
			Password:   password,
		},
		DeviceName: "e2e-verifier",
		Logger:     zerolog.New(zerolog.NewTestWriter(t)).Level(zerolog.WarnLevel),
	})
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		if err := c.RestoreFromRecoveryKey(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	s := &sasInitiator{done: make(chan struct{})}
	s.vh = verificationhelper.NewVerificationHelper(c.Client, c.OlmMachine(), verificationhelper.NewInMemoryVerificationStore(), s, false, false, true)
	if err := s.vh.Init(ctx); err != nil {
		t.Fatal(err)
	}
	syncCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); c.Sync(syncCtx) }()
	t.Cleanup(func() { cancel(); <-done; c.Close() })
	return s
}

// TestVerifyBySAS: a device skipped at setup is unverified; verify will
// not sync beside a running connector; once it is stopped, verify answers
// an emoji verification from another device, both sides show the same
// emoji, and the device ends verified.
func TestVerifyBySAS(t *testing.T) {
	hs := homeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tg := tag()
	botLocal := "sasbot-" + tg
	bot := id.UserID("@" + botLocal + ":localhost")
	register(t, ctx, hs, botLocal, "bot-pw")
	key := recoveryKey(t, provision(t, t.TempDir(), hs, bot.String(), "bot-pw"))

	home := t.TempDir()
	provision(t, home, hs, bot.String(), "bot-pw", "3", "n")
	if st := status(t, home); !strings.Contains(st, "e2ee:        unverified (as of setup)") {
		t.Fatalf("status after a skipped setup:\n%s", st)
	}

	// Not beside a running connector.
	conn := spawn(t, home)
	conn.handshake()
	v := startVerb(t, home, "verify")
	v.waitFor(t, "[y/N]: ", 60*time.Second)
	v.answer(t, "y")
	v.waitFor(t, "the connector is running", 30*time.Second)
	if code := v.wait(t, 30*time.Second); code == 0 {
		t.Fatalf("verify exited 0 with the device unverified:\n%s", v.output())
	}
	conn.shutdown()

	v = startVerb(t, home, "verify")
	v.waitFor(t, "[y/N]: ", 60*time.Second)
	v.answer(t, "y")
	v.waitFor(t, "waiting up to", 30*time.Second)
	// A request from another user comes first and must be declined, or
	// it would take the place of the bot's own device's request.
	register(t, ctx, hs, "stranger-"+tg, "stranger-pw")
	stranger := newSASInitiator(t, ctx, hs, "stranger-"+tg, "stranger-pw", "")
	if _, err := stranger.vh.StartVerification(ctx, bot); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	initiator := newSASInitiator(t, ctx, hs, botLocal, "bot-pw", key)
	if _, err := initiator.vh.StartVerification(ctx, bot); err != nil {
		t.Fatal(err)
	}
	v.waitFor(t, "do the emoji match", 90*time.Second)
	// Each side derives its emoji on its own after the key exchange, so
	// the initiator may show them a moment after verify does.
	var theirs []string
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		initiator.mu.Lock()
		theirs = initiator.emoji
		initiator.mu.Unlock()
		if len(theirs) > 0 || time.Now().After(deadline) {
			break
		}
	}
	if len(theirs) != 7 {
		t.Fatalf("the initiator saw %d emoji", len(theirs))
	}
	shown := v.output()
	for _, d := range theirs {
		if !strings.Contains(shown, d) {
			t.Fatalf("verify did not show %q, which the other device shows:\n%s", d, shown)
		}
	}
	v.answer(t, "y")
	if code := v.wait(t, 90*time.Second); code != 0 {
		t.Fatalf("verify exited %d:\n%s", code, v.output())
	}
	select {
	case <-initiator.done:
	case <-time.After(30 * time.Second):
		t.Fatal("the initiator never saw the verification finish")
	}
	if !strings.Contains(v.output(), fmt.Sprintf(": %s", rihma.Verified)) {
		t.Fatalf("verify did not end verified:\n%s", v.output())
	}
	if st := status(t, home); !strings.Contains(st, "e2ee:        verified (as of the last verify)") {
		t.Fatalf("status after verify:\n%s", st)
	}
}
