//go:build e2e

package rihma

// The live suite for the library, against the throwaway Synapse from
// `just synapse`. `just e2e` runs it. It never touches a real account.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func e2eHomeserver(t *testing.T) string {
	hs := os.Getenv("RIHMA_E2E_HS")
	if hs == "" {
		t.Skip("RIHMA_E2E_HS not set; run `just e2e`")
	}
	return hs
}

func e2eTag() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func register(t *testing.T, ctx context.Context, hs, localpart, password string) {
	t.Helper()
	cli, err := mautrix.NewClient(hs, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.RegisterDummy(ctx, &mautrix.ReqRegister[any]{
		Username: localpart, Password: password, InhibitLogin: true,
	}); err != nil {
		t.Fatalf("register %s (is `just synapse` up?): %v", localpart, err)
	}
}

// e2eOptions returns Options for a device of localpart whose state lives
// under dir, so reopening with the same dir resumes the same device.
func e2eOptions(t *testing.T, hs, localpart, password, dir string) Options {
	return Options{
		Homeserver: hs,
		StateDir:   filepath.Join(dir, "state"),
		Sessions:   FileSessionStore{Path: filepath.Join(dir, "session.json")},
		Login: &mautrix.ReqLogin{
			Type:       mautrix.AuthTypePassword,
			Identifier: mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: localpart},
			Password:   password,
		},
		DeviceName: "rihma e2e",
		Logger:     zerolog.New(zerolog.NewTestWriter(t)).Level(zerolog.WarnLevel).With().Str("user", localpart).Logger(),
	}
}

// running is a client with its sync loop going; stop cancels the loop,
// waits for it, and closes the client, in that order.
type running struct {
	*Client
	cancel context.CancelFunc
	done   chan error
}

func openAndSync(t *testing.T, ctx context.Context, opts Options, setup func(*Client)) *running {
	t.Helper()
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(c)
	}
	syncCtx, cancel := context.WithCancel(ctx)
	r := &running{Client: c, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- c.Sync(syncCtx) }()
	t.Cleanup(r.stop)
	return r
}

func (r *running) stop() {
	if r.cancel == nil {
		return
	}
	r.cancel()
	<-r.done
	r.Close()
	r.cancel = nil
}

// inbox records decrypted text messages from one sender.
type inbox struct {
	mu   sync.Mutex
	msgs []received
	from id.UserID
}

type received struct {
	body      string
	encrypted bool
}

func (in *inbox) attach(c *Client) {
	c.Handlers().OnEventType(event.EventMessage, func(_ context.Context, evt *event.Event) {
		if evt.Sender != in.from {
			return
		}
		in.mu.Lock()
		in.msgs = append(in.msgs, received{evt.Content.AsMessage().Body, evt.Mautrix.WasEncrypted})
		in.mu.Unlock()
	})
}

func (in *inbox) snapshot() []received {
	in.mu.Lock()
	defer in.mu.Unlock()
	return append([]received(nil), in.msgs...)
}

func (in *inbox) waitFor(t *testing.T, ctx context.Context, body string) {
	t.Helper()
	for {
		for _, m := range in.snapshot() {
			if m.body == body {
				if !m.encrypted {
					t.Fatalf("%q arrived unencrypted", body)
				}
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("never received %q; got %+v", body, in.snapshot())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func autoJoin(c *Client) {
	c.Handlers().OnEventType(event.StateMember, func(ctx context.Context, evt *event.Event) {
		if evt.GetStateKey() == c.UserID.String() && evt.Content.AsMember().Membership == event.MembershipInvite {
			c.JoinRoomByID(ctx, evt.RoomID)
		}
	})
}

func createEncryptedDM(t *testing.T, ctx context.Context, from *Client, to id.UserID) id.RoomID {
	t.Helper()
	resp, err := from.CreateRoom(ctx, &mautrix.ReqCreateRoom{
		Preset: "trusted_private_chat", IsDirect: true, Invite: []id.UserID{to},
		InitialState: []*event.Event{{
			Type:    event.StateEncryption,
			Content: event.Content{Parsed: &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp.RoomID
}

// waitJoined waits until c's state store shows user joined, so c's next
// encrypted send shares its session with user's devices.
func waitJoined(t *testing.T, ctx context.Context, c *Client, room id.RoomID, user id.UserID) {
	t.Helper()
	for {
		m, err := c.StateStore.GetMember(ctx, room, user)
		if err == nil && m != nil && m.Membership == event.MembershipJoin {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s never joined %s", user, room)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func TestE2EEncryptedDMRoundTrip(t *testing.T) {
	hs := e2eHomeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tag := e2eTag()
	botName, humanName := "bot-"+tag, "human-"+tag
	register(t, ctx, hs, botName, "pw-bot")
	register(t, ctx, hs, humanName, "pw-human")

	botIn := &inbox{}
	humanIn := &inbox{}
	var botRef *Client
	bot := openAndSync(t, ctx, e2eOptions(t, hs, botName, "pw-bot", t.TempDir()), func(c *Client) {
		botRef = c
		autoJoin(c)
		c.Handlers().OnEventType(event.EventMessage, func(ctx context.Context, evt *event.Event) {
			c.SendText(ctx, evt.RoomID, "echo: "+evt.Content.AsMessage().Body)
		})
	})
	human := openAndSync(t, ctx, e2eOptions(t, hs, humanName, "pw-human", t.TempDir()), func(c *Client) {
		humanIn.attach(c)
	})
	botIn.from, humanIn.from = human.UserID, botRef.UserID
	botIn.attach(bot.Client)

	if err := human.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	room := createEncryptedDM(t, ctx, human.Client, bot.UserID)
	waitJoined(t, ctx, human.Client, room, bot.UserID)

	text := "hello rihma " + tag
	if _, err := human.SendText(ctx, room, text); err != nil {
		t.Fatal(err)
	}
	botIn.waitFor(t, ctx, text)
	humanIn.waitFor(t, ctx, "echo: "+text)
	assertCiphertextOnWire(t, ctx, hs, human.AccessToken, room, text)
}

// TestE2EDiscardLiveAndDowntime: a message sent before the bot's first
// sync is history and must not be delivered; one sent while it syncs
// must be; one sent while it is stopped must be delivered on restart,
// decrypted, without replaying what it already saw.
func TestE2EDiscardLiveAndDowntime(t *testing.T) {
	hs := e2eHomeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	tag := e2eTag()
	botName, humanName := "bot-"+tag, "human-"+tag
	register(t, ctx, hs, botName, "pw-bot")
	register(t, ctx, hs, humanName, "pw-human")

	human := openAndSync(t, ctx, e2eOptions(t, hs, humanName, "pw-human", t.TempDir()), nil)
	if err := human.Connect(ctx); err != nil {
		t.Fatal(err)
	}

	// The bot logs in and joins over the API, but has never synced.
	botDir := t.TempDir()
	botOpts := e2eOptions(t, hs, botName, "pw-bot", botDir)
	bot, err := Open(ctx, botOpts)
	if err != nil {
		t.Fatal(err)
	}
	room := createEncryptedDM(t, ctx, human.Client, bot.UserID)
	if _, err := bot.JoinRoomByID(ctx, room); err != nil {
		t.Fatal(err)
	}
	botUser := bot.UserID
	bot.Close()
	waitJoined(t, ctx, human.Client, room, botUser)
	history := "history " + tag
	if _, err := human.SendText(ctx, room, history); err != nil {
		t.Fatal(err)
	}

	botOpts.Login = nil
	in := &inbox{from: human.UserID}
	first := openAndSync(t, ctx, botOpts, in.attach)
	// Let the first (discarding) sync land before sending live traffic.
	if err := first.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	live := "live " + tag
	if _, err := human.SendText(ctx, room, live); err != nil {
		t.Fatal(err)
	}
	in.waitFor(t, ctx, live)
	for _, m := range in.snapshot() {
		if m.body == history {
			t.Fatal("history from before the first sync was delivered")
		}
	}
	first.stop()

	downtime := "downtime " + tag
	if _, err := human.SendText(ctx, room, downtime); err != nil {
		t.Fatal(err)
	}
	in2 := &inbox{from: human.UserID}
	openAndSync(t, ctx, botOpts, in2.attach)
	in2.waitFor(t, ctx, downtime)
	time.Sleep(time.Second) // give a replay the chance to show itself
	for _, m := range in2.snapshot() {
		if m.body == live || m.body == history {
			t.Fatalf("warm restart replayed %q", m.body)
		}
	}
}

func TestE2ERecoveryKey(t *testing.T) {
	hs := e2eHomeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tag := e2eTag()
	name, pw := "bot-"+tag, "pw-bot"
	register(t, ctx, hs, name, pw)

	a, err := Open(ctx, e2eOptions(t, hs, name, pw, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	key, err := a.CreateRecoveryKey(ctx, pw)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := a.DeviceVerified(ctx); err != nil || !ok {
		t.Fatalf("device A verified after create = %v, %v", ok, err)
	}
	if _, err := a.CreateRecoveryKey(ctx, pw); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("second create = %v, want ErrIdentityExists", err)
	}

	b, err := Open(ctx, e2eOptions(t, hs, name, pw, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if ok, err := b.DeviceVerified(ctx); err != nil || ok {
		t.Fatalf("device B verified before restore = %v, %v; want false", ok, err)
	}
	if err := b.RestoreFromRecoveryKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if ok, err := b.DeviceVerified(ctx); err != nil || !ok {
		t.Fatalf("device B verified after restore = %v, %v", ok, err)
	}
}

// TestE2EResetIdentityWithPassword: Synapse takes a first identity with
// no auth, refuses a replacement without the password or with a wrong
// one (leaving the identity as it was), and takes it with the password.
// The new recovery key restores on another device; the old one does not.
func TestE2EResetIdentityWithPassword(t *testing.T) {
	hs := e2eHomeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tag := e2eTag()
	name, pw := "reset-"+tag, "pw-reset"
	register(t, ctx, hs, name, pw)

	a, err := Open(ctx, e2eOptions(t, hs, name, pw, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	oldKey, err := a.CreateRecoveryKey(ctx, "")
	if err != nil {
		t.Fatalf("first identity without a password: %v", err)
	}
	master := func() id.Ed25519 {
		t.Helper()
		resp, err := a.QueryKeys(ctx, &mautrix.ReqQueryKeys{DeviceKeys: mautrix.DeviceKeysRequest{a.UserID: mautrix.DeviceIDList{}}})
		if err != nil {
			t.Fatal(err)
		}
		k := resp.MasterKeys[a.UserID]
		return k.FirstKey()
	}
	before := master()

	if _, err := a.ResetCrossSigningIdentity(ctx, CrossSigningAuth{}); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("reset without a password = %v, want ErrPasswordRequired", err)
	}
	if _, err := a.ResetCrossSigningIdentity(ctx, CrossSigningAuth{Password: "wrong-" + pw}); !errors.Is(err, mautrix.MForbidden) {
		t.Fatalf("reset with a wrong password = %v, want M_FORBIDDEN", err)
	}
	if got := master(); got != before {
		t.Fatal("a refused reset replaced the master key")
	}

	newKey, err := a.ResetCrossSigningIdentity(ctx, CrossSigningAuth{Password: pw})
	if err != nil {
		t.Fatalf("reset with the password: %v", err)
	}
	if got := master(); got == before || got != a.OlmMachine().CrossSigningKeys.MasterKey.PublicKey() {
		t.Fatal("the server does not hold this device's new master key")
	}
	if ok, err := a.DeviceVerified(ctx); err != nil || !ok {
		t.Fatalf("device A verified after reset = %v, %v", ok, err)
	}

	b, err := Open(ctx, e2eOptions(t, hs, name, pw, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.RestoreFromRecoveryKey(ctx, oldKey); err == nil {
		t.Fatal("the old recovery key still restores after a reset")
	}
	if err := b.RestoreFromRecoveryKey(ctx, newKey); err != nil {
		t.Fatalf("restore with the new recovery key: %v", err)
	}
	if ok, err := b.DeviceVerified(ctx); err != nil || !ok {
		t.Fatalf("device B verified after restore = %v, %v", ok, err)
	}
}

// assertCiphertextOnWire reads the room timeline as raw JSON from the
// homeserver, bypassing mautrix, and checks that the messages are Megolm
// ciphertext and that the plaintext appears nowhere.
func assertCiphertextOnWire(t *testing.T, ctx context.Context, hs, token string, room id.RoomID, text string) {
	t.Helper()
	u := fmt.Sprintf("%s/_matrix/client/v3/rooms/%s/messages?dir=b&limit=50", strings.TrimRight(hs, "/"), url.PathEscape(room.String()))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("messages: %d %v", resp.StatusCode, err)
	}
	if strings.Contains(string(raw), text) {
		t.Fatal("plaintext found in the server's timeline")
	}
	var page struct {
		Chunk []struct {
			Type    string `json:"type"`
			Sender  string `json:"sender"`
			Content struct {
				Algorithm  string `json:"algorithm"`
				Ciphertext string `json:"ciphertext"`
			} `json:"content"`
		} `json:"chunk"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatal(err)
	}
	encrypted := 0
	for _, e := range page.Chunk {
		switch e.Type {
		case "m.room.message":
			t.Fatalf("cleartext m.room.message from %s on the wire", e.Sender)
		case "m.room.encrypted":
			if e.Content.Algorithm != string(id.AlgorithmMegolmV1) || e.Content.Ciphertext == "" {
				t.Fatalf("encrypted event from %s: algorithm %q, ciphertext %d bytes", e.Sender, e.Content.Algorithm, len(e.Content.Ciphertext))
			}
			encrypted++
		}
	}
	if encrypted != 2 {
		t.Fatalf("found %d m.room.encrypted events, want 2", encrypted)
	}
}

// TestE2EKeyBackup: device A creates the recovery key and the key backup,
// receives and sends encrypted messages, restarts, and receives in a new
// room. Device B, which never syncs, restores from the recovery key and
// decrypts all three from the server's raw events with backup keys alone.
func TestE2EKeyBackup(t *testing.T) {
	hs := e2eHomeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tag := e2eTag()
	botName, humanName := "bkbot-"+tag, "bkhuman-"+tag
	register(t, ctx, hs, botName, "pw-bot")
	register(t, ctx, hs, humanName, "pw-human")
	dirA := t.TempDir()
	botIn := &inbox{from: id.UserID("@" + humanName + ":localhost")}

	a := openAndSync(t, ctx, e2eOptions(t, hs, botName, "pw-bot", dirA), func(c *Client) { autoJoin(c); botIn.attach(c) })
	key, err := a.CreateRecoveryKey(ctx, "pw-bot")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.EnableKeyBackup(ctx, key); err != nil {
		t.Fatal(err)
	}
	version := a.KeyBackupVersion()
	if version == "" {
		t.Fatal("no backup version after EnableKeyBackup")
	}
	if err := a.EnableKeyBackup(ctx, key); !errors.Is(err, ErrBackupExists) {
		t.Fatalf("second EnableKeyBackup = %v, want ErrBackupExists", err)
	}

	human := openAndSync(t, ctx, e2eOptions(t, hs, humanName, "pw-human", t.TempDir()), nil)
	room := createEncryptedDM(t, ctx, human.Client, a.UserID)
	waitJoined(t, ctx, human.Client, room, a.UserID)
	received := sendText(t, ctx, human.Client, room, "secret one")
	botIn.waitFor(t, ctx, "secret one")
	waitJoined(t, ctx, a.Client, room, human.UserID)
	sent := sendText(t, ctx, a.Client, room, "from the bot")
	waitBackupCount(t, ctx, a.Client, 2)

	// After a restart the stored key keeps uploading: a new room means a
	// new room key.
	a.stop()
	a = openAndSync(t, ctx, e2eOptions(t, hs, botName, "pw-bot", dirA), func(c *Client) { autoJoin(c); botIn.attach(c) })
	if a.KeyBackupVersion() != version {
		t.Fatalf("backup version after restart = %q, want %q", a.KeyBackupVersion(), version)
	}
	room2 := createEncryptedDM(t, ctx, human.Client, a.UserID)
	waitJoined(t, ctx, human.Client, room2, a.UserID)
	later := sendText(t, ctx, human.Client, room2, "after the restart")
	botIn.waitFor(t, ctx, "after the restart")
	waitBackupCount(t, ctx, a.Client, 3)
	// Uploaded keys are marked, so each goes up once.
	for {
		left, err := a.OlmMachine().CryptoStore.GetGroupSessionsWithoutKeyBackupVersion(ctx, version).AsList()
		if err != nil {
			t.Fatal(err)
		}
		if len(left) == 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%d room keys never marked as backed up", len(left))
		case <-time.After(250 * time.Millisecond):
		}
	}
	// Other clients trust the backup through the master key's signature.
	latest, err := a.GetKeyBackupLatestVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := a.OlmMachine().GetOwnCrossSigningPublicKeys(ctx)
	if err != nil || pub == nil {
		t.Fatalf("own cross-signing public keys: %v, %v", pub, err)
	}
	master := pub.MasterKey
	if ok, err := signatures.VerifySignatureJSON(latest.AuthData, a.UserID, master.String(), master); err != nil || !ok {
		t.Fatalf("backup auth_data not signed by the master key: %v, %v", ok, err)
	}

	b, err := Open(ctx, e2eOptions(t, hs, botName, "pw-bot", t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.RestoreFromRecoveryKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := b.RestoreKeyBackup(ctx, key); err != nil {
		t.Fatal(err)
	}
	if b.KeyBackupVersion() != version {
		t.Fatalf("B adopted backup %q, want %q", b.KeyBackupVersion(), version)
	}
	for _, want := range []struct {
		room id.RoomID
		evt  id.EventID
		body string
	}{{room, received, "secret one"}, {room, sent, "from the bot"}, {room2, later, "after the restart"}} {
		evt, err := b.GetEvent(ctx, want.room, want.evt)
		if err != nil {
			t.Fatal(err)
		}
		if evt.Content.Parsed == nil {
			if err := evt.Content.ParseRaw(evt.Type); err != nil {
				t.Fatal(err)
			}
		}
		dec, err := b.OlmMachine().DecryptMegolmEvent(ctx, evt)
		if err != nil {
			t.Fatalf("B cannot decrypt %q from backup: %v", want.body, err)
		}
		if got := dec.Content.AsMessage().Body; got != want.body {
			t.Fatalf("decrypted %q, want %q", got, want.body)
		}
	}
}

func sendText(t *testing.T, ctx context.Context, c *Client, room id.RoomID, body string) id.EventID {
	t.Helper()
	resp, err := c.SendText(ctx, room, body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.EventID
}

// waitBackupCount waits until the server's backup holds at least n keys.
func waitBackupCount(t *testing.T, ctx context.Context, c *Client, n int) {
	t.Helper()
	for {
		v, err := c.GetKeyBackupLatestVersion(ctx)
		if err == nil && v.Count >= n {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the backup never reached %d keys (last: %+v, %v)", n, v, err)
		case <-time.After(250 * time.Millisecond):
		}
	}
}
