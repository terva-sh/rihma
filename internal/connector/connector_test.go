package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"

	"terva.sh/rihma"
)

// tervaHome points connsdk at a temporary TERVA_HOME. With sealed set,
// terva has an at-rest recipient, so SealedState really seals.
func tervaHome(t *testing.T, sealed bool) string {
	home := t.TempDir()
	t.Setenv("TERVA_HOME", home)
	if sealed {
		ident, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		cfg := map[string]any{"secrets": map[string]string{"recipient": ident.Recipient().String()}}
		data, _ := json.Marshal(cfg)
		if err := os.WriteFile(filepath.Join(home, "config.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func TestNewTransportRefusesProtocol1(t *testing.T) {
	tervaHome(t, false)
	_, err := NewTransport(connsdk.Session{Protocol: 1})
	if err == nil || !strings.Contains(err.Error(), "protocol 2") {
		t.Fatalf("NewTransport at protocol 1 = %v, want a protocol-floor error", err)
	}
}

func TestNewTransportRefusesUnconfigured(t *testing.T) {
	tervaHome(t, false)
	if Configured() {
		t.Fatal("Configured() true in an empty TERVA_HOME")
	}
	_, err := NewTransport(connsdk.Session{Protocol: 2})
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("NewTransport unconfigured = %v", err)
	}
}

// TestSessionSealedAtRest saves a session through the SessionStore and
// checks neither secret is readable in config.json, that they round trip,
// and that the declared paths are the ones sealed.
func TestSessionSealedAtRest(t *testing.T) {
	ctx := context.Background()
	tervaHome(t, true)
	if err := saveConfig(fileConfig{HomeserverURL: "https://hs.example"}); err != nil {
		t.Fatal(err)
	}
	const token = "syt_secret_token_value_123456"
	pickle := []byte("0123456789abcdef0123456789abcdef")
	backupKey := []byte("backup-private-key-32-bytes-long")
	if err := (sessionStore{}).Save(ctx, &rihma.Session{UserID: "@bot:hs.example", DeviceID: "DEV", AccessToken: token, PickleKey: pickle,
		BackupKey: backupKey, BackupVersion: "7"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(State.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token) {
		t.Fatal("access token readable in config.json")
	}
	var onDisk struct {
		Session struct {
			AccessToken string `json:"access_token"`
			PickleKey   string `json:"pickle_key"`
			BackupKey   string `json:"backup_key"`
		} `json:"session"`
	}
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"access_token": onDisk.Session.AccessToken, "pickle_key": onDisk.Session.PickleKey, "backup_key": onDisk.Session.BackupKey} {
		if !strings.HasPrefix(v, "enc:") {
			t.Errorf("session.%s on disk is not sealed: %.12q...", name, v)
		}
	}

	got, err := (sessionStore{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != token || string(got.PickleKey) != string(pickle) || got.UserID != "@bot:hs.example" || got.DeviceID != "DEV" ||
		string(got.BackupKey) != string(backupKey) || got.BackupVersion != "7" {
		t.Fatalf("round trip = %+v", got)
	}
	if !Configured() {
		t.Fatal("Configured() false with a stored session")
	}

	status, err := Status()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "key backup:  version 7") {
		t.Fatalf("status lacks the backup version:\n%s", status)
	}
	if strings.Contains(status, token) || strings.Contains(status, string(pickle)) || strings.Contains(status, string(backupKey)) {
		t.Fatalf("status shows a secret:\n%s", status)
	}

	if err := (sessionStore{}).Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := (sessionStore{}).Load(ctx); err != nil || got != nil {
		t.Fatalf("after Clear = %v, %v", got, err)
	}
}

// TestSecretsDeclared is terva's sealing gate, which only scans terva's
// own commands, restated for this module: the Config must declare the
// state it seals with.
func TestSecretsDeclared(t *testing.T) {
	cfg := Config()
	if cfg.Secrets == nil || cfg.Secrets.Name != Name || strings.Join(cfg.Secrets.Paths, ",") != strings.Join(sealedPaths, ",") {
		t.Fatalf("Config.Secrets = %+v, want the sealed state %v", cfg.Secrets, sealedPaths)
	}
	if cfg.Name != Name {
		t.Fatalf("Config.Name = %q", cfg.Name)
	}
}

func TestMaskToken(t *testing.T) {
	for tok, want := range map[string]string{
		"":                         "<hidden>",
		"short":                    "<hidden>",
		"syt_abcdefghijklmnop1234": "syt_...1234",
	} {
		if got := maskToken(tok); got != want {
			t.Errorf("maskToken(%q) = %q, want %q", tok, got, want)
		}
	}
}

func msgEvent(t *testing.T, content string) *event.Event {
	evt := &event.Event{
		Type: event.EventMessage, ID: "$evt", RoomID: "!room:hs", Sender: "@human:hs", Timestamp: 1700000000000,
		Content: event.Content{VeryRaw: json.RawMessage(content)},
	}
	if err := evt.Content.ParseRaw(evt.Type); err != nil {
		t.Fatal(err)
	}
	return evt
}

func TestTranslateMessage(t *testing.T) {
	tr := newTestTransport()
	tr.titles.set("!room:hs", "ops")
	tr.dms.set(event.DirectChatsEventContent{"@human:hs": {"!room:hs"}})

	m, ok := tr.translateMessage(context.Background(), msgEvent(t, `{"msgtype":"m.text","body":"hello"}`))
	if !ok || m.Text != "hello" || m.ID != "$evt" || m.ChatID != "!room:hs" || m.ChatKind != "dm" ||
		m.UserID != "@human:hs" || m.Username != "human" || m.TS != 1700000000000 || m.ReplyTo != "" {
		t.Fatalf("plain text = %+v, %v", m, ok)
	}

	m, ok = tr.translateMessage(context.Background(), msgEvent(t, `{"msgtype":"m.text","body":"> <@bot:hs> quoted\n\ngot it",
		"m.relates_to":{"m.in_reply_to":{"event_id":"$orig"}}}`))
	if !ok || m.Text != "got it" || m.ReplyTo != "$orig" {
		t.Fatalf("rich reply = %+v, %v; want fallback stripped and reply_to set", m, ok)
	}

	m, ok = tr.translateMessage(context.Background(), msgEvent(t, `{"msgtype":"m.text","body":"> not a fallback\n\nkept"}`))
	if !ok || m.Text != "> not a fallback\n\nkept" {
		t.Fatalf("a quote that is not a reply = %+v; must be kept", m)
	}

	m, ok = tr.translateMessage(context.Background(), msgEvent(t, `{"msgtype":"m.text","body":"\\/status"}`))
	if !ok || m.Text != "/status" {
		t.Fatalf("Element's escaped command = %q; want /status", m.Text)
	}
	m, _ = tr.translateMessage(context.Background(), msgEvent(t, `{"msgtype":"m.text","body":"see \\/etc"}`))
	if m.Text != `see \/etc` {
		t.Fatalf("an escape past the start = %q; must be kept", m.Text)
	}

	for _, drop := range []string{
		`{"msgtype":"m.notice","body":"bot noise"}`,
		`{"msgtype":"m.emote","body":"waves"}`,
		`{"msgtype":"m.text","body":"* edit","m.new_content":{"msgtype":"m.text","body":"edit"},"m.relates_to":{"rel_type":"m.replace","event_id":"$orig"}}`,
	} {
		if m, ok := tr.translateMessage(context.Background(), msgEvent(t, drop)); ok {
			t.Errorf("delivered %s as %+v", drop, m)
		}
	}

	if m.ChatTitle != "" || m.Entities != nil {
		t.Fatalf("a DM carries no title and, here, no entities: %+v", m)
	}

	tr.dms.set(event.DirectChatsEventContent{})
	m, _ = tr.translateMessage(context.Background(), msgEvent(t, `{"msgtype":"m.text","body":"hey Bot go","m.mentions":{"user_ids":["@bot:hs"]}}`))
	if m.ChatKind != "group" || m.ChatTitle != "ops" {
		t.Fatalf("group message = %+v, want kind group and title ops", m)
	}
	if len(m.Entities) != 1 || m.Entities[0] != (connsdk.Entity{Kind: "bot_mention", Offset: 4, Length: 3}) {
		t.Fatalf("entities = %+v, want a bot_mention on the display name", m.Entities)
	}

	tr.sent.add("$mine")
	m, _ = tr.translateMessage(context.Background(), msgEvent(t, `{"msgtype":"m.text","body":"> <@bot:hs> x\n\nthanks",
		"m.relates_to":{"m.in_reply_to":{"event_id":"$mine"}}}`))
	if len(m.Entities) != 1 || m.Entities[0] != (connsdk.Entity{Kind: "bot_mention"}) {
		t.Fatalf("reply to the bot: entities = %+v, want a bot_mention at 0/0", m.Entities)
	}
}

func TestLocalpart(t *testing.T) {
	if got := localpart(id.UserID("@bot:example.org")); got != "bot" {
		t.Fatalf("localpart = %q", got)
	}
}

// TestStatusReportsVerdict: no verdict reads as not recorded, never as
// unverified, and a verdict says which verb read it.
func TestStatusReportsVerdict(t *testing.T) {
	tervaHome(t, false)
	base := fileConfig{HomeserverURL: "https://hs.example", UserID: "@bot:hs.example", DeviceID: "DEV",
		Session: &sessionSecrets{AccessToken: "syt_abcdefghijklmnop1234", PickleKey: "cGlja2xl"}}
	for _, tc := range []struct{ verdict, source, want string }{
		{"", "", "e2ee:        not recorded"},
		{"unverified", "setup", "e2ee:        unverified (as of setup)"},
		{"verified", "verify", "e2ee:        verified (as of the last verify)"},
	} {
		cfg := base
		cfg.E2EE, cfg.E2EESource = tc.verdict, tc.source
		if err := saveConfig(cfg); err != nil {
			t.Fatal(err)
		}
		got, err := Status()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("verdict %q from %q: status lacks %q:\n%s", tc.verdict, tc.source, tc.want, got)
		}
	}
}
