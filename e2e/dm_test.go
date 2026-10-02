//go:build e2e

package e2e

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connproto"

	"terva.sh/rihma"
)

// human is the person on the other side, a rihma client recording what
// the bot sends and whether it is typing.
type human struct {
	*rihma.Client
	bot id.UserID
	// plain allows bot messages that arrive unencrypted, for scenarios
	// in unencrypted rooms; otherwise every one must be encrypted.
	plain bool

	mu     sync.Mutex
	seen   []seenMsg
	typing bool
}

type seenMsg struct {
	id            id.EventID
	body          string
	formattedBody string
	encrypted     bool
	content       *event.MessageEventContent
}

func newHuman(t *testing.T, ctx context.Context, hs, localpart, password string, bot id.UserID) *human {
	t.Helper()
	register(t, ctx, hs, localpart, password)
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
		Logger: zerolog.New(zerolog.NewTestWriter(t)).Level(zerolog.WarnLevel),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := &human{Client: c, bot: bot}
	c.Handlers().OnEventType(event.EventMessage, func(_ context.Context, evt *event.Event) {
		if evt.Sender != bot {
			return
		}
		msg := evt.Content.AsMessage()
		h.mu.Lock()
		h.seen = append(h.seen, seenMsg{id: evt.ID, body: msg.Body, formattedBody: msg.FormattedBody, encrypted: evt.Mautrix.WasEncrypted, content: msg})
		h.mu.Unlock()
	})
	c.Handlers().OnEventType(event.EphemeralEventTyping, func(_ context.Context, evt *event.Event) {
		content := evt.Content.AsTyping()
		h.mu.Lock()
		h.typing = slices.Contains(content.UserIDs, bot)
		h.mu.Unlock()
	})
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	syncCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); c.Sync(syncCtx) }()
	t.Cleanup(func() { cancel(); <-done; c.Close() })
	return h
}

func (h *human) waitSeen(t *testing.T, ctx context.Context, what string, pred func(seenMsg) bool) seenMsg {
	t.Helper()
	for {
		h.mu.Lock()
		for _, m := range h.seen {
			if pred(m) {
				h.mu.Unlock()
				if !m.encrypted && !h.plain {
					t.Fatalf("%s arrived unencrypted in an encrypted DM", what)
				}
				return m
			}
		}
		h.mu.Unlock()
		select {
		case <-ctx.Done():
			t.Fatalf("human never saw %s", what)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (h *human) waitTyping(t *testing.T, want bool, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		h.mu.Lock()
		got := h.typing
		h.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("bot typing never became %v", want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (h *human) send(t *testing.T, ctx context.Context, room id.RoomID, content *event.MessageEventContent) id.EventID {
	t.Helper()
	resp, err := h.SendMessageEvent(ctx, room, event.EventMessage, content)
	if err != nil {
		t.Fatal(err)
	}
	return resp.EventID
}

func text(body string) *event.MessageEventContent {
	return &event.MessageEventContent{MsgType: event.MsgText, Body: body}
}

func str(f map[string]any, k string) string { s, _ := f[k].(string); return s }

// TestDMRoundTripCompliance ports dm_round_trip_compliance from
// terva-conn-matrix's tests/live_synapse.rs.
func TestDMRoundTripCompliance(t *testing.T) {
	hs := homeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	tg := tag()
	botLocal, botPW := "bot-"+tg, "bot-pw"
	bot := id.UserID("@" + botLocal + ":localhost")
	register(t, ctx, hs, botLocal, botPW)
	home := t.TempDir()
	provision(t, home, hs, bot.String(), botPW)
	hu := newHuman(t, ctx, hs, "human-"+tg, "human-pw", bot)

	// Session 1.
	conn := spawn(t, home)
	if got := conn.handshake(); str(got, "id") != bot.String() {
		t.Fatalf("connected id = %v, want %s", got["id"], bot)
	}

	room := openEncryptedDM(t, ctx, hu, bot)
	helloID := hu.send(t, ctx, room, text("hello agent"))

	m := conn.expect("message 'hello agent'", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "message" && f["text"] == "hello agent"
	})
	if str(m, "id") != helloID.String() || str(m, "chat_id") != room.String() || str(m, "user_id") != hu.UserID.String() {
		t.Fatalf("message identity: %v; want id %s chat %s user %s", m, helloID, room, hu.UserID)
	}
	if str(m, "chat_kind") != "dm" {
		t.Fatalf("chat_kind = %v; an is_direct invite must map to dm", m["chat_kind"])
	}

	// Markdown out, as a reply.
	conn.write(connproto.SendFromHost{Type: "send", ID: "e2e-1", ChatID: room.String(), ReplyTo: helloID.String(), Text: "__hello__ human"})
	r := conn.expect("result e2e-1", 30*time.Second, func(f map[string]any) bool { return f["type"] == "result" && f["id"] == "e2e-1" })
	if str(r, "error") != "" || str(r, "message_id") == "" {
		t.Fatalf("result e2e-1 = %v", r)
	}
	botEvt := id.EventID(str(r, "message_id"))
	got := hu.waitSeen(t, ctx, "the markdown reply", func(s seenMsg) bool { return s.id == botEvt })
	if got.body != "__hello__ human" || !strings.Contains(got.formattedBody, "<strong>hello</strong>") {
		t.Fatalf("bot message body %q formatted %q; want markdown source and rendered HTML", got.body, got.formattedBody)
	}

	// A rich reply's fallback quote is stripped.
	reply := text("> <" + bot.String() + "> (quoted)\n\ngot it")
	reply.RelatesTo = (&event.RelatesTo{}).SetReplyTo(botEvt)
	hu.send(t, ctx, room, reply)
	m = conn.expect("reply 'got it'", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "message" && f["reply_to"] == botEvt.String()
	})
	if str(m, "text") != "got it" {
		t.Fatalf("reply text = %q; the fallback quote must be stripped", m["text"])
	}

	// Typing on, then off through typing_stop.
	conn.write(connproto.TypingFromHost{Type: "typing", ChatID: room.String()})
	hu.waitTyping(t, true, 15*time.Second)
	off := false
	conn.write(connproto.TypingFromHost{Type: "typing", ChatID: room.String(), Active: &off})
	hu.waitTyping(t, false, 15*time.Second)
	conn.shutdown()

	// Downtime is recovered on reconnect, and the DM is still a DM.
	hu.send(t, ctx, room, text("sent while you were away"))
	conn = spawn(t, home)
	conn.handshake()
	conn.expect("the downtime message", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "message" && f["text"] == "sent while you were away"
	})
	hu.send(t, ctx, room, text("after the restart"))
	m = conn.expect("a fresh message", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "message" && f["text"] == "after the restart"
	})
	if str(m, "chat_kind") != "dm" {
		t.Fatalf("chat_kind after restart = %v; m.direct must survive the restart", m["chat_kind"])
	}

	// Cold owner addressing: a user id as chat id resolves to the DM.
	conn.write(connproto.SendFromHost{Type: "send", ID: "cold-1", ChatID: hu.UserID.String(), Text: "addressed by user id"})
	r = conn.expect("result cold-1", 30*time.Second, func(f map[string]any) bool { return f["type"] == "result" && f["id"] == "cold-1" })
	if str(r, "error") != "" {
		t.Fatalf("cold addressing: %v", r)
	}
	hu.waitSeen(t, ctx, "the cold-addressed message", func(s seenMsg) bool { return s.body == "addressed by user id" })
	conn.shutdown()
}

func waitJoined(t *testing.T, ctx context.Context, c *rihma.Client, room id.RoomID, user id.UserID) {
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
