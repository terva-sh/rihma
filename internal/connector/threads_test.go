package connector

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func TestThreadChatIDCodec(t *testing.T) {
	derived := threadChatID("!r:localhost", "$root")
	if derived != "!r:localhost;thread=$root" {
		t.Fatalf("derived = %q", derived)
	}
	if room, root, ok := splitChatID(derived); room != "!r:localhost" || root != "$root" || !ok {
		t.Fatalf("split = %q %q %v", room, root, ok)
	}
	if room, root, ok := splitChatID("!r:localhost"); room != "!r:localhost" || root != "" || ok {
		t.Fatalf("split plain = %q %q %v", room, root, ok)
	}
	// Split at the first marker, as terva-conn-matrix does; the root
	// then fails event id validation in resolveTarget.
	if _, root, _ := splitChatID("!r:hs;thread=$a;thread=$b"); root != "$a;thread=$b" {
		t.Fatalf("split twice = %q", root)
	}
	for _, c := range []chatTarget{{room: "!r:hs"}, {room: "!r:hs", root: "$x"}} {
		room, root, _ := splitChatID(c.chatID())
		if id.RoomID(room) != c.room || id.EventID(root) != c.root {
			t.Errorf("%+v round-tripped to %q %q", c, room, root)
		}
	}
}

func TestSnippet(t *testing.T) {
	long := strings.Repeat("é", 61)
	for in, want := range map[string]string{
		"the flaky test strikes again": "the flaky test strikes again",
		"first line\nsecond":           "first line",
		"crlf line\r\nsecond":          "crlf line",
		strings.Repeat("é", 60):        strings.Repeat("é", 60),
		long:                           strings.Repeat("é", 60) + "…",
		"":                             "",
	} {
		if got := snippet(in); got != want {
			t.Errorf("snippet(%q) = %q, want %q", in, got, want)
		}
	}
}

func relJSON(rel *event.RelatesTo) string {
	b, _ := json.Marshal(rel)
	return string(b)
}

func TestOutboundRelation(t *testing.T) {
	tr := newTestTransport()
	room := chatTarget{room: "!r:hs"}
	thread := chatTarget{room: "!r:hs", root: "$root"}
	for _, c := range []struct {
		name    string
		target  chatTarget
		replyTo string
		want    string
	}{
		{"plain", room, "", "null"},
		{"rich reply", room, "$m", `{"m.in_reply_to":{"event_id":"$m"}}`},
		{"bad reply_to dropped", room, "nope", "null"},
		{"thread, nothing known: fallback to root", thread, "", `{"rel_type":"m.thread","event_id":"$root","m.in_reply_to":{"event_id":"$root"},"is_falling_back":true}`},
		{"thread reply is real", thread, "$m", `{"rel_type":"m.thread","event_id":"$root","m.in_reply_to":{"event_id":"$m"}}`},
	} {
		if got := relJSON(tr.outboundRelation(c.target, c.replyTo)); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	// The fallback follows the newest event noted in the thread.
	tr.note(thread, "$latest")
	if got, want := relJSON(tr.outboundRelation(thread, "")), `{"rel_type":"m.thread","event_id":"$root","m.in_reply_to":{"event_id":"$latest"},"is_falling_back":true}`; got != want {
		t.Fatalf("after a note: %s, want %s", got, want)
	}
}

func TestScopeCache(t *testing.T) {
	ctx := context.Background()
	tr := newTestTransport()
	fetches := map[id.EventID]int{}
	server := map[id.EventID]id.EventID{"$old-in-thread": "$root", "$old-in-room": ""}
	tr.threads.fetchRoot = func(_ context.Context, _ id.RoomID, e id.EventID) (id.EventID, bool) {
		fetches[e]++
		root, ok := server[e]
		return root, ok
	}

	// Noted events answer from the cache.
	tr.note(chatTarget{room: "!r:hs", root: "$root"}, "$t")
	tr.note(chatTarget{room: "!r:hs"}, "$p")
	if got := tr.scopeOf(ctx, "!r:hs", "$t"); got != "!r:hs;thread=$root" {
		t.Fatalf("noted thread event = %q", got)
	}
	if got := tr.scopeOf(ctx, "!r:hs", "$p"); got != "!r:hs" {
		t.Fatalf("noted room event = %q", got)
	}
	if len(fetches) != 0 {
		t.Fatalf("a cache hit fetched: %v", fetches)
	}

	// A miss fetches once, and the answer is cached either way.
	for range 2 {
		if got := tr.scopeOf(ctx, "!r:hs", "$old-in-thread"); got != "!r:hs;thread=$root" {
			t.Fatalf("fetched thread event = %q", got)
		}
		if got := tr.scopeOf(ctx, "!r:hs", "$old-in-room"); got != "!r:hs" {
			t.Fatalf("fetched room event = %q", got)
		}
	}
	if fetches["$old-in-thread"] != 1 || fetches["$old-in-room"] != 1 {
		t.Fatalf("fetches = %v", fetches)
	}

	// A failed fetch degrades to the room and is not cached, so the next
	// event about it tries again.
	for range 2 {
		if got := tr.scopeOf(ctx, "!r:hs", "$unreachable"); got != "!r:hs" {
			t.Fatalf("failed fetch = %q", got)
		}
	}
	if fetches["$unreachable"] != 2 {
		t.Fatalf("a failed fetch was cached: %v", fetches)
	}

	// Redactions never fetch.
	if got := tr.cachedScopeOf("!r:hs", "$t"); got != "!r:hs;thread=$root" {
		t.Fatalf("cached thread = %q", got)
	}
	if got := tr.cachedScopeOf("!r:hs", "$never-seen"); got != "!r:hs" || fetches["$never-seen"] != 0 {
		t.Fatalf("cache-only miss = %q, fetches %v", got, fetches)
	}
}

func TestInboundThreadRouting(t *testing.T) {
	ctx := context.Background()
	tr := newTestTransport()
	tr.titles.set("!room:hs", "ops")
	tr.dms.set(event.DirectChatsEventContent{"@human:hs": {"!room:hs"}})
	titles := 0
	tr.threads.fetchTitle = func(_ context.Context, _ id.RoomID, root id.EventID) (string, error) {
		titles++
		if root == "$gone" {
			return "", errors.New("gone")
		}
		return "the flaky test strikes again", nil
	}

	// A fallback-shaped thread message: the thread chat, titled, no reply.
	m, ok := tr.translateMessage(ctx, msgEvent(t, `{"msgtype":"m.text","body":"nice find",
		"m.relates_to":{"rel_type":"m.thread","event_id":"$root","is_falling_back":true,"m.in_reply_to":{"event_id":"$root"}}}`))
	if !ok || m.ChatID != "!room:hs;thread=$root" || m.ChatKind != "thread" || m.ChatTitle != "the flaky test strikes again" || m.ReplyTo != "" || m.Text != "nice find" {
		t.Fatalf("thread message = %+v", m)
	}
	if m.ParentChatID != "!room:hs" || m.ParentChatKind != "dm" {
		t.Fatalf("DM parent = %+v", m)
	}
	// A real in-thread reply keeps reply_to; the title is cached.
	m, _ = tr.translateMessage(ctx, msgEvent(t, `{"msgtype":"m.text","body":"ship it",
		"m.relates_to":{"rel_type":"m.thread","event_id":"$root","m.in_reply_to":{"event_id":"$bot"}}}`))
	if m.ChatID != "!room:hs;thread=$root" || m.ReplyTo != "$bot" || titles != 1 {
		t.Fatalf("in-thread reply = %+v, title fetches %d", m, titles)
	}
	// Both were noted: an edit of one resolves to the thread.
	if got := tr.scopeOf(ctx, "!room:hs", "$evt"); got != "!room:hs;thread=$root" {
		t.Fatalf("scope of a delivered thread message = %q", got)
	}
	// A root that cannot be read titles as "", once.
	m, _ = tr.translateMessage(ctx, msgEvent(t, `{"msgtype":"m.text","body":"x","m.relates_to":{"rel_type":"m.thread","event_id":"$gone"}}`))
	tr.translateMessage(ctx, msgEvent(t, `{"msgtype":"m.text","body":"y","m.relates_to":{"rel_type":"m.thread","event_id":"$gone"}}`))
	if m.ChatTitle != "" || titles != 2 {
		t.Fatalf("unreadable root: title %q, fetches %d", m.ChatTitle, titles)
	}
	tr.dms.set(event.DirectChatsEventContent{})
	m, ok = tr.translateMessage(ctx, msgEvent(t, `{"msgtype":"m.text","body":"group thread",
		"m.relates_to":{"rel_type":"m.thread","event_id":"$group-root"}}`))
	if !ok || m.ParentChatID != "!room:hs" || m.ParentChatKind != "group" || m.ChatKind != "thread" {
		t.Fatalf("group thread parent = %+v", m)
	}
	m, ok = tr.translateMessage(ctx, msgEvent(t, `{"msgtype":"m.text","body":"room message"}`))
	if !ok || m.ParentChatID != "" || m.ParentChatKind != "" || m.ChatKind != "group" {
		t.Fatalf("room parent metadata = %+v", m)
	}
}
