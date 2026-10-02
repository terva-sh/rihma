package connector

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"
)

func eventOf(t *testing.T, typ event.Type, evtID id.EventID, sender id.UserID, content string) *event.Event {
	t.Helper()
	evt := &event.Event{Type: typ, ID: evtID, RoomID: "!room:hs", Sender: sender, Timestamp: 1700000000999,
		Content: event.Content{VeryRaw: json.RawMessage(content)}}
	if err := evt.Content.ParseRaw(typ); err != nil {
		t.Fatal(err)
	}
	return evt
}

// newTestTransport has no client. Every server read fails, so unknown
// events are room-scoped and thread titles empty.
func newTestTransport() *transport {
	tr := &transport{self: "@bot:hs", nameLoaded: true, name: "Bot", events: newChatEvents(), asks: newAsks(), threads: newThreads(), log: zerolog.Nop()}
	tr.threads.fetchRoot = func(context.Context, id.RoomID, id.EventID) (id.EventID, bool) { return "", false }
	tr.threads.fetchTitle = func(context.Context, id.RoomID, id.EventID) (string, error) { return "", errors.New("no server") }
	return tr
}

func next(t *testing.T, tr *transport) chatEvent {
	t.Helper()
	select {
	case ev := <-tr.events.frames:
		return ev
	default:
		t.Fatal("no frame")
		return chatEvent{}
	}
}

func TestTranslateEdit(t *testing.T) {
	tr := newTestTransport()
	ed, ok := tr.translateEdit(context.Background(), eventOf(t, event.EventMessage, "$edit", "@human:hs", `{
		"msgtype":"m.text","body":"* hello v2",
		"m.new_content":{"msgtype":"m.text","body":"hello Bot v2","m.mentions":{"user_ids":["@bot:hs"]}},
		"m.relates_to":{"rel_type":"m.replace","event_id":"$orig"}}`))
	want := connsdk.MessageEdited{ChatID: "!room:hs", ID: "$orig", TS: 1700000000999, Text: "hello Bot v2",
		Entities: []connsdk.Entity{{Kind: "bot_mention", Offset: 6, Length: 3}}}
	if !ok || ed.ChatID != want.ChatID || ed.ID != want.ID || ed.TS != want.TS || ed.Text != want.Text ||
		len(ed.Entities) != 1 || ed.Entities[0] != want.Entities[0] {
		t.Fatalf("edit = %+v, %v; want %+v", ed, ok, want)
	}

	// The top-level mentions stand in when m.new_content has none.
	ed, _ = tr.translateEdit(context.Background(), eventOf(t, event.EventMessage, "$edit2", "@human:hs", `{
		"msgtype":"m.text","body":"* x","m.mentions":{"user_ids":["@bot:hs"]},
		"m.new_content":{"msgtype":"m.text","body":"plain"},
		"m.relates_to":{"rel_type":"m.replace","event_id":"$orig"}}`))
	if len(ed.Entities) != 1 || ed.Entities[0] != (connsdk.Entity{Kind: "bot_mention"}) {
		t.Fatalf("fallback mentions: %+v", ed.Entities)
	}

	for _, drop := range []string{
		`{"msgtype":"m.text","body":"* x","m.relates_to":{"rel_type":"m.replace","event_id":"$orig"}}`,
		`{"msgtype":"m.text","body":"* x","m.new_content":{"msgtype":"m.image","body":"x.png","url":"mxc://hs/x"},"m.relates_to":{"rel_type":"m.replace","event_id":"$orig"}}`,
	} {
		if ed, ok := tr.translateEdit(context.Background(), eventOf(t, event.EventMessage, "$e", "@human:hs", drop)); ok {
			t.Errorf("delivered %s as %+v", drop, ed)
		}
	}
}

func TestReactionThenRedactionIsRemoval(t *testing.T) {
	tr := newTestTransport()
	ctx := context.Background()
	tr.handleReaction(ctx, eventOf(t, event.EventReaction, "$r1", "@human:hs",
		`{"m.relates_to":{"rel_type":"m.annotation","event_id":"$msg","key":"👍"}}`))
	want := connsdk.Reaction{ChatID: "!room:hs", MessageID: "$msg", UserID: "@human:hs", Username: "human", Key: "👍"}
	if r := next(t, tr).reaction; r == nil || *r != want {
		t.Fatalf("reaction = %+v, want %+v", r, want)
	}

	// Redacted by a moderator: still the reactor's reaction, removed.
	red := eventOf(t, event.EventRedaction, "$red", "@mod:hs", `{}`)
	red.Redacts = "$r1"
	tr.handleRedaction(ctx, red)
	want.Removed = true
	if r := next(t, tr).reaction; r == nil || *r != want {
		t.Fatalf("removal = %+v, want %+v", r, want)
	}

	// The same redaction again is a delete of an id the host never saw.
	tr.handleRedaction(ctx, red)
	if d := next(t, tr).deleted; d == nil || d.ID != "$r1" {
		t.Fatalf("repeat redaction = %+v", d)
	}

	// Room v11 puts the target in content.
	tr.handleRedaction(ctx, eventOf(t, event.EventRedaction, "$red2", "@human:hs", `{"redacts":"$msg"}`))
	if d := next(t, tr).deleted; d == nil || *d != (connsdk.MessageDeleted{ChatID: "!room:hs", ID: "$msg"}) {
		t.Fatalf("v11 delete = %+v", d)
	}
}

func TestLeftRoomEventsAreDropped(t *testing.T) {
	tr := newTestTransport()
	evt := eventOf(t, event.EventReaction, "$r", "@human:hs", `{"m.relates_to":{"rel_type":"m.annotation","event_id":"$m","key":"x"}}`)
	evt.Mautrix.EventSource = event.SourceLeave | event.SourceTimeline
	tr.handleReaction(context.Background(), evt)
	select {
	case ev := <-tr.events.frames:
		t.Fatalf("a left room delivered %+v", ev)
	default:
	}
}

func TestBoundedMap(t *testing.T) {
	m := newBoundedMap[int, string](2)
	m.put(1, "a")
	m.put(2, "b")
	m.put(3, "c")
	if _, ok := m.take(1); ok {
		t.Fatal("the oldest entry survived")
	}
	if v, ok := m.take(3); !ok || v != "c" {
		t.Fatal("the newest entry is gone")
	}
	if _, ok := m.take(3); ok {
		t.Fatal("take left the entry")
	}
	m.put(4, "d")
	m.put(5, "e")
	if _, ok := m.take(2); ok {
		t.Fatal("take did not free its slot, or order is wrong")
	}
}

func TestEventIDValidation(t *testing.T) {
	for _, bad := range []string{"", "$", "m-1", "!room:hs"} {
		if _, err := eventID(bad); err == nil {
			t.Errorf("eventID(%q) accepted", bad)
		}
	}
}
