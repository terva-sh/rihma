package connector

import (
	"encoding/json"
	"testing"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const testRoom = id.RoomID("!r:hs")

// memberEvt builds the bot's membership event as sync delivers it; prev
// is the replaced membership, "" for an event without prev_content.
func memberEvt(t *testing.T, sender id.UserID, now, prev event.Membership, prevSender id.UserID) *event.Event {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"membership": now})
	evt := &event.Event{Type: event.StateMember, RoomID: testRoom, Sender: sender, StateKey: ptr("@bot:hs"),
		Content: event.Content{VeryRaw: raw}}
	if err := evt.Content.ParseRaw(evt.Type); err != nil {
		t.Fatal(err)
	}
	if prev != "" {
		praw, _ := json.Marshal(map[string]any{"membership": prev})
		evt.Unsigned.PrevContent = &event.Content{VeryRaw: praw}
		evt.Unsigned.PrevSender = prevSender
	}
	return evt
}

func ptr(s string) *string { return &s }

func TestMembershipChanges(t *testing.T) {
	const human, mod = id.UserID("@human:hs"), id.UserID("@mod:hs")
	type step struct {
		sender     id.UserID
		now, prev  event.Membership
		prevSender id.UserID
		initial    bool
		wantChange string
		wantBy     id.UserID
	}
	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"invite then join is added by the inviter", []step{
			{sender: human, now: "invite", wantChange: ""},
			{sender: "@bot:hs", now: "join", prev: "invite", prevSender: human, wantChange: "added", wantBy: human},
		}},
		{"a join after restart credits prev_sender", []step{
			{sender: "@bot:hs", now: "join", prev: "invite", prevSender: mod, wantChange: "added", wantBy: mod},
		}},
		{"a profile change is no change", []step{
			{sender: "@bot:hs", now: "join", prev: "join", wantChange: ""},
		}},
		{"a kick is removed by the kicker", []step{
			{sender: mod, now: "leave", prev: "join", wantChange: "removed", wantBy: mod},
		}},
		{"a ban is removed", []step{
			{sender: mod, now: "ban", prev: "join", wantChange: "removed", wantBy: mod},
		}},
		{"a rejected invite is nothing", []step{
			{sender: human, now: "invite", wantChange: ""},
			{sender: "@bot:hs", now: "leave", prev: "invite", wantChange: ""},
		}},
		{"history announces nothing, but a later kick is removed", []step{
			{sender: "@bot:hs", now: "join", initial: true, wantChange: ""},
			{sender: mod, now: "leave", wantChange: "removed", wantBy: mod},
		}},
		{"without prev_content, the announced set dedupes", []step{
			{sender: "@bot:hs", now: "join", wantChange: "added"},
			{sender: "@bot:hs", now: "join", wantChange: ""},
			{sender: "@bot:hs", now: "leave", wantChange: "removed", wantBy: "@bot:hs"},
			{sender: "@bot:hs", now: "leave", wantChange: ""},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMembership()
			for i, s := range tc.steps {
				m.setInitial(s.initial)
				change, by := m.change(memberEvt(t, s.sender, s.now, s.prev, s.prevSender))
				if change != s.wantChange || by != s.wantBy {
					t.Fatalf("step %d (%s over %q): got %q by %q, want %q by %q", i, s.now, s.prev, change, by, s.wantChange, s.wantBy)
				}
			}
		})
	}
}

// A re-invite after a kick, as a sync delivers it: the invite as
// stripped state, with no id or timestamp, then the join in the room's
// state, then a timeline that still holds the kick, the invite, and the
// join. The stripped invite must pass, or the bot never joins, and only
// the join is a change.
func TestMembershipRejoinReplaysNothing(t *testing.T) {
	const mod = id.UserID("@mod:hs")
	at := func(evt *event.Event, eventID id.EventID, ts int64) *event.Event {
		evt.ID, evt.Timestamp = eventID, ts
		return evt
	}
	m := newMembership()
	join1 := at(memberEvt(t, "@bot:hs", "join", "invite", mod), "$join1", 100)
	kick := at(memberEvt(t, mod, "leave", "join", ""), "$kick", 200)
	invite := at(memberEvt(t, mod, "invite", "leave", mod), "$invite", 300)
	join2 := at(memberEvt(t, "@bot:hs", "join", "invite", mod), "$join2", 400)

	stripped := memberEvt(t, mod, "invite", "", "")

	var got []string
	for i, evt := range []*event.Event{join1, kick, stripped, join2, kick, invite, join2} {
		if !m.fresh(evt) {
			if evt == stripped {
				t.Fatalf("step %d: the stripped invite was dropped", i)
			}
			continue
		}
		if change, _ := m.change(evt); change != "" {
			got = append(got, change+" "+evt.ID.String())
		}
	}
	want := []string{"added $join1", "removed $kick", "added $join2"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}
