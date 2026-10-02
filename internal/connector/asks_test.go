package connector

import (
	"context"
	"slices"
	"testing"
	"time"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"
)

func opt(key, label, hint string) connsdk.AskOption {
	return connsdk.AskOption{Key: key, Label: label, Hint: hint}
}

// terva-conn-matrix's asks.rs cases.
func TestAssignEmojis(t *testing.T) {
	for _, c := range []struct {
		name    string
		options []connsdk.AskOption
		want    []string
	}{
		{"hints win and fallbacks fill gaps", []connsdk.AskOption{opt("approve", "Approve", "👍"), opt("deny", "Deny", ""), opt("later", "Later", "👍")}, []string{"👍", "①", "②"}},
		{"variation selector and spaces stripped", []connsdk.AskOption{opt("a", "A", " 👍️ ")}, []string{"👍"}},
		{"a hint equal to a used digit falls back", []connsdk.AskOption{opt("a", "A", ""), opt("b", "B", "①")}, []string{"①", "②"}},
	} {
		if got := assignEmojis(c.options); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	var many []connsdk.AskOption
	for range 22 {
		many = append(many, opt("k", "L", ""))
	}
	got := assignEmojis(many)
	if got[0] != "①" || got[19] != "⑳" || got[20] != "⑳" || got[21] != "⑳" {
		t.Fatalf("past twenty: %q", got)
	}
}

func TestRenderAsk(t *testing.T) {
	options := []connsdk.AskOption{opt("approve", "Approve", "👍"), opt("deny", "Deny", "")}
	if got, want := renderAsk("Run it?", options, assignEmojis(options)), "Run it?\n\n- 👍 Approve\n- ① Deny\n"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
}

// openAsk registers an ask on $ask without a client.
func openAsk(tr *transport, askID string, restrictTo []string, got *[]connsdk.Answer) *askState {
	s := &askState{room: "!room:hs", message: "$ask", text: "Deploy?", emojis: []string{"👍", "①"}, keys: []string{"approve", "deny"},
		restrictTo: restrictTo, deliver: func(a connsdk.Answer) { *got = append(*got, a) }}
	tr.asks.add(askID, s)
	return s
}

func tap(t *testing.T, evtID id.EventID, sender id.UserID, target, key string) *event.Event {
	return eventOf(t, event.EventReaction, evtID, sender, `{"m.relates_to":{"rel_type":"m.annotation","event_id":"`+target+`","key":"`+key+`"}}`)
}

func noFrame(t *testing.T, tr *transport, what string) {
	t.Helper()
	select {
	case ev := <-tr.events.frames:
		t.Fatalf("%s produced %+v", what, ev)
	default:
	}
}

func TestAnswerRouting(t *testing.T) {
	ctx := context.Background()
	tr := newTestTransport()
	refused := make(chan id.EventID, 4)
	tr.asks.refuse = func(_ id.RoomID, e id.EventID) { refused <- e }
	var answers []connsdk.Answer
	s := openAsk(tr, "ask-1", []string{"@owner:hs"}, &answers)

	// The owner's tap is one attested answer and no reaction frame; a
	// variation selector does not matter.
	tr.handleReaction(ctx, tap(t, "$t1", "@owner:hs", "$ask", "👍️"))
	want := connsdk.Answer{AskID: "ask-1", Key: "approve", UserID: "@owner:hs", Username: "owner", Attestation: "attested"}
	if len(answers) != 1 || answers[0] != want {
		t.Fatalf("answers = %+v, want %+v", answers, want)
	}
	noFrame(t, tr, "an answer")

	// Its un-tap is nothing: no deleted message, no removed reaction.
	red := eventOf(t, event.EventRedaction, "$u1", "@owner:hs", `{}`)
	red.Redacts = "$t1"
	tr.handleRedaction(ctx, red)
	noFrame(t, tr, "an un-tap")

	// A near-miss MXID is outside RestrictTo: no answer, no frame, and
	// the tap is redacted; its redaction is swallowed too.
	tr.handleReaction(ctx, tap(t, "$t2", "@owner:hs.evil", "$ask", "①"))
	if len(answers) != 1 {
		t.Fatalf("an imposter answered: %+v", answers)
	}
	noFrame(t, tr, "an imposter tap")
	select {
	case e := <-refused:
		if e != "$t2" {
			t.Fatalf("refused %s", e)
		}
	case <-time.After(time.Second):
		t.Fatal("the imposter tap was not redacted")
	}

	// Another emoji on the widget is a plain reaction.
	tr.handleReaction(ctx, tap(t, "$t3", "@owner:hs", "$ask", "🎉"))
	if r := next(t, tr).reaction; r == nil || r.Key != "🎉" || r.MessageID != "$ask" {
		t.Fatalf("other emoji = %+v", r)
	}

	// An expired ask answers nothing; its taps are plain reactions.
	s.expired = true
	tr.handleReaction(ctx, tap(t, "$t4", "@owner:hs", "$ask", "👍"))
	if r := next(t, tr).reaction; r == nil || r.Key != "👍" || len(answers) != 1 {
		t.Fatalf("tap on an expired ask = %+v, answers %+v", r, answers)
	}

	// So does a closed one.
	s.expired = false
	if tr.asks.remove("ask-1") != s {
		t.Fatal("remove did not return the open ask")
	}
	tr.handleReaction(ctx, tap(t, "$t5", "@owner:hs", "$ask", "👍"))
	if r := next(t, tr).reaction; r == nil || len(answers) != 1 {
		t.Fatalf("tap on a closed ask = %+v, answers %+v", r, answers)
	}

	// Closing it again, or an ask that never existed, succeeds without
	// touching the network (there is no client here).
	for _, id := range []string{"ask-1", "never"} {
		if err := tr.CloseAsk(ctx, id, "Approved"); err != nil {
			t.Fatalf("close %s: %v", id, err)
		}
	}
}

func TestAnyoneMayAnswerWithoutRestrictTo(t *testing.T) {
	tr := newTestTransport()
	var answers []connsdk.Answer
	openAsk(tr, "ask-1", nil, &answers)
	tr.handleReaction(context.Background(), tap(t, "$t", "@someone:else", "$ask", "①"))
	if len(answers) != 1 || answers[0].Key != "deny" || answers[0].UserID != "@someone:else" {
		t.Fatalf("answers = %+v", answers)
	}
}

func TestOpenAsksAreBounded(t *testing.T) {
	a := newAsks()
	first := &askState{timer: time.AfterFunc(time.Hour, func() { t.Error("an evicted ask's timer fired") })}
	a.add("first", first)
	for i := range maxOpenAsks {
		a.add(string(rune('a'+i%26))+string(rune(i)), &askState{})
	}
	if _, ok := a.open["first"]; ok || len(a.open) != maxOpenAsks || len(a.order) != maxOpenAsks {
		t.Fatalf("open = %d, order = %d, first kept = %v", len(a.open), len(a.order), ok)
	}
	if first.timer.Stop() {
		t.Fatal("evicting the ask left its timer running")
	}

	// Re-adding an id replaces it rather than leaving a second entry.
	b := newAsks()
	old := &askState{timer: time.AfterFunc(time.Hour, func() {})}
	b.add("x", old)
	b.add("x", &askState{})
	if len(b.order) != 1 || old.timer.Stop() {
		t.Fatalf("order = %v; old timer still running = %v", b.order, !old.timer.Stop())
	}
}

func TestShutdownStopsTimers(t *testing.T) {
	a := newAsks()
	s := &askState{timer: time.AfterFunc(time.Hour, func() {})}
	a.add("x", s)
	a.shutdown()
	if s.timer.Stop() || !a.done {
		t.Fatal("shutdown left a timer running")
	}
}
