package connector

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"

	"terva.sh/rihma"
)

// The widget itself is rihma's and tested there; these tests cover the
// connector's part: translating asks and answers, and keeping widget
// taps out of the reaction stream.

// widgetSender posts the widget as $ask and its seeds as $seed.
type widgetSender struct{}

func (widgetSender) SendMessageEvent(context.Context, id.RoomID, event.Type, any, ...mautrix.ReqSendEvent) (*mautrix.RespSendEvent, error) {
	return &mautrix.RespSendEvent{EventID: "$ask"}, nil
}

func (widgetSender) SendReaction(context.Context, id.RoomID, id.EventID, string) (*mautrix.RespSendEvent, error) {
	return &mautrix.RespSendEvent{EventID: "$seed"}, nil
}

func (widgetSender) RedactEvent(context.Context, id.RoomID, id.EventID, ...mautrix.ReqRedact) (*mautrix.RespSendEvent, error) {
	return &mautrix.RespSendEvent{EventID: "$redaction"}, nil
}

func TestRihmaAsk(t *testing.T) {
	rel := (&event.RelatesTo{}).SetThread("$root", "$root")
	a := connsdk.Ask{
		ID: "ask-1", ChatID: "!room:hs", Text: "Deploy?",
		Options:    []connsdk.AskOption{{Key: "approve", Label: "Approve", Style: "affirm", Hint: "👍", Recommended: true}},
		RestrictTo: []string{"@owner:hs"}, Expires: time.Minute,
	}
	want := rihma.Ask{
		ID: "ask-1", Room: "!room:hs", Text: "Deploy?", RelatesTo: rel,
		Options:    []rihma.AskOption{{Key: "approve", Label: "Approve", Hint: "👍"}},
		RestrictTo: []id.UserID{"@owner:hs"}, Expires: 50 * time.Second,
	}
	if got := rihmaAsk(a, "!room:hs", rel, 10*time.Second); !reflect.DeepEqual(got, want) {
		t.Fatalf("rihmaAsk:\n got %+v\nwant %+v", got, want)
	}

	// The deadline is the command's: a floor of a second, less the time
	// already spent, once. An overdue ask still expires rather than
	// turning into one that never does.
	for _, c := range []struct{ expires, elapsed, want time.Duration }{
		{time.Second, 900 * time.Millisecond, 100 * time.Millisecond},
		{500 * time.Millisecond, 0, time.Second},
		{500 * time.Millisecond, 300 * time.Millisecond, 700 * time.Millisecond},
		{time.Second, 2 * time.Second, time.Nanosecond},
		{0, time.Second, 0},
	} {
		a.Expires = c.expires
		if got := rihmaAsk(a, "!room:hs", nil, c.elapsed).Expires; got != c.want {
			t.Errorf("Expires %s after %s = %s, want %s", c.expires, c.elapsed, got, c.want)
		}
	}
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
	tr.asks = rihma.NewAsks(widgetSender{}, "@bot:hs", zerolog.Nop())
	var answers []connsdk.Answer
	ask := rihmaAsk(connsdk.Ask{ID: "ask-1", Text: "Deploy?",
		Options:    []connsdk.AskOption{{Key: "approve", Label: "Approve", Hint: "👍"}, {Key: "deny", Label: "Deny"}},
		RestrictTo: []string{"@owner:hs"}}, "!room:hs", nil, 0)
	if _, err := tr.asks.Open(ctx, ask, func(ans rihma.AskAnswer) { answers = append(answers, answerOf(ans)) }); err != nil {
		t.Fatal(err)
	}

	// The owner's tap is one attested answer and no reaction frame.
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

	// A tap from outside RestrictTo is swallowed too.
	tr.handleReaction(ctx, tap(t, "$t2", "@owner:hs.evil", "$ask", "①"))
	noFrame(t, tr, "an imposter tap")
	if len(answers) != 1 {
		t.Fatalf("an imposter answered: %+v", answers)
	}

	// Another emoji on the widget is a plain reaction.
	tr.handleReaction(ctx, tap(t, "$t3", "@owner:hs", "$ask", "🎉"))
	if r := next(t, tr).reaction; r == nil || r.Key != "🎉" || r.MessageID != "$ask" {
		t.Fatalf("other emoji = %+v", r)
	}

	// After CloseAsk a tap is a plain reaction.
	if err := tr.CloseAsk(ctx, "ask-1", ""); err != nil {
		t.Fatal(err)
	}
	tr.handleReaction(ctx, tap(t, "$t4", "@owner:hs", "$ask", "👍"))
	if r := next(t, tr).reaction; r == nil || len(answers) != 1 {
		t.Fatalf("tap on a closed ask = %+v, answers %+v", r, answers)
	}

	// Closing an ask that never existed succeeds without a client, and
	// before Connect has made the asks at all.
	if err := newTestTransport().CloseAsk(ctx, "never", "Approved"); err != nil {
		t.Fatal(err)
	}
	if err := (&transport{}).CloseAsk(ctx, "never", "Approved"); err != nil {
		t.Fatal(err)
	}
}
