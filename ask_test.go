package rihma

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// fakeAskSender records what an ask sends and answers with sequential
// event ids. failSeeds makes every SendReaction fail.
type fakeAskSender struct {
	mu        sync.Mutex
	seq       int
	messages  []*event.MessageEventContent
	reactions []string // emoji, in order
	redacted  []id.EventID
	failSeeds bool
	// onSend runs inside SendMessageEvent, while the question is in
	// flight.
	onSend func()
}

func (f *fakeAskSender) next() id.EventID {
	f.seq++
	return id.EventID(fmt.Sprintf("$e%d", f.seq))
}

func (f *fakeAskSender) SendMessageEvent(_ context.Context, _ id.RoomID, _ event.Type, content any, _ ...mautrix.ReqSendEvent) (*mautrix.RespSendEvent, error) {
	if f.onSend != nil {
		f.onSend()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages = append(f.messages, content.(*event.MessageEventContent))
	return &mautrix.RespSendEvent{EventID: f.next()}, nil
}

func (f *fakeAskSender) SendReaction(_ context.Context, _ id.RoomID, _ id.EventID, emoji string) (*mautrix.RespSendEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSeeds {
		return nil, errors.New("no seeds today")
	}
	f.reactions = append(f.reactions, emoji)
	return &mautrix.RespSendEvent{EventID: f.next()}, nil
}

func (f *fakeAskSender) RedactEvent(_ context.Context, _ id.RoomID, target id.EventID, _ ...mautrix.ReqRedact) (*mautrix.RespSendEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.redacted = append(f.redacted, target)
	return &mautrix.RespSendEvent{EventID: f.next()}, nil
}

func (f *fakeAskSender) redactions() []id.EventID {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.redacted)
}

var _ AskSender = (*Client)(nil)

func askOpt(key, label, hint string) AskOption { return AskOption{Key: key, Label: label, Hint: hint} }

// deployAsk is a two-option ask in !room:hs; the first message the fake
// sends is $e1 and its seeds $e2 and $e3.
func deployAsk(restrictTo ...id.UserID) Ask {
	return Ask{ID: "ask-1", Room: "!room:hs", Text: "Deploy?",
		Options:    []AskOption{askOpt("approve", "Approve", "👍"), askOpt("deny", "Deny", "")},
		RestrictTo: restrictTo}
}

func askTap(t *testing.T, evtID id.EventID, sender id.UserID, target id.EventID, key string) *event.Event {
	t.Helper()
	evt := &event.Event{Type: event.EventReaction, ID: evtID, RoomID: "!room:hs", Sender: sender,
		Content: event.Content{VeryRaw: json.RawMessage(`{"m.relates_to":{"rel_type":"m.annotation","event_id":"` + string(target) + `","key":"` + key + `"}}`)}}
	if err := evt.Content.ParseRaw(evt.Type); err != nil {
		t.Fatal(err)
	}
	return evt
}

// terva-conn-matrix's asks.rs cases.
func TestAssignAskEmojis(t *testing.T) {
	for _, c := range []struct {
		name    string
		options []AskOption
		want    []string
	}{
		{"hints win and fallbacks fill gaps", []AskOption{askOpt("approve", "Approve", "👍"), askOpt("deny", "Deny", ""), askOpt("later", "Later", "👍")}, []string{"👍", "①", "②"}},
		{"variation selector and spaces stripped", []AskOption{askOpt("a", "A", " 👍️ ")}, []string{"👍"}},
		{"a hint equal to a used digit falls back", []AskOption{askOpt("a", "A", ""), askOpt("b", "B", "①")}, []string{"①", "②"}},
	} {
		if got := assignAskEmojis(c.options); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	var many []AskOption
	for range 22 {
		many = append(many, askOpt("k", "L", ""))
	}
	got := assignAskEmojis(many)
	if got[0] != "①" || got[19] != "⑳" || got[20] != "⑳" || got[21] != "⑳" {
		t.Fatalf("past twenty: %q", got)
	}
}

func TestRenderAsk(t *testing.T) {
	options := []AskOption{askOpt("approve", "Approve", "👍"), askOpt("deny", "Deny", "")}
	if got, want := renderAsk("Run it?", options, assignAskEmojis(options)), "Run it?\n\n- 👍 Approve\n- ① Deny\n"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
}

// TestAskOpenAndClose checks the widget on the wire: the legend as
// Markdown in its thread, one seed per option, and on Close the seeds
// withdrawn and the outcome edited in.
func TestAskOpenAndClose(t *testing.T) {
	ctx := context.Background()
	f := &fakeAskSender{}
	a := NewAsks(f, "@bot:hs", zerolog.Nop())
	ask := deployAsk()
	ask.RelatesTo = (&event.RelatesTo{}).SetThread("$root", "$root")
	msg, err := a.Open(ctx, ask, func(AskAnswer) {})
	if err != nil || msg != "$e1" {
		t.Fatalf("Open = %s, %v", msg, err)
	}
	m := f.messages[0]
	if m.Body != "Deploy?\n\n- 👍 Approve\n- ① Deny\n" || m.MsgType != event.MsgText || !strings.Contains(m.FormattedBody, "<li>👍 Approve</li>") {
		t.Fatalf("widget = %+v", m)
	}
	if m.RelatesTo == nil || m.RelatesTo.GetThreadParent() != "$root" {
		t.Fatalf("widget relation = %+v", m.RelatesTo)
	}
	if !slices.Equal(f.reactions, []string{"👍", "①"}) {
		t.Fatalf("seeds = %q", f.reactions)
	}

	if err := a.Close(ctx, "ask-1", "Approved by @owner:hs"); err != nil {
		t.Fatal(err)
	}
	if got := f.redactions(); !slices.Equal(got, []id.EventID{"$e2", "$e3"}) {
		t.Fatalf("withdrawn = %q", got)
	}
	edit := f.messages[1]
	if edit.RelatesTo.GetReplaceID() != "$e1" || edit.NewContent == nil || edit.NewContent.Body != "Deploy?\n\n**Approved by @owner:hs**" {
		t.Fatalf("outcome edit = %+v", edit)
	}

	// Closing it again, or an ask that never existed, sends nothing.
	for _, askID := range []string{"ask-1", "never"} {
		if err := a.Close(ctx, askID, "Approved"); err != nil {
			t.Fatalf("close %s: %v", askID, err)
		}
	}
	if len(f.messages) != 2 || len(f.redactions()) != 2 {
		t.Fatalf("a second close sent %d messages, %d redactions", len(f.messages), len(f.redactions()))
	}

	if _, err := a.Open(ctx, Ask{ID: "empty", Room: "!room:hs", Text: "?"}, nil); err == nil {
		t.Fatal("an ask with no options opened")
	}
}

// A seed that fails degrades the widget but not the ask: the legend
// still lists every option, and a typed reaction still answers.
func TestAskSurvivesFailedSeeds(t *testing.T) {
	f := &fakeAskSender{failSeeds: true}
	a := NewAsks(f, "@bot:hs", zerolog.Nop())
	var got []AskAnswer
	if _, err := a.Open(context.Background(), deployAsk(), func(ans AskAnswer) { got = append(got, ans) }); err != nil {
		t.Fatal(err)
	}
	if !a.HandleReaction(askTap(t, "$t", "@owner:hs", "$e1", "①")) || len(got) != 1 || got[0].Key != "deny" {
		t.Fatalf("answers = %+v", got)
	}
}

func TestAskAnswerRouting(t *testing.T) {
	ctx := context.Background()
	a := NewAsks(&fakeAskSender{}, "@bot:hs", zerolog.Nop())
	refused := make(chan id.EventID, 4)
	a.refuse = func(_ id.RoomID, e id.EventID) { refused <- e }
	var answers []AskAnswer
	if _, err := a.Open(ctx, deployAsk("@owner:hs"), func(ans AskAnswer) { answers = append(answers, ans) }); err != nil {
		t.Fatal(err)
	}

	// The owner's tap is one answer; a variation selector does not matter.
	if !a.HandleReaction(askTap(t, "$t1", "@owner:hs", "$e1", "👍️")) {
		t.Fatal("the owner's tap was not consumed")
	}
	want := AskAnswer{AskID: "ask-1", Key: "approve", Sender: "@owner:hs", Event: "$t1"}
	if len(answers) != 1 || answers[0] != want {
		t.Fatalf("answers = %+v, want %+v", answers, want)
	}

	// Its un-tap is taken once, and is not a deleted message.
	if !a.TakeAnswerRedaction("$t1") || a.TakeAnswerRedaction("$t1") {
		t.Fatal("the un-tap was not taken exactly once")
	}

	// A near-miss MXID is outside RestrictTo: consumed, no answer, and
	// the tap is redacted; its redaction is taken too.
	if !a.HandleReaction(askTap(t, "$t2", "@owner:hs.evil", "$e1", "①")) || len(answers) != 1 {
		t.Fatalf("an imposter answered: %+v", answers)
	}
	select {
	case e := <-refused:
		if e != "$t2" {
			t.Fatalf("refused %s", e)
		}
	case <-time.After(time.Second):
		t.Fatal("the imposter tap was not redacted")
	}
	if !a.TakeAnswerRedaction("$t2") {
		t.Fatal("the imposter's un-tap was not taken")
	}

	// Another emoji, the bot's own seed echo, another message, and a
	// non-reaction are none of the widget's business.
	for name, evt := range map[string]*event.Event{
		"another emoji":   askTap(t, "$t3", "@owner:hs", "$e1", "🎉"),
		"the bot's seed":  askTap(t, "$t4", "@bot:hs", "$e1", "👍"),
		"another message": askTap(t, "$t5", "@owner:hs", "$other", "👍"),
		"a message":       {Type: event.EventMessage, ID: "$m", Sender: "@owner:hs", Content: event.Content{Parsed: &event.MessageEventContent{Body: "hi"}}},
	} {
		if a.HandleReaction(evt) {
			t.Errorf("%s was consumed", name)
		}
	}

	// An expired ask answers nothing; its taps are plain reactions.
	a.mu.Lock()
	a.open["ask-1"].expired = true
	a.mu.Unlock()
	if a.HandleReaction(askTap(t, "$t6", "@owner:hs", "$e1", "👍")) {
		t.Fatal("a tap on an expired ask was consumed")
	}

	// So does a closed one.
	a.mu.Lock()
	a.open["ask-1"].expired = false
	a.mu.Unlock()
	if err := a.Close(ctx, "ask-1", ""); err != nil {
		t.Fatal(err)
	}
	if a.HandleReaction(askTap(t, "$t7", "@owner:hs", "$e1", "👍")) || len(answers) != 1 {
		t.Fatalf("a tap on a closed ask was consumed; answers %+v", answers)
	}
}

func TestAnyoneMayAnswerWithoutRestrictTo(t *testing.T) {
	a := NewAsks(&fakeAskSender{}, "@bot:hs", zerolog.Nop())
	var answers []AskAnswer
	if _, err := a.Open(context.Background(), deployAsk(), func(ans AskAnswer) { answers = append(answers, ans) }); err != nil {
		t.Fatal(err)
	}
	a.HandleReaction(askTap(t, "$t", "@someone:else", "$e1", "①"))
	if len(answers) != 1 || answers[0].Key != "deny" || answers[0].Sender != "@someone:else" {
		t.Fatalf("answers = %+v", answers)
	}
}

// TestAskExpiry checks that an expired ask withdraws its seeds and stops
// answering, but stays registered so a later Close renders the outcome.
func TestAskExpiry(t *testing.T) {
	ctx := context.Background()
	f := &fakeAskSender{}
	a := NewAsks(f, "@bot:hs", zerolog.Nop())
	ask := deployAsk()
	ask.Expires = 50 * time.Millisecond
	start := time.Now()
	_, err := a.Wait(ctx, ask)
	if !errors.Is(err, ErrAskExpired) {
		t.Fatalf("Wait = %v, want ErrAskExpired", err)
	}
	if took := time.Since(start); took < ask.Expires {
		t.Fatalf("expired after %s, before its %s", took, ask.Expires)
	}
	// Wait is released before the seeds are withdrawn, so wait for them.
	waitRedactions(t, f, "$e2", "$e3")
	if a.HandleReaction(askTap(t, "$late", "@owner:hs", "$e1", "👍")) {
		t.Fatal("a late tap answered")
	}
	if err := a.Close(ctx, "ask-1", "Expired"); err != nil {
		t.Fatal(err)
	}
	if len(f.messages) != 2 || f.messages[1].NewContent.Body != "Deploy?\n\n**Expired**" {
		t.Fatalf("no outcome edit after expiry: %d messages", len(f.messages))
	}
}

func TestAskWait(t *testing.T) {
	ctx := context.Background()

	// The first permitted answer returns; the ask stays open for Close.
	a := NewAsks(&fakeAskSender{}, "@bot:hs", zerolog.Nop())
	done := make(chan struct{})
	var ans AskAnswer
	var err error
	go func() { ans, err = a.Wait(ctx, deployAsk("@owner:hs")); close(done) }()
	waitOpen(t, a, "ask-1")
	a.HandleReaction(askTap(t, "$no", "@other:hs", "$e1", "👍"))
	a.HandleReaction(askTap(t, "$yes", "@owner:hs", "$e1", "①"))
	a.HandleReaction(askTap(t, "$again", "@owner:hs", "$e1", "👍"))
	<-done
	if err != nil || ans.Key != "deny" || ans.Event != "$yes" {
		t.Fatalf("Wait = %+v, %v", ans, err)
	}
	if waitOpen(t, a, "ask-1"); a.Close(ctx, "ask-1", "Denied") != nil {
		t.Fatal("Close after Wait failed")
	}

	// Closing, replacing, or shutting down releases a Wait.
	for name, end := range map[string]func(*Asks){
		"close":    func(a *Asks) { _ = a.Close(ctx, "ask-1", "") },
		"replace":  func(a *Asks) { _, _ = a.Open(ctx, deployAsk(), func(AskAnswer) {}) },
		"shutdown": func(a *Asks) { a.Shutdown() },
	} {
		a := NewAsks(&fakeAskSender{}, "@bot:hs", zerolog.Nop())
		got := make(chan error, 1)
		go func() { _, err := a.Wait(ctx, deployAsk()); got <- err }()
		waitOpen(t, a, "ask-1")
		end(a)
		select {
		case err := <-got:
			if !errors.Is(err, ErrAskClosed) {
				t.Errorf("%s: Wait = %v, want ErrAskClosed", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s did not release Wait", name)
		}
	}

	// So does the context.
	a = NewAsks(&fakeAskSender{}, "@bot:hs", zerolog.Nop())
	cctx, cancel := context.WithCancel(ctx)
	got := make(chan error, 1)
	go func() { _, err := a.Wait(cctx, deployAsk()); got <- err }()
	waitOpen(t, a, "ask-1")
	cancel()
	if err := <-got; !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait = %v, want context.Canceled", err)
	}
}

// waitRedactions waits until f has redacted exactly want, in order.
func waitRedactions(t *testing.T, f *fakeAskSender, want ...id.EventID) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := f.redactions()
		if slices.Equal(got, want) {
			return
		}
		if len(got) > len(want) || time.Now().After(deadline) {
			t.Fatalf("withdrawn = %q, want %q", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitOpen waits until askID is registered and seeded.
func waitOpen(t *testing.T, a *Asks, askID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.mu.Lock()
		s := a.open[askID]
		seeded := s != nil && len(s.seeds) == len(s.emojis)
		a.mu.Unlock()
		if seeded {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ask %s never opened", askID)
		}
		time.Sleep(time.Millisecond)
	}
}

func newTestAskState() *askState { return &askState{gone: make(chan struct{})} }

func TestOpenAsksAreBounded(t *testing.T) {
	a := NewAsks(nil, "@bot:hs", zerolog.Nop())
	first := newTestAskState()
	first.timer = time.AfterFunc(time.Hour, func() { t.Error("an evicted ask's timer fired") })
	a.add("first", first, -1)
	for i := range maxOpenAsks {
		a.add(fmt.Sprint("ask-", i), newTestAskState(), -1)
	}
	if _, ok := a.open["first"]; ok || len(a.open) != maxOpenAsks || len(a.order) != maxOpenAsks {
		t.Fatalf("open = %d, order = %d, first kept = %v", len(a.open), len(a.order), ok)
	}
	if first.timer.Stop() {
		t.Fatal("evicting the ask left its timer running")
	}
	select {
	case <-first.gone:
	default:
		t.Fatal("evicting the ask did not release its Wait")
	}

	// Re-adding an id replaces it rather than leaving a second entry.
	b := NewAsks(nil, "@bot:hs", zerolog.Nop())
	old := newTestAskState()
	old.timer = time.AfterFunc(time.Hour, func() {})
	b.add("x", old, -1)
	b.add("x", newTestAskState(), -1)
	if len(b.order) != 1 || old.timer.Stop() {
		t.Fatalf("order = %v; old timer still running = %v", b.order, !old.timer.Stop())
	}
}

func TestShutdownStopsTimers(t *testing.T) {
	a := NewAsks(nil, "@bot:hs", zerolog.Nop())
	s := newTestAskState()
	s.timer = time.AfterFunc(time.Hour, func() {})
	a.add("x", s, -1)
	a.Shutdown()
	if s.timer.Stop() || !a.done {
		t.Fatal("shutdown left a timer running")
	}

	// Opening after Shutdown fails and sends nothing.
	f := &fakeAskSender{}
	b := NewAsks(f, "@bot:hs", zerolog.Nop())
	b.Shutdown()
	if _, err := b.Open(context.Background(), deployAsk(), func(AskAnswer) {}); !errors.Is(err, ErrAskClosed) || len(f.messages) != 0 {
		t.Fatalf("Open after Shutdown = %v, sent %d", err, len(f.messages))
	}
}

// TestShutdownDuringOpen covers a question in flight when Shutdown runs:
// its Wait is released rather than left blocked, it arms no timer, and
// it stays registered so Close can still withdraw it.
func TestShutdownDuringOpen(t *testing.T) {
	f := &fakeAskSender{}
	a := NewAsks(f, "@bot:hs", zerolog.Nop())
	f.onSend = a.Shutdown
	ask := deployAsk()
	ask.Expires = time.Hour
	got := make(chan error, 1)
	go func() { _, err := a.Wait(context.Background(), ask); got <- err }()
	select {
	case err := <-got:
		if !errors.Is(err, ErrAskClosed) {
			t.Fatalf("Wait = %v, want ErrAskClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown during Open left Wait blocked")
	}
	a.mu.Lock()
	s := a.open["ask-1"]
	a.mu.Unlock()
	if s == nil || s.timer != nil {
		t.Fatalf("the in-flight ask: %+v", s)
	}
	if err := a.Close(context.Background(), "ask-1", "Cancelled"); err != nil || len(f.messages) != 2 {
		t.Fatalf("Close after Shutdown = %v, %d messages", err, len(f.messages))
	}
}

// TestBoundedSet checks the answer-event memory forgets its oldest.
func TestBoundedSet(t *testing.T) {
	b := newBoundedSet(2)
	b.put("$a")
	b.put("$b")
	b.put("$b")
	b.put("$c")
	if b.take("$a") || !b.take("$b") || !b.take("$c") || b.take("$c") {
		t.Fatal("bounded set kept the wrong ids")
	}
}
