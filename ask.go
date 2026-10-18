package rihma

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
)

// Asks as a reaction widget, as terva-conn-matrix's src/matrix/asks.rs
// renders them. Matrix has no buttons, so an ask is its text plus an
// emoji legend, and the bot seeds its own message with one reaction per
// option; a tap on a seed answers. A reaction is an event whose sender
// the origin homeserver authenticated, so answers are attested, with one
// caveat: a hostile federated homeserver can forge events for its own
// users, and an exact-MXID RestrictTo keeps that to the owner's own
// server. Reaction keys are cleartext even in encrypted rooms, so hints
// must never carry anything sensitive.

const (
	// askSeedTimeout bounds each seed and each withdrawal. They are
	// widget furniture: a failure degrades the widget, never the ask,
	// because the legend still lists every option.
	askSeedTimeout  = 5 * time.Second
	maxOpenAsks     = 256
	maxAnswerEvents = 512
)

// Errors Asks.Wait returns when no answer came.
var (
	ErrAskExpired = errors.New("rihma: the ask expired unanswered")
	// ErrAskClosed means the ask was closed, replaced, or evicted, or the
	// set shut down, before anyone answered. Open returns it once the set
	// has shut down.
	ErrAskClosed = errors.New("rihma: the ask closed unanswered")
)

// AskOption is one answer an ask offers.
type AskOption struct {
	// Key is what an answer reports.
	Key string
	// Label is shown in the legend beside the option's emoji.
	Label string
	// Hint is a preferred emoji. An empty or taken hint falls back to
	// the next free circled digit, ① to ⑳.
	Hint string
}

// Ask is a question with a fixed set of answers.
type Ask struct {
	// ID is the caller's name for the ask. Opening an ask with the ID of
	// one still open replaces it.
	ID   string
	Room id.RoomID
	// Text is the question, as Markdown.
	Text    string
	Options []AskOption
	// RestrictTo lists the users who may answer, by exact MXID. Empty
	// means anyone in the room.
	RestrictTo []id.UserID
	// Expires withdraws the widget after this long, measured from the
	// call that opens it; zero waits until Close.
	Expires time.Duration
	// RelatesTo places the widget as a reply or in a thread.
	RelatesTo *event.RelatesTo
}

// AskAnswer is one permitted answer to an ask.
type AskAnswer struct {
	AskID string
	Key   string
	// Sender was authenticated by its own homeserver.
	Sender id.UserID
	// Event is the reaction that answered.
	Event id.EventID
}

// AskSender is what Asks needs from a client to post, seed, edit, and
// withdraw a widget. *Client satisfies it.
type AskSender interface {
	SendMessageEvent(ctx context.Context, roomID id.RoomID, eventType event.Type, contentJSON any, extra ...mautrix.ReqSendEvent) (*mautrix.RespSendEvent, error)
	SendReaction(ctx context.Context, roomID id.RoomID, eventID id.EventID, reaction string) (*mautrix.RespSendEvent, error)
	RedactEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID, extra ...mautrix.ReqRedact) (*mautrix.RespSendEvent, error)
}

// Asks is a set of open asks. Its reaction handling is not registered on
// any syncer: a program calls HandleReaction from its own reaction
// handler, before treating a reaction as ordinary, and
// TakeAnswerRedaction from its redaction handler.
type Asks struct {
	sender AskSender
	self   id.UserID
	log    zerolog.Logger

	mu    sync.Mutex
	open  map[string]*askState
	order []string // ask ids, oldest first
	done  bool     // Shutdown ran; arm no more timers
	// answers are taps on a widget, answered or refused, so that their
	// redaction is not taken for a deleted message.
	answers *boundedSet
	// refuse removes a tap from outside RestrictTo; a seam for tests.
	refuse func(room id.RoomID, tap id.EventID)
}

// askState is one open, or expired but unclosed, ask.
type askState struct {
	room       id.RoomID
	message    id.EventID
	text       string
	emojis     []string // normalized, parallel to keys
	keys       []string
	restrictTo []id.UserID
	deliver    func(AskAnswer)
	seeds      []id.EventID
	// expired asks answer nothing (their seeds are gone) but stay
	// registered so a late Close still renders the outcome.
	expired bool
	timer   *time.Timer
	// gone is closed when the ask expires or leaves the set, for Wait.
	gone  chan struct{}
	ended bool
}

// NewAsks returns an empty set of asks that sends through s as self and
// logs ids and counts, never question text, to log. Reactions from self
// are the widget's own seeds and never answer.
func NewAsks(s AskSender, self id.UserID, log zerolog.Logger) *Asks {
	a := &Asks{sender: s, self: self, log: log, open: map[string]*askState{}, answers: newBoundedSet(maxAnswerEvents)}
	a.refuse = a.redactRefused
	return a
}

// Asks returns the client's set of asks, made on first use. Close shuts
// it down.
func (c *Client) Asks() *Asks {
	c.asksOnce.Do(func() { c.asks = NewAsks(c, c.UserID, c.Log) })
	return c.asks
}

// Open posts the widget, seeds it, and returns its event without waiting
// for anyone. Each permitted answer goes to deliver, from the goroutine
// that called HandleReaction, until Close.
func (a *Asks) Open(ctx context.Context, ask Ask, deliver func(AskAnswer)) (id.EventID, error) {
	_, msg, err := a.open1(ctx, ask, deliver)
	return msg, err
}

func (a *Asks) open1(ctx context.Context, ask Ask, deliver func(AskAnswer)) (*askState, id.EventID, error) {
	start := time.Now()
	if len(ask.Options) == 0 {
		return nil, "", errors.New("rihma: an ask needs at least one option")
	}
	a.mu.Lock()
	done := a.done
	a.mu.Unlock()
	if done {
		return nil, "", ErrAskClosed
	}
	emojis := assignAskEmojis(ask.Options)
	content := askMarkdown(renderAsk(ask.Text, ask.Options, emojis))
	content.RelatesTo = ask.RelatesTo
	resp, err := a.sender.SendMessageEvent(ctx, ask.Room, event.EventMessage, &content)
	if err != nil {
		return nil, "", fmt.Errorf("rihma: send the ask: %w", err)
	}
	s := &askState{
		room: ask.Room, message: resp.EventID, text: ask.Text, emojis: emojis,
		restrictTo: slices.Clone(ask.RestrictTo), deliver: deliver, gone: make(chan struct{}),
	}
	for _, o := range ask.Options {
		s.keys = append(s.keys, o.Key)
	}
	expiry := time.Duration(-1)
	if ask.Expires > 0 {
		expiry = max(ask.Expires-time.Since(start), 0)
	}
	// Registered before seeding, so a tap racing the seeds still answers.
	a.add(ask.ID, s, expiry)
	for _, emoji := range emojis {
		a.seed(ctx, ask.ID, s, emoji)
	}
	a.log.Info().Str("ask_id", ask.ID).Stringer("event_id", resp.EventID).Int("options", len(emojis)).Msg("ask opened and seeded")
	return s, resp.EventID, nil
}

// Wait opens the ask and blocks until its first permitted answer, until
// ctx ends, or until the ask expires (ErrAskExpired) or leaves the set
// (ErrAskClosed). An answered or expired ask stays open, so the caller
// Closes it with the outcome.
func (a *Asks) Wait(ctx context.Context, ask Ask) (AskAnswer, error) {
	got := make(chan AskAnswer, 1)
	s, _, err := a.open1(ctx, ask, func(ans AskAnswer) {
		select {
		case got <- ans:
		default: // only the first answer is waited for
		}
	})
	if err != nil {
		return AskAnswer{}, err
	}
	select {
	case ans := <-got:
		return ans, nil
	case <-s.gone:
		select {
		case ans := <-got: // an answer that raced the end still counts
			return ans, nil
		default:
		}
		a.mu.Lock()
		expired := s.expired
		a.mu.Unlock()
		if expired {
			return AskAnswer{}, ErrAskExpired
		}
		return AskAnswer{}, ErrAskClosed
	case <-ctx.Done():
		return AskAnswer{}, ctx.Err()
	}
}

// Close withdraws the widget's seeds and edits the outcome, when there
// is one, into the question. Closing an unknown or closed ask succeeds.
func (a *Asks) Close(ctx context.Context, askID, outcome string) error {
	s := a.remove(askID)
	if s == nil {
		a.log.Debug().Str("ask_id", askID).Msg("closing an ask that is not open")
		return nil
	}
	a.mu.Lock()
	seeds := s.seeds
	s.seeds = nil
	a.mu.Unlock()
	a.log.Info().Str("ask_id", askID).Msg("ask closed; withdrawing the widget")
	a.withdraw(askID, s.room, seeds)
	if outcome == "" {
		return nil
	}
	content := askMarkdown(s.text + "\n\n**" + outcome + "**")
	content.SetEdit(s.message)
	if _, err := a.sender.SendMessageEvent(ctx, s.room, event.EventMessage, &content); err != nil {
		return fmt.Errorf("rihma: edit the ask's outcome: %w", err)
	}
	return nil
}

// HandleReaction consumes a reaction that answers an open ask, or that a
// user outside RestrictTo put on one, and reports whether it did. Call it
// before treating a reaction as ordinary. It returns false for anything
// else: another emoji, or a tap on an expired or closed ask.
func (a *Asks) HandleReaction(evt *event.Event) bool {
	if evt.Content.Parsed == nil {
		_ = evt.Content.ParseRaw(evt.Type)
	}
	reaction := evt.Content.AsReaction()
	if reaction == nil || reaction.RelatesTo.Type != event.RelAnnotation {
		return false
	}
	if evt.Sender == a.self && a.self != "" {
		return false // a seed's echo, or the bot reacting as itself
	}
	rel := reaction.RelatesTo
	key := normalizeAskKey(rel.Key)
	a.mu.Lock()
	var askID string
	var s *askState
	for aid, open := range a.open {
		if open.message == rel.EventID {
			askID, s = aid, open
			break
		}
	}
	if s == nil || s.expired {
		a.mu.Unlock()
		return false
	}
	i := slices.Index(s.emojis, key)
	if i < 0 {
		a.mu.Unlock()
		return false
	}
	optionKey, deliver, room := s.keys[i], s.deliver, s.room
	allowed := len(s.restrictTo) == 0 || slices.Contains(s.restrictTo, evt.Sender)
	a.mu.Unlock()

	a.answers.put(evt.ID)
	if !allowed {
		a.log.Info().Str("ask_id", askID).Stringer("sender", evt.Sender).Msg("ignoring an answer from outside restrict_to")
		go a.refuse(room, evt.ID)
		return true
	}
	a.log.Info().Str("ask_id", askID).Stringer("sender", evt.Sender).Msg("answer delivered")
	deliver(AskAnswer{AskID: askID, Key: optionKey, Sender: evt.Sender, Event: evt.ID})
	return true
}

// TakeAnswerRedaction reports whether target was a tap on a widget, and
// forgets it. A program calls it from its redaction handler, so that an
// un-tap is not reported as a deleted message.
func (a *Asks) TakeAnswerRedaction(target id.EventID) bool {
	return a.answers.take(target)
}

// Shutdown stops every expiry timer and releases every Wait, and Open
// fails from then on. The client's Close calls it. The asks stay
// registered, so Close still renders an outcome.
func (a *Asks) Shutdown() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.done = true
	for _, s := range a.open {
		s.stop()
		s.end()
	}
}

// add registers an ask, replacing one with the same id and evicting the
// oldest past maxOpenAsks, and arms its expiry unless expiry is negative.
// Callers close their asks, so the cap only matters when they do not. An
// ask whose question was in flight when Shutdown ran is registered, so
// Close can still withdraw it, but arms nothing and releases its Wait.
func (a *Asks) add(askID string, s *askState, expiry time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if old, ok := a.open[askID]; ok {
		old.stop()
		old.end()
		a.order = slices.DeleteFunc(a.order, func(o string) bool { return o == askID })
	}
	a.open[askID] = s
	a.order = append(a.order, askID)
	for len(a.order) > maxOpenAsks {
		a.open[a.order[0]].stop()
		a.open[a.order[0]].end()
		delete(a.open, a.order[0])
		a.order = a.order[1:]
	}
	switch {
	case a.done:
		s.end()
	case expiry >= 0:
		s.timer = time.AfterFunc(expiry, func() { a.expire(askID, s) })
	}
}

func (a *Asks) remove(askID string) *askState {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.open[askID]
	if !ok {
		return nil
	}
	s.stop()
	s.end()
	delete(a.open, askID)
	a.order = slices.DeleteFunc(a.order, func(o string) bool { return o == askID })
	return s
}

func (s *askState) stop() {
	if s.timer != nil {
		s.timer.Stop()
	}
}

// end releases Wait; the caller holds Asks.mu.
func (s *askState) end() {
	if !s.ended {
		s.ended = true
		close(s.gone)
	}
}

func (a *Asks) seed(ctx context.Context, askID string, s *askState, emoji string) {
	sctx, cancel := context.WithTimeout(ctx, askSeedTimeout)
	defer cancel()
	resp, err := a.sender.SendReaction(sctx, s.room, s.message, emoji)
	if err != nil {
		a.log.Warn().Err(err).Str("ask_id", askID).Msg("seeding an ask option failed")
		return
	}
	a.mu.Lock()
	live := a.open[askID] == s && !s.expired
	if live {
		s.seeds = append(s.seeds, resp.EventID)
	}
	a.mu.Unlock()
	if !live {
		// Closed or expired while seeding: withdraw the straggler too.
		a.withdraw(askID, s.room, []id.EventID{resp.EventID})
	}
}

// expire withdraws the widget but keeps the ask, so that a later Close
// still renders the outcome. Late taps fall through as plain reactions.
func (a *Asks) expire(askID string, s *askState) {
	a.mu.Lock()
	if a.open[askID] != s || s.expired {
		a.mu.Unlock()
		return
	}
	s.expired = true
	s.end()
	seeds := s.seeds
	s.seeds = nil
	a.mu.Unlock()
	a.log.Info().Str("ask_id", askID).Msg("ask expired; withdrawing the widget")
	a.withdraw(askID, s.room, seeds)
}

func (a *Asks) withdraw(askID string, room id.RoomID, seeds []id.EventID) {
	for _, seed := range seeds {
		ctx, cancel := context.WithTimeout(context.Background(), askSeedTimeout)
		_, err := a.sender.RedactEvent(ctx, room, seed)
		cancel()
		if err != nil {
			a.log.Warn().Err(err).Str("ask_id", askID).Stringer("event_id", seed).Msg("withdrawing a seed failed")
		}
	}
}

// redactRefused removes a tap from outside RestrictTo, to keep the widget
// readable. It is best effort: redacting others' events needs power.
func (a *Asks) redactRefused(room id.RoomID, tap id.EventID) {
	ctx, cancel := context.WithTimeout(context.Background(), askSeedTimeout)
	defer cancel()
	if _, err := a.sender.RedactEvent(ctx, room, tap, mautrix.ReqRedact{Reason: "not addressed to you"}); err != nil {
		a.log.Debug().Err(err).Stringer("event_id", tap).Msg("could not redact a tap from outside restrict_to")
	}
}

// normalizeAskKey strips VARIATION SELECTOR-16, which clients add or omit
// at will, so a picker-typed 👍️ matches a seeded 👍.
func normalizeAskKey(key string) string { return strings.ReplaceAll(key, "️", "") }

// assignAskEmojis picks one emoji per option: its hint when present and
// not already taken, else the next free circled digit (①②③…). There are
// twenty; a degenerate ask past that reuses ⑳, as terva-conn-matrix does.
func assignAskEmojis(options []AskOption) []string {
	used := make([]string, 0, len(options))
	fallback := 0
	for _, o := range options {
		emoji := normalizeAskKey(strings.TrimSpace(o.Hint))
		if emoji == "" || slices.Contains(used, emoji) {
			for {
				emoji = string(rune(0x2460 + min(fallback, 19)))
				fallback++
				if !slices.Contains(used, emoji) || fallback > 20 {
					break
				}
			}
		}
		used = append(used, emoji)
	}
	return used
}

// renderAsk is the question, a blank line, and one "- emoji label" per
// option. The legend explains the reaction row and is the numbered
// fallback for clients that cannot show reactions.
func renderAsk(text string, options []AskOption, emojis []string) string {
	var b strings.Builder
	b.WriteString(text)
	b.WriteString("\n\n")
	for i, o := range options {
		fmt.Fprintf(&b, "- %s %s\n", emojis[i], o.Label)
	}
	return b.String()
}

// askMarkdown is a text message rendered from Markdown, with the source
// as its plain body.
func askMarkdown(text string) event.MessageEventContent {
	content := format.RenderMarkdown(text, true, false)
	content.MsgType = event.MsgText
	content.Body = text
	return content
}

// boundedSet remembers the most recent ids, up to size.
type boundedSet struct {
	mu    sync.Mutex
	size  int
	m     map[id.EventID]struct{}
	order []id.EventID
}

func newBoundedSet(size int) *boundedSet {
	return &boundedSet{size: size, m: map[id.EventID]struct{}{}}
}

func (b *boundedSet) put(k id.EventID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.m[k]; ok {
		return
	}
	b.m[k] = struct{}{}
	b.order = append(b.order, k)
	for len(b.order) > b.size {
		delete(b.m, b.order[0])
		b.order = b.order[1:]
	}
}

func (b *boundedSet) take(k id.EventID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.m[k]; !ok {
		return false
	}
	delete(b.m, k)
	b.order = slices.DeleteFunc(b.order, func(o id.EventID) bool { return o == k })
	return true
}
