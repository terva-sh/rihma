package connector

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"
)

// Asks as a reaction widget, as terva-conn-matrix's src/matrix/asks.rs
// renders them. Matrix has no buttons, so an ask is its text plus an
// emoji legend, and the bot seeds its own message with one reaction per
// option; a tap on a seed answers. A reaction is an event whose sender
// the origin homeserver authenticated, so answers are attested, with one
// caveat: a hostile federated homeserver can forge events for its own
// users, and the exact-MXID RestrictTo match keeps that to the owner's
// own server. Reaction keys are cleartext even in encrypted rooms, so
// hints must never carry anything sensitive.

const (
	// seedTimeout bounds each seed and each withdrawal. They are widget
	// furniture: a failure degrades the widget, never the ask, because
	// the legend still lists every option.
	seedTimeout      = 5 * time.Second
	minAskExpiry     = time.Second
	maxOpenAsks      = 256
	answerEventsSize = 512
)

// askState is one open, or expired but unclosed, ask.
type askState struct {
	room       id.RoomID
	message    id.EventID
	text       string
	emojis     []string // normalized, parallel to keys
	keys       []string
	restrictTo []string
	deliver    func(connsdk.Answer)
	seeds      []id.EventID
	// expired asks answer nothing (their seeds are gone) but stay
	// registered so a late CloseAsk still renders the outcome.
	expired bool
	timer   *time.Timer
}

type asks struct {
	mu    sync.Mutex
	open  map[string]*askState
	order []string // ask ids, oldest first
	done  bool     // Receive has ended; arm no more timers
	// answerEvents are taps on a widget, answered or refused, so that
	// their redaction is not reported as a deleted message.
	answerEvents *boundedMap[id.EventID, struct{}]
	// refuse removes a tap from outside RestrictTo; a seam for tests.
	refuse func(room id.RoomID, tap id.EventID)
}

func newAsks() *asks {
	return &asks{open: map[string]*askState{}, answerEvents: newBoundedMap[id.EventID, struct{}](answerEventsSize)}
}

// add registers an ask, replacing one with the same id and evicting the
// oldest past maxOpenAsks. The host always closes its asks, so the cap
// only matters when it does not.
func (a *asks) add(askID string, s *askState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if old, ok := a.open[askID]; ok {
		old.stop()
		a.order = slices.DeleteFunc(a.order, func(o string) bool { return o == askID })
	}
	a.open[askID] = s
	a.order = append(a.order, askID)
	for len(a.order) > maxOpenAsks {
		a.open[a.order[0]].stop()
		delete(a.open, a.order[0])
		a.order = a.order[1:]
	}
}

func (a *asks) remove(askID string) *askState {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.open[askID]
	if !ok {
		return nil
	}
	s.stop()
	delete(a.open, askID)
	a.order = slices.DeleteFunc(a.order, func(o string) bool { return o == askID })
	return s
}

// shutdown stops every expiry timer.
func (a *asks) shutdown() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.done = true
	for _, s := range a.open {
		s.stop()
	}
}

func (s *askState) stop() {
	if s.timer != nil {
		s.timer.Stop()
	}
}

// normalizeKey strips VARIATION SELECTOR-16, which clients add or omit
// at will, so a picker-typed 👍️ matches a seeded 👍.
func normalizeKey(key string) string { return strings.ReplaceAll(key, "️", "") }

// assignEmojis picks one emoji per option: its hint when present and not
// already taken, else the next free circled digit (①②③…). There are
// twenty; a degenerate ask past that reuses ⑳, as terva-conn-matrix does.
func assignEmojis(options []connsdk.AskOption) []string {
	used := make([]string, 0, len(options))
	fallback := 0
	for _, o := range options {
		emoji := normalizeKey(strings.TrimSpace(o.Hint))
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
func renderAsk(text string, options []connsdk.AskOption, emojis []string) string {
	var b strings.Builder
	b.WriteString(text)
	b.WriteString("\n\n")
	for i, o := range options {
		fmt.Fprintf(&b, "- %s %s\n", emojis[i], o.Label)
	}
	return b.String()
}

// Ask posts the widget and seeds it, and returns the posted message id
// without waiting for anyone. Answers go to deliver until CloseAsk.
func (t *transport) Ask(ctx context.Context, a connsdk.Ask, deliver func(connsdk.Answer)) (string, error) {
	start := time.Now()
	if len(a.Options) == 0 {
		return "", errors.New("ask carries no options")
	}
	if err := t.ready(ctx); err != nil {
		return "", err
	}
	target, err := t.resolveTarget(ctx, a.ChatID)
	if err != nil {
		return "", err
	}
	room := target.room
	emojis := assignEmojis(a.Options)
	// An ask into a thread renders inside the thread.
	message, err := t.sendMarkdown(ctx, room, renderAsk(a.Text, a.Options, emojis), t.outboundRelation(target, a.ReplyTo))
	if err != nil {
		return "", fmt.Errorf("ask send failed: %w", err)
	}
	t.note(target, message)
	// Not added to t.sent: a reply to the widget is not a reply to the
	// bot's conversation, as in terva-conn-matrix.
	s := &askState{room: room, message: message, text: a.Text, emojis: emojis, restrictTo: a.RestrictTo, deliver: deliver}
	for _, o := range a.Options {
		s.keys = append(s.keys, o.Key)
	}
	// Registered before seeding, so a tap racing the seeds still answers.
	t.asks.add(a.ID, s)
	if a.Expires > 0 {
		// Measured from the command, as the host measures it.
		wait := max(a.Expires, minAskExpiry) - time.Since(start)
		t.asks.mu.Lock()
		if !t.asks.done {
			askID := a.ID
			s.timer = time.AfterFunc(max(wait, 0), func() { t.expireAsk(askID, s) })
		}
		t.asks.mu.Unlock()
	}
	for _, emoji := range emojis {
		t.seed(ctx, a.ID, s, emoji)
	}
	t.log.Info().Str("ask_id", a.ID).Stringer("event_id", message).Int("options", len(emojis)).Msg("ask opened and seeded")
	return message.String(), nil
}

func (t *transport) seed(ctx context.Context, askID string, s *askState, emoji string) {
	sctx, cancel := context.WithTimeout(ctx, seedTimeout)
	defer cancel()
	resp, err := t.client.SendReaction(sctx, s.room, s.message, emoji)
	if err != nil {
		t.log.Warn().Err(err).Str("ask_id", askID).Msg("seeding an ask option failed")
		return
	}
	t.asks.mu.Lock()
	live := t.asks.open[askID] == s && !s.expired
	if live {
		s.seeds = append(s.seeds, resp.EventID)
	}
	t.asks.mu.Unlock()
	if !live {
		// Closed or expired while seeding: withdraw the straggler too.
		t.withdraw(askID, s.room, []id.EventID{resp.EventID})
	}
}

// tryAnswer consumes a reaction that answers an open ask, or that a user
// outside RestrictTo put on one. It returns false for anything else,
// which the caller delivers as a plain reaction: another emoji, or a tap
// on an expired or closed ask.
func (t *transport) tryAnswer(evt *event.Event) bool {
	rel := evt.Content.AsReaction().RelatesTo
	key := normalizeKey(rel.Key)
	t.asks.mu.Lock()
	var askID string
	var s *askState
	for aid, open := range t.asks.open {
		if open.message == rel.EventID {
			askID, s = aid, open
			break
		}
	}
	if s == nil || s.expired {
		t.asks.mu.Unlock()
		return false
	}
	i := slices.Index(s.emojis, key)
	if i < 0 {
		t.asks.mu.Unlock()
		return false
	}
	optionKey, deliver, room := s.keys[i], s.deliver, s.room
	allowed := len(s.restrictTo) == 0 || slices.Contains(s.restrictTo, evt.Sender.String())
	t.asks.mu.Unlock()

	t.asks.answerEvents.put(evt.ID, struct{}{})
	if !allowed {
		t.log.Info().Str("ask_id", askID).Stringer("sender", evt.Sender).Msg("ignoring an answer from outside restrict_to")
		go t.asks.refuse(room, evt.ID)
		return true
	}
	t.log.Info().Str("ask_id", askID).Stringer("sender", evt.Sender).Msg("answer delivered")
	deliver(connsdk.Answer{
		AskID: askID, Key: optionKey, UserID: evt.Sender.String(), Username: localpart(evt.Sender),
		Attestation: connsdk.AttestationAttested,
	})
	return true
}

// redactRefused removes a tap from outside RestrictTo, to keep the widget
// readable. It is best effort: redacting others' events needs power.
func (t *transport) redactRefused(room id.RoomID, tap id.EventID) {
	ctx, cancel := context.WithTimeout(context.Background(), seedTimeout)
	defer cancel()
	if _, err := t.client.RedactEvent(ctx, room, tap, mautrix.ReqRedact{Reason: "not addressed to you"}); err != nil {
		t.log.Debug().Err(err).Stringer("event_id", tap).Msg("could not redact a tap from outside restrict_to")
	}
}

// CloseAsk withdraws the seeds and edits the outcome into the question.
// Closing an unknown or already-closed ask succeeds, as connproto
// specifies; terva-conn-matrix returns an error there instead.
func (t *transport) CloseAsk(ctx context.Context, askID, outcome string) error {
	s := t.asks.remove(askID)
	if s == nil {
		t.log.Debug().Str("ask_id", askID).Msg("closing an ask that is not open")
		return nil
	}
	if err := t.ready(ctx); err != nil {
		return err
	}
	t.asks.mu.Lock()
	seeds := s.seeds
	s.seeds = nil
	t.asks.mu.Unlock()
	t.log.Info().Str("ask_id", askID).Msg("ask closed; withdrawing the widget")
	t.withdraw(askID, s.room, seeds)
	if outcome != "" {
		if err := t.edit(ctx, s.room, s.message, s.text+"\n\n**"+outcome+"**"); err != nil {
			return fmt.Errorf("outcome edit failed: %w", err)
		}
	}
	return nil
}

// expireAsk withdraws the widget but keeps the ask, so that the host's
// later CloseAsk still renders the outcome. Late taps fall through as
// plain reactions.
func (t *transport) expireAsk(askID string, s *askState) {
	t.asks.mu.Lock()
	if t.asks.open[askID] != s || s.expired {
		t.asks.mu.Unlock()
		return
	}
	s.expired = true
	seeds := s.seeds
	s.seeds = nil
	t.asks.mu.Unlock()
	t.log.Info().Str("ask_id", askID).Msg("ask expired; withdrawing the widget")
	t.withdraw(askID, s.room, seeds)
}

func (t *transport) withdraw(askID string, room id.RoomID, seeds []id.EventID) {
	for _, seed := range seeds {
		ctx, cancel := context.WithTimeout(context.Background(), seedTimeout)
		_, err := t.client.RedactEvent(ctx, room, seed)
		cancel()
		if err != nil {
			t.log.Warn().Err(err).Str("ask_id", askID).Stringer("event_id", seed).Msg("withdrawing a seed failed")
		}
	}
}
