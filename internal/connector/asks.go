package connector

import (
	"context"
	"errors"
	"time"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"

	"terva.sh/rihma"
)

// Asks are rihma's reaction widget (rihma.Asks), which renders them as
// terva-conn-matrix does. The connector resolves the chat, places the
// widget in its thread, and translates answers into connsdk's terms.

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
	// An ask into a thread renders inside the thread.
	ask := rihmaAsk(a, target.room, t.outboundRelation(target, a.ReplyTo), time.Since(start))
	message, err := t.asks.Open(ctx, ask, func(ans rihma.AskAnswer) { deliver(answerOf(ans)) })
	if err != nil {
		return "", err
	}
	t.note(target, message)
	// Not added to t.sent: a reply to the widget is not a reply to the
	// bot's conversation, as in terva-conn-matrix.
	return message.String(), nil
}

// minAskExpiry is the shortest expiry an ask gets, as terva-conn-matrix
// gives it.
const minAskExpiry = time.Second

// rihmaAsk is a host's ask in rihma's terms, elapsed after the command.
func rihmaAsk(a connsdk.Ask, room id.RoomID, rel *event.RelatesTo, elapsed time.Duration) rihma.Ask {
	ask := rihma.Ask{ID: a.ID, Room: room, Text: a.Text, RelatesTo: rel}
	for _, o := range a.Options {
		ask.Options = append(ask.Options, rihma.AskOption{Key: o.Key, Label: o.Label, Hint: o.Hint})
	}
	for _, u := range a.RestrictTo {
		ask.RestrictTo = append(ask.RestrictTo, id.UserID(u))
	}
	if a.Expires > 0 {
		// Measured from the command, as the host measures it, with a
		// floor of a second; rihma measures from Open, so the time already
		// spent comes off. An ask already overdue expires once posted.
		ask.Expires = max(max(a.Expires, minAskExpiry)-elapsed, time.Nanosecond)
	}
	return ask
}

// answerOf is a widget answer in connsdk's terms. A reaction's sender
// was authenticated by its homeserver, so the answer is attested.
func answerOf(ans rihma.AskAnswer) connsdk.Answer {
	return connsdk.Answer{
		AskID: ans.AskID, Key: ans.Key, UserID: ans.Sender.String(), Username: localpart(ans.Sender),
		Attestation: connsdk.AttestationAttested,
	}
}

// CloseAsk withdraws the seeds and edits the outcome into the question.
// Closing an unknown or already-closed ask succeeds, as connproto
// specifies; terva-conn-matrix returns an error there instead. It needs
// no ready check: an open ask was posted after one. Before Connect there
// are no asks, so every ask is unknown.
func (t *transport) CloseAsk(ctx context.Context, askID, outcome string) error {
	if t.asks == nil {
		return nil
	}
	return t.asks.Close(ctx, askID, outcome)
}
