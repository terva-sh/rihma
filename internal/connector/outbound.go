package connector

import (
	"context"
	"fmt"
	"time"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"
)

// typingTimeout is how long the server shows us typing per PUT. The
// host refreshes every TypingRefresh (20 s), well inside it.
const typingTimeout = 30 * time.Second

// ready makes sure encryption is up before anything leaves. The host
// can send as soon as we report connected, which is before Sync has
// initialized crypto, and mautrix sends plaintext into an encrypted room
// when it has no crypto. Connect is idempotent.
func (t *transport) ready(ctx context.Context) error {
	if err := t.client.Connect(ctx); err != nil {
		return fmt.Errorf("encryption not ready: %w", err)
	}
	return nil
}

func (t *transport) Send(ctx context.Context, out connsdk.Outgoing) error {
	_, err := t.SendWithID(ctx, out)
	return err
}

// SendWithID sends markdown as m.text: body is the source as written,
// formatted_body the rendered HTML. Chunking to MaxTextLen is the host's.
func (t *transport) SendWithID(ctx context.Context, out connsdk.Outgoing) (string, error) {
	return t.sendText(ctx, out, nil)
}

// sendText is SendWithID with an optional speaker profile.
func (t *transport) sendText(ctx context.Context, out connsdk.Outgoing, profile *event.BeeperPerMessageProfile) (string, error) {
	if err := t.ready(ctx); err != nil {
		return "", err
	}
	target, err := t.resolveTarget(ctx, out.ChatID)
	if err != nil {
		return "", err
	}
	content := markdown(out.Text)
	content.RelatesTo = t.outboundRelation(target, out.ReplyTo)
	content.BeeperPerMessageProfile = profile
	resp, err := t.client.SendMessageEvent(ctx, target.room, event.EventMessage, &content)
	if err != nil {
		return "", fmt.Errorf("send failed: %w", err)
	}
	evtID := resp.EventID
	t.note(target, evtID)
	t.sent.add(evtID.String())
	return evtID.String(), nil
}

// markdown is text as m.text: body is the source as written,
// formatted_body the rendered HTML.
func markdown(text string) event.MessageEventContent {
	content := format.RenderMarkdown(text, true, false)
	content.MsgType = event.MsgText
	content.Body = text
	return content
}

func (t *transport) sendMarkdown(ctx context.Context, room id.RoomID, text string, rel *event.RelatesTo) (id.EventID, error) {
	content := markdown(text)
	content.RelatesTo = rel
	resp, err := t.client.SendMessageEvent(ctx, room, event.EventMessage, &content)
	if err != nil {
		return "", err
	}
	return resp.EventID, nil
}

func (t *transport) Typing(ctx context.Context, chatID string) error {
	return t.setTyping(ctx, chatID, true)
}

func (t *transport) StopTyping(ctx context.Context, chatID string) error {
	return t.setTyping(ctx, chatID, false)
}

// setTyping is fire-and-forget for the host: failures are logged, as in
// terva-conn-matrix, and returned so connsdk can log them too.
func (t *transport) setTyping(ctx context.Context, chatID string, typing bool) error {
	room, err := t.resolveChat(ctx, chatID)
	if err != nil {
		return err
	}
	if _, err := t.client.UserTyping(ctx, room, typing, typingTimeout); err != nil {
		t.log.Warn().Err(err).Stringer("room_id", room).Bool("typing", typing).Msg("typing update failed")
		return err
	}
	return nil
}
