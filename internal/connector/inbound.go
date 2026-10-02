package connector

import (
	"context"
	"strings"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"
)

// registerHandlers wires Matrix events to host frames. rihma has already
// dropped our own events and, on the first connect, history.
func (t *transport) registerHandlers(deliver func(connsdk.Message)) {
	h := t.client.Handlers()
	h.OnEventType(event.AccountDataDirectChats, func(_ context.Context, evt *event.Event) {
		if content, ok := evt.Content.Parsed.(*event.DirectChatsEventContent); ok {
			t.dms.set(*content)
		}
	})
	h.OnEventType(event.StateMember, t.handleMember)
	// A sync with no since token is history (rihma discards its
	// messages); membership in it seeds state but announces nothing,
	// as terva-conn-matrix's handler-less first sync does.
	h.OnSync(func(_ context.Context, _ *mautrix.RespSync, since string) bool {
		t.members.setInitial(since == "")
		return true
	})
	forgetTitle := func(_ context.Context, evt *event.Event) { t.titles.forget(evt.RoomID) }
	h.OnEventType(event.StateRoomName, forgetTitle)
	h.OnEventType(event.StateCanonicalAlias, forgetTitle)
	h.OnEventType(event.EventMessage, func(ctx context.Context, evt *event.Event) {
		if fromLeftRoom(evt) {
			return
		}
		if rel := evt.Content.AsMessage().RelatesTo; rel != nil && rel.Type == event.RelReplace {
			if ed, ok := t.translateEdit(ctx, evt); ok {
				t.emit(ctx, chatEvent{edited: &ed})
			}
			return
		}
		if msg, ok := t.translateMessage(ctx, evt); ok {
			deliver(msg)
		} else if msg, ok := t.translateMedia(ctx, evt, false); ok {
			deliver(msg)
		}
	})
	h.OnEventType(event.EventSticker, func(ctx context.Context, evt *event.Event) {
		if fromLeftRoom(evt) {
			return
		}
		if msg, ok := t.translateMedia(ctx, evt, true); ok {
			deliver(msg)
		}
	})
	h.OnEventType(event.EventReaction, t.handleReaction)
	h.OnEventType(event.EventRedaction, t.handleRedaction)
}

// translateMessage maps an m.room.message to a host message. Only m.text
// is delivered: notices and emotes are dropped, as in terva-conn-matrix,
// and media is P5. Edits are P5 and are not new messages, so they are
// dropped here rather than delivered as one.
func (t *transport) translateMessage(ctx context.Context, evt *event.Event) (connsdk.Message, bool) {
	msg := evt.Content.AsMessage()
	if msg.MsgType != event.MsgText {
		return connsdk.Message{}, false
	}
	rel := msg.RelatesTo
	if rel != nil && rel.Type == event.RelReplace {
		return connsdk.Message{}, false
	}
	chatID, kind, title, replyTo := t.inboundShape(ctx, evt, rel)
	parentID, parentKind := t.parentContext(ctx, evt.RoomID, kind)
	text := msg.Body
	if replyTo != "" { // real replies carry the quote fallback; threads' do not
		text = event.TrimReplyFallbackText(text)
	}
	text = unescapeCommand(text)
	in := mentionInput{text: text, mentions: msg.Mentions, repliedToBot: t.sent.has(replyTo.String())}
	if msg.Format == event.FormatHTML {
		in.html = msg.FormattedBody
	}
	return connsdk.Message{
		ID:             evt.ID.String(),
		TS:             evt.Timestamp,
		ChatID:         chatID,
		ChatKind:       kind,
		ChatTitle:      title,
		ParentChatID:   parentID,
		ParentChatKind: parentKind,
		UserID:         evt.Sender.String(),
		Username:       localpart(evt.Sender),
		ReplyTo:        replyTo.String(),
		Text:           text,
		Entities:       extractEntities(in, botIdentity{userID: t.self, displayName: t.displayName(ctx)}),
	}, true
}

// unescapeCommand undoes the Markdown escape Element puts on a leading
// slash. A message typed as /status that Element does not know as a
// command goes out with body \/status, which the host would read as a
// prompt instead of its built-in. In Markdown, which body carries, \/ is
// a literal slash, so the text the person meant starts with /. Element
// parses commands only at the start of the composer, so the escape is
// only ever leading.
func unescapeCommand(text string) string {
	if strings.HasPrefix(text, `\/`) {
		return text[1:]
	}
	return text
}

// localpart is the sender's stable handle. Display names are per room
// and mutable, so they are not used.
func localpart(user id.UserID) string {
	local, _, err := user.Parse()
	if err != nil {
		return user.String()
	}
	return local
}
