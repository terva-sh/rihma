package connector

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"
)

// Edits, deletes, and reactions, both ways, as terva-conn-matrix's
// src/matrix/{inbound,outbound}.rs do them. The bot's own events never
// arrive here: rihma drops them before any handler runs, which is the
// echo hygiene the protocol asks of reactions as of messages.

// boundedMap forgets its oldest insertion past its size.
type boundedMap[K comparable, V any] struct {
	mu    sync.Mutex
	size  int
	m     map[K]V
	order []K
}

func newBoundedMap[K comparable, V any](size int) *boundedMap[K, V] {
	return &boundedMap[K, V]{size: size, m: map[K]V{}}
}

func (b *boundedMap[K, V]) put(k K, v V) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.m[k]; !ok {
		b.order = append(b.order, k)
	}
	b.m[k] = v
	for len(b.order) > b.size {
		delete(b.m, b.order[0])
		b.order = b.order[1:]
	}
}

func (b *boundedMap[K, V]) get(k K) (V, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[k]
	return v, ok
}

// take removes and returns the entry for k.
func (b *boundedMap[K, V]) take(k K) (V, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[k]
	if ok {
		delete(b.m, k)
		for i, o := range b.order {
			if o == k {
				b.order = append(b.order[:i], b.order[i+1:]...)
				break
			}
		}
	}
	return v, ok
}

const (
	seenReactionsSize = 1024
	ourReactionsSize  = 256
)

// chatEvent is one frame for ReceiveChatEvents; exactly one field is set.
type chatEvent struct {
	edited   *connsdk.MessageEdited
	deleted  *connsdk.MessageDeleted
	reaction *connsdk.Reaction
}

type reactionKey struct {
	message id.EventID
	key     string
}

// chatEvents is the transport's event-stream state.
type chatEvents struct {
	frames chan chatEvent
	// seen maps a reaction event to the frame it produced, so its
	// redaction can be reported as the same reaction removed.
	seen *boundedMap[id.EventID, connsdk.Reaction]
	// ours maps a reaction the bot sent to its event, for removal.
	ours *boundedMap[reactionKey, id.EventID]
}

func newChatEvents() *chatEvents {
	return &chatEvents{
		frames: make(chan chatEvent, 64),
		seen:   newBoundedMap[id.EventID, connsdk.Reaction](seenReactionsSize),
		ours:   newBoundedMap[reactionKey, id.EventID](ourReactionsSize),
	}
}

func (t *transport) emit(ctx context.Context, ev chatEvent) {
	select {
	case t.events.frames <- ev:
	case <-ctx.Done():
	}
}

// ReceiveChatEvents delivers the frames the sync handlers produce.
func (t *transport) ReceiveChatEvents(ctx context.Context, sink connsdk.ChatEventSink) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-t.events.frames:
			switch {
			case ev.edited != nil && sink.Edited != nil:
				sink.Edited(*ev.edited)
			case ev.deleted != nil && sink.Deleted != nil:
				sink.Deleted(*ev.deleted)
			case ev.reaction != nil && sink.Reaction != nil:
				sink.Reaction(*ev.reaction)
			}
		}
	}
}

// fromLeftRoom is true for timeline events of a room the bot has left,
// which terva-conn-matrix does not deliver.
func fromLeftRoom(evt *event.Event) bool { return evt.Mautrix.EventSource&event.SourceLeave != 0 }

// translateEdit maps an m.replace to message_edited under the original
// id. Every edit is its own frame; the host coalesces. Only text edits
// are delivered.
func (t *transport) translateEdit(ctx context.Context, evt *event.Event) (connsdk.MessageEdited, bool) {
	msg := evt.Content.AsMessage()
	nc := msg.NewContent
	if msg.RelatesTo == nil || nc == nil || nc.MsgType != event.MsgText {
		return connsdk.MessageEdited{}, false
	}
	mentions := nc.Mentions
	if mentions == nil {
		mentions = msg.Mentions
	}
	text := unescapeCommand(nc.Body)
	in := mentionInput{text: text, mentions: mentions}
	if nc.Format == event.FormatHTML {
		in.html = nc.FormattedBody
	}
	original := msg.RelatesTo.EventID
	return connsdk.MessageEdited{
		ChatID:   t.scopeOf(ctx, evt.RoomID, original),
		ID:       original.String(),
		TS:       evt.Timestamp,
		Text:     text,
		Entities: extractEntities(in, botIdentity{userID: t.self, displayName: t.displayName(ctx)}),
	}, true
}

func (t *transport) handleReaction(ctx context.Context, evt *event.Event) {
	if fromLeftRoom(evt) {
		return
	}
	rel := evt.Content.AsReaction().RelatesTo
	if rel.Type != event.RelAnnotation || rel.EventID == "" {
		return
	}
	if t.tryAnswer(evt) {
		return
	}
	r := connsdk.Reaction{
		ChatID: t.scopeOf(ctx, evt.RoomID, rel.EventID), MessageID: rel.EventID.String(),
		UserID: evt.Sender.String(), Username: localpart(evt.Sender), Key: rel.Key,
	}
	t.events.seen.put(evt.ID, r)
	t.emit(ctx, chatEvent{reaction: &r})
}

// handleRedaction reports a redacted reaction as that reaction removed,
// credited to the reactor, and anything else as message_deleted; the
// host ignores ids it never saw.
func (t *transport) handleRedaction(ctx context.Context, evt *event.Event) {
	if fromLeftRoom(evt) {
		return
	}
	target := evt.Redacts
	if target == "" { // room v11 moved it into content
		target = evt.Content.AsRedaction().Redacts
	}
	if target == "" {
		return
	}
	if _, ok := t.asks.answerEvents.take(target); ok {
		return // an un-tap; the protocol has no answer retraction
	}
	if r, ok := t.events.seen.take(target); ok {
		r.Removed = true
		t.emit(ctx, chatEvent{reaction: &r})
		return
	}
	t.emit(ctx, chatEvent{deleted: &connsdk.MessageDeleted{ChatID: t.cachedScopeOf(evt.RoomID, target), ID: target.String()}})
}

func eventID(messageID string) (id.EventID, error) {
	if len(messageID) < 2 || messageID[0] != '$' {
		return "", fmt.Errorf("bad message id %q", messageID)
	}
	return id.EventID(messageID), nil
}

// EditMessage replaces a message's text with rendered markdown; clients
// that ignore edits see the "* " fallback.
func (t *transport) EditMessage(ctx context.Context, chatID, messageID, text string) error {
	if err := t.ready(ctx); err != nil {
		return err
	}
	room, err := t.resolveChat(ctx, chatID)
	if err != nil {
		return err
	}
	target, err := eventID(messageID)
	if err != nil {
		return err
	}
	if err := t.edit(ctx, room, target, text); err != nil {
		return fmt.Errorf("edit failed: %w", err)
	}
	return nil
}

func (t *transport) edit(ctx context.Context, room id.RoomID, target id.EventID, text string) error {
	content := markdown(text)
	content.SetEdit(target)
	_, err := t.client.SendMessageEvent(ctx, room, event.EventMessage, &content)
	return err
}

func (t *transport) DeleteMessage(ctx context.Context, chatID, messageID string) error {
	if err := t.ready(ctx); err != nil {
		return err
	}
	room, err := t.resolveChat(ctx, chatID)
	if err != nil {
		return err
	}
	target, err := eventID(messageID)
	if err != nil {
		return err
	}
	if _, err := t.client.RedactEvent(ctx, room, target); err != nil {
		return fmt.Errorf("delete failed: %w", err)
	}
	return nil
}

// React adds or removes the bot's reaction. Removal finds the bot's
// reaction event in memory, or after a restart from the target's
// relations.
func (t *transport) React(ctx context.Context, chatID, messageID, key string, remove bool) error {
	if err := t.ready(ctx); err != nil {
		return err
	}
	room, err := t.resolveChat(ctx, chatID)
	if err != nil {
		return err
	}
	target, err := eventID(messageID)
	if err != nil {
		return err
	}
	rk := reactionKey{target, key}
	if !remove {
		resp, err := t.client.SendReaction(ctx, room, target, key)
		if err != nil {
			return fmt.Errorf("react failed: %w", err)
		}
		t.events.ours.put(rk, resp.EventID)
		return nil
	}
	ours, ok := t.events.ours.take(rk)
	if !ok {
		if ours, err = t.findOurReaction(ctx, room, target, key); err != nil {
			return err
		}
	}
	if _, err := t.client.RedactEvent(ctx, room, ours); err != nil {
		return fmt.Errorf("react remove failed: %w", err)
	}
	return nil
}

// findOurReaction looks through the target's annotations for the bot's
// reaction with key. mautrix never encrypts reactions, but another client
// on the bot's account may have, so encrypted ones are decrypted first.
func (t *transport) findOurReaction(ctx context.Context, room id.RoomID, target id.EventID, key string) (id.EventID, error) {
	resp, err := t.client.GetRelations(ctx, room, target, &mautrix.ReqGetRelations{RelationType: event.RelAnnotation, Limit: 100})
	if err != nil {
		return "", fmt.Errorf("react remove failed: reading reactions: %w", err)
	}
	for _, evt := range resp.Chunk {
		if evt.Sender != t.self {
			continue
		}
		if evt.Type == event.EventEncrypted {
			if err := parse(evt); err != nil {
				continue
			}
			dec, err := t.client.Crypto.Decrypt(ctx, evt)
			if err != nil {
				continue
			}
			evt = dec
		}
		if evt.Type != event.EventReaction || parse(evt) != nil {
			continue
		}
		if rel := evt.Content.AsReaction().RelatesTo; rel.Key == key && rel.EventID == target {
			return evt.ID, nil
		}
	}
	return "", fmt.Errorf("no reaction of ours with key %q to remove", key)
}

// parse fills Content.Parsed for an event read outside sync.
func parse(evt *event.Event) error {
	if evt.Content.Parsed != nil {
		return nil
	}
	err := evt.Content.ParseRaw(evt.Type)
	if errors.Is(err, event.ErrContentAlreadyParsed) {
		return nil
	}
	return err
}
