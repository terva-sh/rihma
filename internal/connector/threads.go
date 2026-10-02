package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Threads, as terva-conn-matrix's src/matrix/rooms.rs does them. A Matrix
// thread is a relation tree inside a room, not a chat, so a thread chat
// rides connproto's opaque chat ids as <room_id>;thread=<root_event_id>.
// The convention is private to this connector: the host never parses a
// chat id, and nothing else should learn to.

const (
	threadMarker     = ";thread="
	threadScopesSize = 2048
	threadTitlesSize = 512
	threadLatestSize = 512
	// fetchTimeout bounds a title or scope fetch. Both run inside sync
	// handlers, so a slow server stalls sync by at most this much.
	fetchTimeout = 4 * time.Second
	titleRunes   = 60
)

// chatTarget is a resolved outbound chat: a room, and the thread root
// when the chat id was a thread's.
type chatTarget struct {
	room id.RoomID
	root id.EventID
}

func threadChatID(room id.RoomID, root id.EventID) string {
	return room.String() + threadMarker + root.String()
}

// splitChatID splits a chat id at its first thread marker.
func splitChatID(chatID string) (room, root string, threaded bool) {
	return strings.Cut(chatID, threadMarker)
}

type threads struct {
	// scopes maps an event to the thread root it was delivered or sent
	// under, or to "" when it was room-scoped.
	scopes *boundedMap[id.EventID, id.EventID]
	titles *boundedMap[id.EventID, string]
	// latest is the newest event we know in each thread, for the reply
	// fallback of the next threaded send.
	latest *boundedMap[id.EventID, id.EventID]

	// The server reads, as seams for tests: fetchRoot reads an event's
	// thread root (ok false when the read failed), fetchTitle a root's
	// title.
	fetchRoot  func(ctx context.Context, room id.RoomID, evt id.EventID) (root id.EventID, ok bool)
	fetchTitle func(ctx context.Context, room id.RoomID, root id.EventID) (string, error)
}

func newThreads() *threads {
	return &threads{
		scopes: newBoundedMap[id.EventID, id.EventID](threadScopesSize),
		titles: newBoundedMap[id.EventID, string](threadTitlesSize),
		latest: newBoundedMap[id.EventID, id.EventID](threadLatestSize),
	}
}

// resolveTarget maps a host chat id, a room's or a thread's, to a joined
// room and its thread root.
func (t *transport) resolveTarget(ctx context.Context, chatID string) (chatTarget, error) {
	roomPart, root, threaded := splitChatID(chatID)
	room, err := t.resolveRoom(ctx, roomPart)
	if err != nil {
		return chatTarget{}, err
	}
	if !threaded {
		return chatTarget{room: room}, nil
	}
	rootID, err := eventID(root)
	if err != nil {
		return chatTarget{}, fmt.Errorf("bad thread root in chat id %q: %w", chatID, err)
	}
	return chatTarget{room: room, root: rootID}, nil
}

// resolveChat is the room a chat id lives in. Typing, edits, reactions,
// and deletes act on the room whether the chat is a thread or not.
func (t *transport) resolveChat(ctx context.Context, chatID string) (id.RoomID, error) {
	target, err := t.resolveTarget(ctx, chatID)
	return target.room, err
}

// outboundRelation is the m.relates_to for a send into target. In a
// thread everything carries the thread relation: reply_to becomes a real
// in-thread reply, and otherwise the is_falling_back reply points at the
// newest thread event we know, or the root. In a room, reply_to is a
// rich reply.
func (t *transport) outboundRelation(target chatTarget, replyTo string) *event.RelatesTo {
	reply := t.replyTarget(replyTo)
	switch {
	case target.root != "" && reply != "":
		return (&event.RelatesTo{}).SetThread(target.root, "").SetReplyTo(reply)
	case target.root != "":
		latest, ok := t.threads.latest.get(target.root)
		if !ok {
			latest = target.root
		}
		return (&event.RelatesTo{}).SetThread(target.root, latest)
	case reply != "":
		return (&event.RelatesTo{}).SetReplyTo(reply)
	}
	return nil
}

// replyTarget is the event a host reply_to names, or "". A reply target
// we cannot use should not cost the message itself.
func (t *transport) replyTarget(replyTo string) id.EventID {
	if replyTo == "" {
		return ""
	}
	evtID, err := eventID(replyTo)
	if err != nil {
		t.log.Warn().Str("reply_to", replyTo).Msg("reply_to is not an event id; sending without it")
		return ""
	}
	return evtID
}

// note records the scope an event was delivered or sent under.
func (t *transport) note(target chatTarget, evtID id.EventID) {
	if target.root != "" {
		t.threads.latest.put(target.root, evtID)
	}
	t.threads.scopes.put(evtID, target.root)
}

// scopeOf is the chat id an edit or reaction about target must carry:
// the one target was delivered under, because the host matches message
// events on (chat_id, id). An event not seen this run (an edit today of
// a message from before a restart) is fetched to read its relation.
func (t *transport) scopeOf(ctx context.Context, room id.RoomID, target id.EventID) string {
	root, ok := t.threads.scopes.get(target)
	if !ok {
		if root, ok = t.threads.fetchRoot(ctx, room, target); ok {
			t.threads.scopes.put(target, root)
		}
	}
	return chatTarget{room: room, root: root}.chatID()
}

// cachedScopeOf is scopeOf without the fetch, for redaction targets: a
// redacted event has lost its relations, so there is nothing to read. An
// unknown target degrades to the room.
func (t *transport) cachedScopeOf(room id.RoomID, target id.EventID) string {
	root, _ := t.threads.scopes.get(target)
	return chatTarget{room: room, root: root}.chatID()
}

func (c chatTarget) chatID() string {
	if c.root == "" {
		return c.room.String()
	}
	return threadChatID(c.room, c.root)
}

// fetchScope reads target's thread relation from the server. Only
// messages ride threads in our translation (stickers are room-scoped),
// and an encrypted envelope carries its relation in cleartext. scopeOf
// caches a successful fetch either way and a failed one not at all, so
// a thread message is never pinned as room-scoped.
func (t *transport) fetchScope(ctx context.Context, room id.RoomID, target id.EventID) (id.EventID, bool) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	evt, err := t.client.GetEvent(ctx, room, target)
	if err != nil {
		t.log.Debug().Err(err).Stringer("event_id", target).Msg("thread scope fetch failed")
		return "", false
	}
	var root id.EventID
	if evt.Type.Type == event.EventMessage.Type || evt.Type.Type == event.EventEncrypted.Type {
		root = relationOf(evt.Content.VeryRaw).GetThreadParent()
	}
	return root, true
}

func relationOf(raw json.RawMessage) *event.RelatesTo {
	var c struct {
		RelatesTo *event.RelatesTo `json:"m.relates_to"`
	}
	_ = json.Unmarshal(raw, &c)
	return c.RelatesTo
}

// threadTitle is a snippet of the root's body, cached. It is decoration,
// so a failure caches as "" rather than refetching for every message.
// An encrypted root is decrypted first.
func (t *transport) threadTitle(ctx context.Context, room id.RoomID, root id.EventID) string {
	if title, ok := t.threads.titles.get(root); ok {
		return title
	}
	title, err := t.threads.fetchTitle(ctx, room, root)
	if err != nil {
		t.log.Debug().Err(err).Stringer("event_id", root).Msg("thread root fetch failed")
	}
	t.threads.titles.put(root, title)
	return title
}

func (t *transport) readTitle(ctx context.Context, room id.RoomID, root id.EventID) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	evt, err := t.client.GetEvent(ctx, room, root)
	if err != nil {
		return "", err
	}
	if evt.Type == event.EventEncrypted {
		if t.client.Crypto == nil {
			return "", errors.New("the root is encrypted and crypto is not ready")
		}
		if err := parse(evt); err != nil {
			return "", err
		}
		if evt, err = t.client.Crypto.Decrypt(ctx, evt); err != nil {
			return "", err
		}
	}
	var c struct {
		Body string `json:"body"`
	}
	_ = json.Unmarshal(evt.Content.VeryRaw, &c)
	return snippet(c.Body), nil
}

// snippet is the first line, cut to titleRunes code points with an
// ellipsis when cut.
func snippet(body string) string {
	line, _, _ := strings.Cut(body, "\n")
	line = strings.TrimSuffix(line, "\r")
	r := []rune(line)
	if len(r) <= titleRunes {
		return line
	}
	return string(r[:titleRunes]) + "…"
}

// inboundShape routes an inbound message: an m.thread relation puts it in
// the thread's chat, titled with the root's snippet, and anything else in
// the room. reply_to is set only for a real reply; a thread's fallback
// reply is rendering compatibility, not intent.
func (t *transport) inboundShape(ctx context.Context, evt *event.Event, rel *event.RelatesTo) (chatID, kind, title string, replyTo id.EventID) {
	replyTo = rel.GetNonFallbackReplyTo()
	if root := rel.GetThreadParent(); root != "" {
		t.note(chatTarget{room: evt.RoomID, root: root}, evt.ID)
		return threadChatID(evt.RoomID, root), "thread", t.threadTitle(ctx, evt.RoomID, root), replyTo
	}
	t.note(chatTarget{room: evt.RoomID}, evt.ID)
	kind = t.chatKind(ctx, evt.RoomID)
	return evt.RoomID.String(), kind, t.chatTitle(ctx, evt.RoomID, kind), replyTo
}

func (t *transport) parentContext(ctx context.Context, room id.RoomID, kind string) (string, string) {
	if kind != "thread" {
		return "", ""
	}
	return room.String(), t.chatKind(ctx, room)
}

// StartThread opens a thread. Anchored, the starter (the name) threads
// off the anchor, which becomes the root; anchorless, the starter is the
// root and later sends thread off it.
func (t *transport) StartThread(ctx context.Context, chatID, fromMessageID, name string) (string, error) {
	if err := t.ready(ctx); err != nil {
		return "", err
	}
	target, err := t.resolveTarget(ctx, chatID)
	if err != nil {
		return "", err
	}
	if target.root != "" {
		return "", errors.New("threads do not nest — thread_start needs a plain chat")
	}
	if name == "" {
		return "", errors.New("thread_start carries no name")
	}
	var anchor id.EventID
	var rel *event.RelatesTo
	if fromMessageID != "" {
		if anchor, err = eventID(fromMessageID); err != nil {
			return "", fmt.Errorf("bad from_message_id: %w", err)
		}
		rel = (&event.RelatesTo{}).SetThread(anchor, anchor)
	}
	starter, err := t.sendMarkdown(ctx, target.room, name, rel)
	if err != nil {
		return "", fmt.Errorf("thread starter send failed: %w", err)
	}
	root := anchor
	if root == "" {
		root = starter
	}
	t.note(chatTarget{room: target.room, root: root}, starter)
	t.sent.add(starter.String())
	return threadChatID(target.room, root), nil
}
