package connector

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"
)

// membership reports the bot's own admission changes, as
// terva-conn-matrix's src/matrix/inbound.rs does: "added" when it joins,
// credited to whoever invited it, and "removed" when it leaves, is
// kicked, or is banned, credited to the event's sender.
//
// Whether a membership event is a change is read from the event itself:
// unsigned.prev_content says what it replaced, so a display-name change
// (join over join) and a duplicate are no change, and that holds across
// restarts. Rust keeps an in-memory set seeded from the store at connect;
// rihma keeps the same set only for an event that arrives without
// prev_content.
type membership struct {
	mu        sync.Mutex
	initial   bool // the sync being dispatched had no since token: history
	announced map[id.RoomID]bool
	inviters  map[id.RoomID]id.UserID
	frames    chan connsdk.Membership
}

func newMembership() *membership {
	return &membership{
		announced: map[id.RoomID]bool{},
		inviters:  map[id.RoomID]id.UserID{},
		frames:    make(chan connsdk.Membership, 64),
	}
}

// change decides what a membership event of the bot means. It returns
// the frame's change ("added" or "removed", or "" for none) and who did
// it.
func (m *membership) change(evt *event.Event) (string, id.UserID) {
	room := evt.RoomID
	now := evt.Content.AsMember().Membership
	prev, known := prevMembership(evt)

	m.mu.Lock()
	defer m.mu.Unlock()
	switch now {
	case event.MembershipInvite:
		m.inviters[room] = evt.Sender
		return "", ""
	case event.MembershipJoin:
		was := m.announced[room]
		if known {
			was = prev == event.MembershipJoin
		}
		m.announced[room] = true
		if was || m.initial {
			return "", ""
		}
		by := m.inviters[room]
		delete(m.inviters, room)
		if by == "" && known && prev == event.MembershipInvite {
			by = evt.Unsigned.PrevSender
		}
		return "added", by
	case event.MembershipLeave, event.MembershipBan:
		was := m.announced[room]
		if known {
			was = prev == event.MembershipJoin
		}
		delete(m.announced, room)
		delete(m.inviters, room)
		if !was || m.initial {
			return "", ""
		}
		return "removed", evt.Sender
	}
	return "", ""
}

func (m *membership) setInitial(initial bool) {
	m.mu.Lock()
	m.initial = initial
	m.mu.Unlock()
}

// prevMembership reads the membership this event replaced.
func prevMembership(evt *event.Event) (event.Membership, bool) {
	pc := evt.Unsigned.PrevContent
	if pc == nil {
		return "", false
	}
	if member, ok := pc.Parsed.(*event.MemberEventContent); ok {
		return member.Membership, true
	}
	var member event.MemberEventContent
	if err := json.Unmarshal(pc.VeryRaw, &member); err != nil {
		return "", false
	}
	return member.Membership, true
}

// handleMember turns the bot's own membership events into frames, and
// joins invites when auto_join allows.
func (t *transport) handleMember(ctx context.Context, evt *event.Event) {
	if evt.GetStateKey() != t.self.String() {
		return
	}
	change, by := t.members.change(evt)
	if evt.Content.AsMember().Membership == event.MembershipInvite {
		t.acceptInvite(ctx, evt)
		return
	}
	if change == "" {
		return
	}
	kind := t.chatKind(ctx, evt.RoomID)
	frame := connsdk.Membership{
		ChatID: evt.RoomID.String(), ChatKind: kind, ChatTitle: t.chatTitle(ctx, evt.RoomID, kind),
		Change: change,
	}
	if by != "" {
		frame.ByUserID, frame.ByUsername = by.String(), localpart(by)
	}
	t.log.Info().Stringer("room_id", evt.RoomID).Str("change", change).Msg("membership")
	select {
	case t.members.frames <- frame:
	case <-ctx.Done():
	}
}

// acceptInvite joins when auto_join allows, retrying twice, and records
// an is_direct invite as a DM.
func (t *transport) acceptInvite(ctx context.Context, evt *event.Event) {
	log := t.log.With().Stringer("room_id", evt.RoomID).Stringer("inviter", evt.Sender).Logger()
	if !t.cfg.autoJoin() {
		log.Info().Msg("invite left pending: auto_join is never")
		return
	}
	var err error
	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		if _, err = t.client.JoinRoomByID(ctx, evt.RoomID); err == nil {
			break
		}
	}
	if err != nil {
		log.Warn().Err(err).Msg("auto-join failed after 3 attempts")
		return
	}
	direct := evt.Content.AsMember().IsDirect
	if direct {
		if err := t.dms.add(ctx, t.client, evt.Sender, evt.RoomID); err != nil {
			log.Warn().Err(err).Msg("joined a DM but could not record it in m.direct")
		}
	}
	log.Info().Bool("direct", direct).Msg("joined after invite")
}

// ReceiveMembership delivers the frames the sync handlers produce.
func (t *transport) ReceiveMembership(ctx context.Context, deliver func(connsdk.Membership)) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case f := <-t.members.frames:
			deliver(f)
		}
	}
}

// titles caches group titles: m.room.name, else the canonical alias,
// else empty. matrix-sdk would compute one from the member heroes for an
// unnamed room; rihma does not, and the host only displays it.
type titles struct {
	mu     sync.Mutex
	byRoom map[id.RoomID]string
}

func (c *titles) get(room id.RoomID) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.byRoom[room]
	return s, ok
}

func (c *titles) set(room id.RoomID, title string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byRoom == nil {
		c.byRoom = map[id.RoomID]string{}
	}
	c.byRoom[room] = title
}

func (c *titles) forget(room id.RoomID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byRoom, room)
}

// chatTitle is empty for a DM, as in terva-conn-matrix. A failed read
// gives "" and is retried next time.
func (t *transport) chatTitle(ctx context.Context, room id.RoomID, kind string) string {
	if kind == "dm" {
		return ""
	}
	if s, ok := t.titles.get(room); ok {
		return s
	}
	var name event.RoomNameEventContent
	err := t.client.StateEvent(ctx, room, event.StateRoomName, "", &name)
	if err == nil && name.Name != "" {
		t.titles.set(room, name.Name)
		return name.Name
	}
	if err != nil && !errors.Is(err, mautrix.MNotFound) {
		t.log.Warn().Err(err).Stringer("room_id", room).Msg("reading the room name failed")
		return ""
	}
	var alias event.CanonicalAliasEventContent
	err = t.client.StateEvent(ctx, room, event.StateCanonicalAlias, "", &alias)
	if err != nil && !errors.Is(err, mautrix.MNotFound) {
		t.log.Warn().Err(err).Stringer("room_id", room).Msg("reading the room alias failed")
		return ""
	}
	t.titles.set(room, alias.Alias.String())
	return alias.Alias.String()
}

// displayName is the bot's global display name, read once. A failed read
// is retried on the next message.
func (t *transport) displayName(ctx context.Context) string {
	t.nameMu.Lock()
	defer t.nameMu.Unlock()
	if t.nameLoaded {
		return t.name
	}
	resp, err := t.client.GetDisplayName(ctx, t.self)
	if err != nil && !errors.Is(err, mautrix.MNotFound) {
		t.log.Warn().Err(err).Msg("reading the bot's display name failed")
		return ""
	}
	if resp != nil {
		t.name = resp.DisplayName
	}
	t.nameLoaded = true
	return t.name
}
