package connector

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"terva.sh/rihma"
)

// dms is our m.direct account data: which rooms are DMs, and with whom.
// The server copy is authoritative; this is a cache refreshed from sync
// and, for cold addressing, from the server directly. An incremental sync
// carries m.direct only when it changes, so after a restart the cache is
// empty until loaded is set.
type dms struct {
	mu     sync.Mutex
	loaded bool
	byUser event.DirectChatsEventContent
	rooms  map[id.RoomID]bool
}

func (d *dms) set(content event.DirectChatsEventContent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loaded = true
	d.byUser = content
	d.rooms = make(map[id.RoomID]bool)
	for _, rooms := range content {
		for _, r := range rooms {
			d.rooms[r] = true
		}
	}
}

func (d *dms) isLoaded() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.loaded
}

func (d *dms) isDM(room id.RoomID) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rooms[room]
}

func (d *dms) roomsWith(user id.UserID) []id.RoomID {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.byUser[user])
}

// refresh reads m.direct from the server. A missing event is no DMs.
func (d *dms) refresh(ctx context.Context, c *rihma.Client) error {
	var content event.DirectChatsEventContent
	err := c.GetAccountData(ctx, event.AccountDataDirectChats.Type, &content)
	if errors.Is(err, mautrix.MNotFound) {
		content = event.DirectChatsEventContent{}
	} else if err != nil {
		return err
	}
	d.set(content)
	return nil
}

// add records room as a DM with user in our m.direct on the server, the
// way clients do when they accept an is_direct invite, so it is still a
// DM after a restart.
func (d *dms) add(ctx context.Context, c *rihma.Client, user id.UserID, room id.RoomID) error {
	if err := d.refresh(ctx, c); err != nil {
		return err
	}
	d.mu.Lock()
	content := make(event.DirectChatsEventContent, len(d.byUser)+1)
	for u, rooms := range d.byUser {
		content[u] = slices.Clone(rooms)
	}
	d.mu.Unlock()
	if slices.Contains(content[user], room) {
		return nil
	}
	content[user] = append(content[user], room)
	if err := c.SetAccountData(ctx, event.AccountDataDirectChats.Type, content); err != nil {
		return err
	}
	d.set(content)
	return nil
}

func (t *transport) joined(ctx context.Context, room id.RoomID) bool {
	m, err := t.client.StateStore.GetMember(ctx, room, t.client.UserID)
	return err == nil && m != nil && m.Membership == event.MembershipJoin
}

// resolveRoom maps a host chat id's room part to a joined room. A room id must be a
// room we are in. A user id is cold owner addressing: before the owner's
// first DM in a host run, terva addresses them by user id, which resolves
// to our joined m.direct DM with them. rihma never creates a DM to
// satisfy it (handoff §6; terva-conn-matrix PLAN §9).
func (t *transport) resolveRoom(ctx context.Context, chatID string) (id.RoomID, error) {
	switch {
	case strings.HasPrefix(chatID, "!"):
		room := id.RoomID(chatID)
		if !t.joined(ctx, room) {
			return "", fmt.Errorf("not joined to chat %s", chatID)
		}
		return room, nil
	case strings.HasPrefix(chatID, "@"):
		user := id.UserID(chatID)
		if _, _, err := user.Parse(); err != nil {
			return "", fmt.Errorf("chat id %q is not a room id or a valid user id", chatID)
		}
		if room, ok := t.joinedDMWith(ctx, user); ok {
			return room, nil
		}
		// The cache may predate the DM; ask the server once.
		if err := t.dms.refresh(ctx, t.client); err != nil {
			return "", fmt.Errorf("chat id %s is a user id; reading m.direct failed: %w", chatID, err)
		}
		if room, ok := t.joinedDMWith(ctx, user); ok {
			return room, nil
		}
		return "", fmt.Errorf("chat id %s is a user id, not a room id, and no joined DM with that user exists yet", chatID)
	default:
		return "", fmt.Errorf("chat id %q is not a room id or a user id", chatID)
	}
}

func (t *transport) joinedDMWith(ctx context.Context, user id.UserID) (id.RoomID, bool) {
	for _, room := range t.dms.roomsWith(user) {
		if t.joined(ctx, room) {
			return room, true
		}
	}
	return "", false
}

// chatKind loads m.direct from the server the first time it is needed.
// It runs from a sync handler, so the server has just answered; if the
// read fails anyway the room reads as a group and the next message tries
// again.
func (t *transport) chatKind(ctx context.Context, room id.RoomID) string {
	if !t.dms.isLoaded() {
		if err := t.dms.refresh(ctx, t.client); err != nil {
			t.log.Warn().Err(err).Msg("reading m.direct failed; chat kind falls back to group")
		}
	}
	if t.dms.isDM(room) {
		return "dm"
	}
	return "group"
}
