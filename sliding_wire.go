package rihma

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type slidingResponse struct {
	Position   string                        `json:"pos"`
	Lists      map[string]json.RawMessage    `json:"lists"`
	Rooms      map[id.RoomID]json.RawMessage `json:"rooms"`
	Extensions map[string]json.RawMessage    `json:"extensions"`
}
type slidingRoom struct {
	Initial       bool           `json:"initial"`
	RequiredState []*event.Event `json:"required_state"`
	InviteState   []*event.Event `json:"invite_state"`
	Timeline      []*event.Event `json:"timeline"`
	Limited       bool           `json:"limited"`
	PrevBatch     string         `json:"prev_batch"`
}
type slidingToDevice struct {
	Next   string         `json:"next_batch"`
	Events []*event.Event `json:"events"`
}
type slidingE2EE struct {
	DeviceLists mautrix.DeviceLists `json:"device_lists"`
	Count       *mautrix.OTKCount   `json:"device_one_time_keys_count"`
	Fallback    []id.KeyAlgorithm   `json:"device_unused_fallback_key_types"`
}

func (c *Client) requestSliding(ctx context.Context, record *slidingRecord, timeout int) ([]byte, error) {
	config := c.opts.SlidingSync
	lists := make(map[string]any, len(config.Lists))
	rooms := make(map[id.RoomID]any, len(config.RoomSubscriptions))
	roomConfig := func(limit int) map[string]any {
		return map[string]any{"timeline_limit": limit, "required_state": [][2]string{{"*", "*"}}}
	}
	for name, list := range config.Lists {
		value := roomConfig(list.TimelineLimit)
		value["ranges"] = list.Ranges
		lists[name] = value
	}
	for room, limit := range config.RoomSubscriptions {
		rooms[room] = roomConfig(limit)
	}
	extensions := map[string]any{
		"e2ee":      map[string]any{"enabled": true},
		"to_device": map[string]any{"enabled": true},
	}
	if record.Cursor.ToDevice != "" {
		extensions["to_device"].(map[string]any)["since"] = record.Cursor.ToDevice
	}
	for _, kind := range []string{"account_data", "typing", "receipts"} {
		extensions[kind] = map[string]any{"enabled": true, "lists": []string{"*"}, "rooms": []string{"*"}}
	}
	body := map[string]any{"conn_id": record.Connection, "lists": lists, "room_subscriptions": rooms, "extensions": extensions}
	query := map[string]string{"timeout": strconv.Itoa(timeout)}
	if record.Cursor.Position != "" {
		query["pos"] = record.Cursor.Position
	}
	log := zerolog.Nop()
	raw, err := c.MakeFullRequest(ctx, mautrix.FullRequest{Method: http.MethodPost,
		URL:         c.BuildURLWithQuery(mautrix.ClientURLPath{"unstable", "org.matrix.simplified_msc3575", "sync"}, query),
		RequestJSON: body, MaxAttempts: 1, SensitiveContent: true, Logger: &log, ResponseSizeLimit: slidingMaxResponse})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return raw, err
}

func decodeSliding(raw []byte) (*slidingResponse, *slidingToDevice, *slidingE2EE, error) {
	if len(raw) == 0 || len(raw) > slidingMaxResponse {
		return nil, nil, nil, ErrSlidingProtocol
	}
	var response slidingResponse
	if json.Unmarshal(raw, &response) != nil || response.Position == "" || len(response.Position) > 4096 || response.Rooms == nil || response.Extensions == nil {
		return nil, nil, nil, ErrSlidingProtocol
	}
	var td slidingToDevice
	var crypto slidingE2EE
	if json.Unmarshal(response.Extensions["to_device"], &td) != nil || td.Next == "" || len(td.Next) > 4096 || !validSlidingEvents(td.Events) || json.Unmarshal(response.Extensions["e2ee"], &crypto) != nil || crypto.Count == nil || crypto.Fallback == nil {
		return nil, nil, nil, ErrSlidingProtocol
	}
	return &response, &td, &crypto, nil
}

func validSlidingEvents(events []*event.Event) bool {
	for _, ev := range events {
		if ev == nil || ev.Type.Type == "" {
			return false
		}
	}
	return true
}

// The raw journal is separate from this narrow adaptation to the upstream
// crypto-aware syncer; unknown fields survive in Raw and the committed view.
func adaptSliding(response *slidingResponse, td *slidingToDevice, crypto *slidingE2EE, record *slidingRecord, self id.UserID) (*mautrix.RespSync, error) {
	result := &mautrix.RespSync{NextBatch: response.Position, ToDevice: mautrix.SyncEventsList{Events: td.Events}, DeviceLists: crypto.DeviceLists, DeviceOTKCount: *crypto.Count, FallbackKeys: crypto.Fallback,
		Rooms: mautrix.RespSyncRooms{Join: make(map[id.RoomID]*mautrix.SyncJoinedRoom), Leave: make(map[id.RoomID]*mautrix.SyncLeftRoom), Invite: make(map[id.RoomID]*mautrix.SyncInvitedRoom), Knock: make(map[id.RoomID]*mautrix.SyncKnockedRoom)}}
	for room, raw := range response.Rooms {
		var data slidingRoom
		if room == "" || json.Unmarshal(raw, &data) != nil || !validSlidingEvents(data.RequiredState) || !validSlidingEvents(data.InviteState) || !validSlidingEvents(data.Timeline) {
			return nil, ErrSlidingProtocol
		}
		membership := record.Membership[room]
		// Required state is the authoritative current snapshot, after timeline state.
		for _, events := range [][]*event.Event{data.Timeline, data.RequiredState, data.InviteState} {
			for _, ev := range events {
				if ev.Type.Type == event.StateMember.Type && ev.StateKey != nil && *ev.StateKey == string(self) {
					value, _ := ev.Content.Raw["membership"].(string)
					membership = value
				}
			}
		}
		if membership != "join" && membership != "invite" && membership != "knock" && membership != "leave" && membership != "ban" {
			return nil, ErrSlidingProtocol
		}
		record.Membership[room] = membership
		state := mautrix.SyncEventsList{Events: data.RequiredState}
		timeline := mautrix.SyncTimeline{SyncEventsList: mautrix.SyncEventsList{Events: data.Timeline}, Limited: data.Limited, PrevBatch: data.PrevBatch}
		switch membership {
		case "invite":
			result.Rooms.Invite[room] = &mautrix.SyncInvitedRoom{State: mautrix.SyncEventsList{Events: data.InviteState}}
		case "knock":
			// The pinned DefaultSyncer has no knock dispatch path. Refuse rather
			// than acknowledge state that application handlers never received.
			return nil, ErrSlidingUnsupported
		case "leave", "ban":
			// The pinned syncer ignores leave StateAfter. Deliver the current
			// required state after historical timeline state under SourceLeave.
			timeline.Events = append(timeline.Events, data.RequiredState...)
			result.Rooms.Leave[room] = &mautrix.SyncLeftRoom{Timeline: timeline}
		case "join":
			result.Rooms.Join[room] = &mautrix.SyncJoinedRoom{StateAfter: &state, Timeline: timeline}
		}
	}
	var account struct {
		Global []*event.Event               `json:"global"`
		Rooms  map[id.RoomID][]*event.Event `json:"rooms"`
	}
	if raw, ok := response.Extensions["account_data"]; ok {
		if json.Unmarshal(raw, &account) != nil || !validSlidingEvents(account.Global) {
			return nil, ErrSlidingProtocol
		}
		result.AccountData.Events = account.Global
		for room, events := range account.Rooms {
			if !validSlidingEvents(events) {
				return nil, ErrSlidingProtocol
			}
			if joined := result.Rooms.Join[room]; joined != nil {
				joined.AccountData.Events = events
			} else if record.Membership[room] == "join" {
				result.Rooms.Join[room] = &mautrix.SyncJoinedRoom{AccountData: mautrix.SyncEventsList{Events: events}}
			}
		}
	}
	for _, kind := range []string{"receipts", "typing"} {
		if raw, ok := response.Extensions[kind]; ok {
			var extension struct {
				Rooms map[id.RoomID]*event.Event `json:"rooms"`
			}
			if json.Unmarshal(raw, &extension) != nil {
				return nil, ErrSlidingProtocol
			}
			for room, ev := range extension.Rooms {
				if ev == nil || ev.Type.Type == "" {
					return nil, ErrSlidingProtocol
				}
				joined := result.Rooms.Join[room]
				if joined == nil && record.Membership[room] == "join" {
					joined = &mautrix.SyncJoinedRoom{}
					result.Rooms.Join[room] = joined
				}
				if joined != nil {
					joined.Ephemeral.Events = append(joined.Ephemeral.Events, ev)
				}
			}
		}
	}
	return result, nil
}

func materializeSliding(record *slidingRecord, response *slidingResponse) error {
	for name, raw := range response.Lists {
		var list struct {
			Count *int `json:"count"`
			Ops   []struct {
				Op    string      `json:"op"`
				Range []int       `json:"range"`
				Rooms []id.RoomID `json:"room_ids"`
			} `json:"ops"`
		}
		if json.Unmarshal(raw, &list) != nil || list.Count == nil || *list.Count < 0 {
			return ErrSlidingProtocol
		}
		view := append([]id.RoomID(nil), record.View.Lists[name]...)
		for _, op := range list.Ops {
			if op.Op != "SYNC" || len(op.Range) != 2 || op.Range[0] < 0 || op.Range[1] < op.Range[0] || op.Range[1] > 9999 || len(op.Rooms) > op.Range[1]-op.Range[0]+1 {
				return ErrSlidingProtocol
			}
			for index := op.Range[0]; index <= op.Range[1]; index++ {
				covered := false
				for _, window := range record.Options.Lists[name].Ranges {
					if index >= window[0] && index <= window[1] {
						covered = true
						break
					}
				}
				if !covered {
					return ErrSlidingProtocol
				}
			}
			expected := min(op.Range[1]-op.Range[0]+1, max(0, *list.Count-op.Range[0]))
			if len(op.Rooms) != expected {
				return ErrSlidingProtocol
			}
			for _, room := range op.Rooms {
				if room == "" {
					return ErrSlidingProtocol
				}
			}
			if len(view) <= op.Range[1] {
				view = append(view, make([]id.RoomID, op.Range[1]+1-len(view))...)
			}
			clear(view[op.Range[0] : op.Range[1]+1])
			copy(view[op.Range[0]:op.Range[1]+1], op.Rooms)
		}
		if len(view) > *list.Count {
			view = view[:*list.Count]
		}
		record.View.Lists[name] = view
		record.View.Counts[name] = *list.Count
	}
	for room, raw := range response.Rooms {
		var prior, delta map[string]json.RawMessage
		if json.Unmarshal(raw, &delta) != nil || delta == nil {
			return ErrSlidingProtocol
		}
		_ = json.Unmarshal(record.View.Rooms[room], &prior)
		if prior == nil {
			prior = make(map[string]json.RawMessage)
		}
		// An initial response replaces old metadata, and deltas patch it.
		var initial bool
		_ = json.Unmarshal(delta["initial"], &initial)
		if initial {
			prior = make(map[string]json.RawMessage)
		}
		for key, value := range delta {
			prior[key] = value
		}
		merged, err := json.Marshal(prior)
		if err != nil {
			return ErrSlidingProtocol
		}
		record.View.Rooms[room] = merged
	}
	return nil
}
