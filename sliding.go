package rihma

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maunium.net/go/mautrix/id"
)

var (
	ErrSlidingUnsupported = errors.New("rihma: sliding sync dialect or capability unsupported")
	ErrSlidingProtocol    = errors.New("rihma: invalid sliding sync response")
	ErrSlidingStore       = errors.New("rihma: sliding sync recovery store failed")
)

// SlidingSyncDialect names a wire contract, not merely a feature flag.
type SlidingSyncDialect string

// SlidingSyncSynapseExperimental uses query pos/timeout, ranges, required_state
// pairs and list SYNC operations. Tested on Synapse 1.162.0. It does not implement
// the current MSC4186 proposal schema or the legacy sliding-sync proxy.
const SlidingSyncSynapseExperimental SlidingSyncDialect = "synapse-experimental"

// SlidingSyncRange is an inclusive room-list window.
type SlidingSyncRange [2]int

// SlidingSyncList selects windows from a server-sorted room list. Complete state
// is always requested so encryption never infers membership from a partial list.
type SlidingSyncList struct {
	Ranges        []SlidingSyncRange `json:"ranges"`
	TimelineLimit int                `json:"timeline_limit"`
}

// SlidingSyncOptions opts into Sliding Sync. Open copies its configuration;
// change windows/subscriptions by stopping and reopening. Classic is the default.
type SlidingSyncOptions struct {
	Dialect           SlidingSyncDialect         `json:"dialect"`
	Lists             map[string]SlidingSyncList `json:"lists"`
	RoomSubscriptions map[id.RoomID]int          `json:"room_subscriptions,omitempty"`
}

// SlidingSyncCursor keeps the independent connection and device acknowledgements.
// Values are opaque and must never be logged or passed to classic /sync.
type SlidingSyncCursor struct {
	Position string `json:"position"`
	ToDevice string `json:"to_device"`
}

// SlidingSyncBatch is the complete unfiltered wire response. Journal is invoked
// on the Sync owner after the internal recovery record is durable, before crypto
// dispatch/cursor commit. Copy what the application needs; do not retain or mutate
// Raw. Applications own protected timeline storage, idempotent replay, retention
// and delayed decryption. The internal record is a bounded crash-recovery slot,
// not an application timeline. A callback failure returns ErrSyncJournal.
type SlidingSyncBatch struct {
	Dialect        SlidingSyncDialect
	Configuration  string
	Previous, Next SlidingSyncCursor
	Raw            json.RawMessage
}

// SlidingSyncView is the last committed room-list view. Missing rooms in a window
// are not leaves. Raw room metadata can include message content; never log it.
type SlidingSyncView struct {
	Lists  map[string][]id.RoomID        `json:"lists"`
	Counts map[string]int                `json:"counts"`
	Rooms  map[id.RoomID]json.RawMessage `json:"rooms"`
}

// SlidingSyncSnapshot returns a detached copy of the committed view, or nil
// before the owner loads recovery state. It is safe to call from event handlers.
func (c *Client) SlidingSyncSnapshot() *SlidingSyncView {
	c.slidingMu.RLock()
	defer c.slidingMu.RUnlock()
	if c.slidingView == nil {
		return nil
	}
	copy, _ := json.Marshal(c.slidingView)
	var result SlidingSyncView
	_ = json.Unmarshal(copy, &result)
	return &result
}

const slidingMaxResponse = 8 << 20
const slidingMaxRecord = 32 << 20

func (o *SlidingSyncOptions) copied() (*SlidingSyncOptions, error) {
	if o.Dialect != SlidingSyncSynapseExperimental || len(o.Lists)+len(o.RoomSubscriptions) == 0 || len(o.Lists) > 16 || len(o.RoomSubscriptions) > 256 {
		return nil, ErrSlidingUnsupported
	}
	result := &SlidingSyncOptions{Dialect: o.Dialect, Lists: make(map[string]SlidingSyncList), RoomSubscriptions: make(map[id.RoomID]int)}
	for name, list := range o.Lists {
		if len(name) == 0 || len(name) > 64 || len(list.Ranges) == 0 || len(list.Ranges) > 16 || list.TimelineLimit < 0 || list.TimelineLimit > 100 {
			return nil, ErrSlidingUnsupported
		}
		list.Ranges = append([]SlidingSyncRange(nil), list.Ranges...)
		for _, r := range list.Ranges {
			if r[0] < 0 || r[1] < r[0] || r[1] > 9999 {
				return nil, ErrSlidingUnsupported
			}
		}
		result.Lists[name] = list
	}
	for room, limit := range o.RoomSubscriptions {
		if len(room) == 0 || len(room) > 255 || limit < 0 || limit > 100 {
			return nil, ErrSlidingUnsupported
		}
		result.RoomSubscriptions[room] = limit
	}
	return result, nil
}

func slidingFingerprint(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Journal runs synchronously and should return only after an application commit.
type SlidingSyncJournal func(context.Context, *SlidingSyncBatch) error
