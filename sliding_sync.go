package rihma

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

func (c *Client) runSlidingSync(ctx context.Context) error {
	identity := slidingFingerprint([]string{c.HomeserverURL.String(), string(c.UserID), string(c.DeviceID), string(c.opts.SlidingSync.Dialect)})
	disk, err := openSlidingDisk(ctx, filepath.Join(c.opts.StateDir, "sliding.db"), c.session.PickleKey, identity)
	if err != nil {
		return slidingContextError(ctx, err)
	}
	defer disk.db.Close()
	record, err := disk.load(ctx)
	if err != nil {
		return slidingContextError(ctx, err)
	}
	if record.Options != nil && (record.Configuration != slidingFingerprint(record.Options) || record.Options.Dialect != c.opts.SlidingSync.Dialect) {
		return ErrSlidingStore
	}
	c.publishSlidingView(record)
	// Replay a locally staged exchange before making any new request, even if
	// the server has expired the connection or the caller changed its windows.
	if len(record.Pending) > 0 {
		record, err = c.processSliding(ctx, disk, record)
		if err != nil {
			return err
		}
	}
	if err = c.discoverSliding(ctx); err != nil {
		return err
	}
	fingerprint := slidingFingerprint(c.opts.SlidingSync)
	if record.Configuration != fingerprint {
		record.Configuration = fingerprint
		record.Options = c.opts.SlidingSync
		record.Connection, err = newSlidingConnection()
		if err != nil {
			return err
		}
		record.Cursor.Position = ""
		record.View.Lists = emptySlidingView().Lists
		record.View.Counts = emptySlidingView().Counts
		if err = disk.save(ctx, record); err != nil {
			return err
		}
	}
	c.publishSlidingView(record)
	for attempt := 1; ; {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		timeout := 30000
		if record.Cursor.Position == "" {
			timeout = 0
		}
		raw, err := c.requestSliding(ctx, record, timeout)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var httpErr mautrix.HTTPError
			if errors.As(err, &httpErr) && httpErr.RespError != nil && httpErr.RespError.ErrCode == "M_UNKNOWN_POS" {
				record.Connection, err = newSlidingConnection()
				if err != nil {
					return err
				}
				record.Cursor.Position = ""
				record.View.Lists = emptySlidingView().Lists
				record.View.Counts = emptySlidingView().Counts
				if err = disk.save(ctx, record); err != nil {
					return err
				}
				c.publishSlidingView(record)
				// Bound repeated expired-position refusals instead of a hot loop.
				if err = c.waitSlidingRetry(ctx, backoff(attempt)); err != nil {
					return err
				}
				attempt++
				continue
			}
			if errors.Is(err, mautrix.MUnknownToken) {
				return mautrix.MUnknownToken
			}
			if oauthRefreshRefused(err) {
				return classifySessionEnd(err)
			}
			if errors.As(err, &httpErr) && httpErr.IsStatus(http.StatusNotFound) {
				return ErrSlidingUnsupported
			}
			delay, retry := startupRetryDelay(err, attempt)
			if !retry {
				return ErrSlidingProtocol
			}
			if err = c.waitSlidingRetry(ctx, delay); err != nil {
				return err
			}
			attempt++
			continue
		}
		candidate := *record
		candidate.Pending = raw
		prepared, err := c.prepareSliding(&candidate)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		record.Pending = raw
		if err = disk.save(ctx, record); err != nil {
			return err
		}
		record, err = c.dispatchSliding(ctx, disk, record, prepared)
		if err != nil {
			return err
		}
		attempt = 1
	}
}

func (c *Client) waitSlidingRetry(ctx context.Context, delay time.Duration) error {
	if c.opts.OnSyncRetry != nil {
		c.opts.OnSyncRetry()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) processSliding(ctx context.Context, disk *slidingDisk, previous *slidingRecord) (*slidingRecord, error) {
	if ctx.Err() != nil {
		return previous, ctx.Err()
	}
	prepared, err := c.prepareSliding(previous)
	if err != nil {
		return previous, err
	}
	return c.dispatchSliding(ctx, disk, previous, prepared)
}

type slidingPrepared struct {
	response *slidingResponse
	next     *slidingRecord
	adapted  *mautrix.RespSync
}

// Validate and materialize into a detached next record without store, journal,
// crypto or application side effects. Invalid responses must never be staged.
func (c *Client) prepareSliding(previous *slidingRecord) (*slidingPrepared, error) {
	response, td, crypto, err := decodeSliding(previous.Pending)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(previous)
	if err != nil {
		return nil, ErrSlidingStore
	}
	var next slidingRecord
	err = json.Unmarshal(raw, &next)
	clear(raw)
	if err != nil {
		return nil, ErrSlidingStore
	}
	if previous.Options == nil {
		return nil, ErrSlidingStore
	}
	for name := range response.Lists {
		if _, ok := previous.Options.Lists[name]; !ok {
			return nil, ErrSlidingProtocol
		}
	}
	adapted, err := adaptSliding(response, td, crypto, &next, c.UserID)
	if err != nil {
		return nil, err
	}
	if err = materializeSliding(&next, response); err != nil {
		return nil, err
	}
	next.Cursor = SlidingSyncCursor{Position: response.Position, ToDevice: td.Next}
	next.Pending = nil
	// Check the storage bound before any application/crypto side effects.
	size, err := json.Marshal(next)
	if err != nil {
		return nil, ErrSlidingStore
	}
	tooLarge := len(size) > slidingMaxRecord
	clear(size)
	if tooLarge {
		return nil, ErrSlidingStore
	}
	return &slidingPrepared{response: response, next: &next, adapted: adapted}, nil
}

func (c *Client) dispatchSliding(ctx context.Context, disk *slidingDisk, previous *slidingRecord, prepared *slidingPrepared) (*slidingRecord, error) {
	if ctx.Err() != nil {
		return previous, ctx.Err()
	}
	response, next, adapted := prepared.response, prepared.next, prepared.adapted
	var err error
	if c.opts.SlidingSyncJournal != nil {
		copy := append(json.RawMessage(nil), previous.Pending...)
		batch := &SlidingSyncBatch{Dialect: c.opts.SlidingSync.Dialect, Configuration: previous.Configuration, Previous: previous.Cursor, Next: next.Cursor, Raw: copy}
		err = c.opts.SlidingSyncJournal(ctx, batch)
		clear(copy)
		if err != nil {
			return previous, slidingContextError(ctx, ErrSyncJournal)
		}
	}
	if ctx.Err() != nil {
		return previous, ctx.Err()
	}
	// Seed current state before callbacks can send encrypted replies. The wire
	// state is after the timeline, so the joined adapter also uses StateAfter
	// to keep historical timeline state from overwriting the current snapshot.
	if c.StateStore != nil {
		for roomID, raw := range response.Rooms {
			var room slidingRoom
			_ = json.Unmarshal(raw, &room)
			current := make(map[[2]string]*event.Event)
			for _, events := range [][]*event.Event{room.Timeline, room.RequiredState} {
				for _, ev := range events {
					if ev.StateKey != nil {
						current[[2]string{ev.Type.Type, *ev.StateKey}] = ev
					}
				}
			}
			for _, ev := range current {
				ev.RoomID = roomID
				ev.Type.Class = event.StateEventType
				if ev.Content.ParseRaw(ev.Type) == nil {
					mautrix.UpdateStateStore(ctx, c.StateStore, ev)
				}
			}
		}
	}
	// Bypass only the classic cursor/journal wrapper, preserving all installed
	// sync hooks, state/crypto event handlers and verification admission gates.
	if err = c.syncer.DefaultSyncer.ProcessResponse(ctx, adapted, previous.Cursor.Position); err != nil {
		return previous, slidingContextError(ctx, ErrSyncDispatch)
	}
	if ctx.Err() != nil {
		return previous, ctx.Err()
	}
	if err = disk.save(ctx, next); err != nil {
		return previous, err
	}
	c.publishSlidingView(next)
	return next, nil
}

func (c *Client) publishSlidingView(record *slidingRecord) {
	raw, _ := json.Marshal(record.View)
	var copy SlidingSyncView
	_ = json.Unmarshal(raw, &copy)
	c.slidingMu.Lock()
	c.slidingView = &copy
	c.slidingMu.Unlock()
}

func slidingContextError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// The pinned upstream state handler does not honor IgnoreState. Sliding room
// state represents the end of the timeline: seed it before dispatch, then keep
// historical timeline state from reverting current membership during callbacks.
// Crypto reads and ordinary state updates still use the same underlying store.
type slidingStateStore struct{ mautrix.StateStore }

func (s *slidingStateStore) UpdateState(ctx context.Context, ev *event.Event) {
	if ev.Mautrix.IgnoreState || ev.Mautrix.EventSource&event.SourceTimeline != 0 {
		return
	}
	mautrix.UpdateStateStore(ctx, s.StateStore, ev)
}

func (c *Client) discoverSliding(ctx context.Context) error {
	for attempt := 1; ; attempt++ {
		_, err := c.Versions(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, mautrix.MUnknownToken) {
			return mautrix.MUnknownToken
		}
		if oauthRefreshRefused(err) {
			return classifySessionEnd(err)
		}
		delay, retry := startupRetryDelay(err, attempt)
		if !retry {
			return ErrSlidingUnsupported
		}
		if err = c.waitSlidingRetry(ctx, delay); err != nil {
			return err
		}
	}
	if c.SpecVersions == nil || !c.SpecVersions.UnstableFeatures["org.matrix.simplified_msc3575"] {
		return ErrSlidingUnsupported
	}
	return nil
}
