package rihma

import (
	"context"
	"errors"
	"sync"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

var (
	ErrSyncDispatch = errors.New("rihma: sync dispatch failed; cursor was not advanced")
	ErrSyncJournal  = errors.New("rihma: sync journal failed; cursor was not advanced")
	ErrSyncCursor   = errors.New("rihma: sync cursor commit failed")
)

// stagedSyncStore intercepts mautrix's early SaveNextBatch. Only ProcessResponse
// commits it after durable journaling and synchronous dispatch. The underlying
// SQL store still owns filter IDs, committed tokens and all crypto state.
type stagedSyncStore struct {
	mautrix.SyncStore
	mu      sync.Mutex
	user    id.UserID
	token   string
	pending bool
}

func (s *stagedSyncStore) SaveNextBatch(ctx context.Context, user id.UserID, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.user, s.token, s.pending = user, token, true
	return nil
}
func (s *stagedSyncStore) commit(ctx context.Context, user id.UserID, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pending || s.user != user || s.token != token {
		return ErrSyncCursor
	}
	if err := s.SyncStore.SaveNextBatch(ctx, user, token); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrSyncCursor
	}
	s.pending = false
	return nil
}

// ProcessResponse preserves DefaultSyncer's handler order and policy hooks.
// With no journal it retains mautrix's original early-cursor behavior.
func (s *syncer) ProcessResponse(ctx context.Context, response *mautrix.RespSync, since string) error {
	if s.journal == nil {
		return s.DefaultSyncer.ProcessResponse(ctx, response, since)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.journal(ctx, response, since); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrSyncJournal
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.DefaultSyncer.ProcessResponse(ctx, response, since); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrSyncDispatch
	}
	return s.cursor.commit(ctx, s.user, response.NextBatch)
}
