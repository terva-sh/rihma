package rihma

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestOneSyncPerStateDir: a second Sync on a state directory that is
// already syncing fails at once, and the lock is free again afterwards.
func TestOneSyncPerStateDir(t *testing.T) {
	h := newTestHS(t)
	c, err := Open(context.Background(), testOptions(t, h, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	stop := runSync(t, c)
	waitFor(t, "the first sync", func() bool { return len(h.seenSinces()) > 0 })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Sync(ctx); !errors.Is(err, ErrSyncInProgress) {
		t.Fatalf("second Sync = %v, want ErrSyncInProgress", err)
	}
	if _, err := lockSync(c.opts.StateDir); !errors.Is(err, ErrSyncInProgress) {
		t.Fatalf("lock from a second open file = %v, want ErrSyncInProgress", err)
	}

	if err := stop(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	unlock, err := lockSync(c.opts.StateDir)
	if err != nil {
		t.Fatalf("lock after Sync returned = %v", err)
	}
	unlock()
}
