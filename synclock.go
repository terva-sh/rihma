package rihma

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrSyncInProgress is returned by Sync when another Sync, in this
// process or another, holds the same state directory.
//
// A device must have one sync at a time. The server hands each to-device
// message to whichever sync asks first and drops it once that sync moves
// on, so two syncs on one device split the room keys and Olm messages
// between them and each loses what the other took.
var ErrSyncInProgress = errors.New("rihma: another sync is running on this state directory")

const syncLockName = "sync.lock"

// lockSync takes the state directory's sync lock without waiting. The
// lock is the OS's, so it is released when the process dies.
func lockSync(stateDir string) (unlock func(), err error) {
	f, err := os.OpenFile(filepath.Join(stateDir, syncLockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("rihma: open sync lock: %w", err)
	}
	held, err := tryLock(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("rihma: take sync lock: %w", err)
	}
	if !held {
		f.Close()
		return nil, ErrSyncInProgress
	}
	return func() { unlockFile(f); f.Close() }, nil
}
