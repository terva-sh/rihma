package rihma

import (
	"context"
	"errors"
	"testing"
	"time"

	"maunium.net/go/mautrix"
)

func TestSyncRetryNoticesExcludeFatalErrors(t *testing.T) {
	s := newSyncer()
	notices := 0
	s.onRetry = func() { notices++ }
	if _, err := s.OnFailedSync(nil, mautrix.MUnknownToken); !errors.Is(err, mautrix.MUnknownToken) || notices != 0 {
		t.Fatalf("fatal error = %v, notices = %d", err, notices)
	}
	// A request timeout is transient; it does not mean the sync context
	// ended. mautrix checks that context before invoking OnFailedSync.
	for i, failure := range []error{errors.New("network unavailable"), context.DeadlineExceeded} {
		wait, err := s.OnFailedSync(nil, failure)
		if err != nil || wait != time.Second<<i || notices != i+1 {
			t.Fatalf("transient failure: wait = %v, error = %v, notices = %d", wait, err, notices)
		}
	}
}
