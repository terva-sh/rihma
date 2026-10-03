package rihma

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"testing"
	"time"
)

func TestSyncStopsOnDeviceMismatch(t *testing.T) {
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	opts.Logger = zerolog.Nop()
	ctx := context.Background()
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	session, err := opts.Sessions.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	session.DeviceID = "MISMATCH"
	if err := opts.Sessions.Save(ctx, session); err != nil {
		t.Fatal(err)
	}
	opts.Login = nil
	notices := 0
	opts.OnSyncRetry = func() { notices++ }
	c, err = Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err = c.Sync(ctx)
	if notices != 0 || ctx.Err() != nil {
		t.Fatalf("deterministic local mismatch retried: notices=%d, timed_out=%t", notices, ctx.Err() != nil)
	}
	if err == nil {
		t.Fatal("Sync ignored device mismatch")
	}
}

func TestSyncStopsOnPermanentConnectHTTPError(t *testing.T) {
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	opts.Logger = zerolog.Nop()
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	opts.Login = nil
	notices := 0
	opts.OnSyncRetry = func() { notices++ }
	c, err = Open(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	original := h.ms.Server.Config.Handler
	h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/keys/query") {
			w.WriteHeader(403)
			w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"synthetic failure"}`))
			return
		}
		original.ServeHTTP(w, r)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Sync(ctx); !errors.Is(err, mautrix.MForbidden) {
		t.Fatalf("Sync = %v, want original forbidden error", err)
	}
	if notices != 0 || ctx.Err() != nil || h.filters.Load() != 0 {
		t.Fatalf("permanent Connect error: notices=%d, timed_out=%t, filters=%d", notices, ctx.Err() != nil, h.filters.Load())
	}
}
