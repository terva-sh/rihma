package rihma

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

type filterTransport func(*http.Request) (*http.Response, error)

func (f filterTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type filterTimeout struct{}

func (filterTimeout) Error() string   { return "synthetic transport timeout" }
func (filterTimeout) Timeout() bool   { return true }
func (filterTimeout) Temporary() bool { return true }

// Fail one bootstrap request, then prove delivery and a warm cursor on a
// newly opened client. Cover the retryable HTTP statuses and a transport error.
func TestSyncRetriesFilterCreation(t *testing.T) {
	for _, kind := range []string{"gateway", "server", "rate_limit", "transport"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			h := newTestHS(t)
			opts := testOptions(t, h, t.TempDir())
			opts.Logger = zerolog.Nop()
			var retries atomic.Int32
			opts.OnSyncRetry = func() { retries.Add(1) }
			c, err := Open(ctx, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var calls atomic.Int32
			transport := c.Client.Client.Transport
			if transport == nil {
				transport = http.DefaultTransport
			}
			c.Client.Client.Transport = filterTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/_matrix/client/v3/user/"+testUser.String()+"/filter" && calls.Add(1) == 1 {
					switch kind {
					case "transport":
						return nil, filterTimeout{}
					case "server":
						return &http.Response{StatusCode: 500, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
					case "rate_limit":
						return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": {"1"}}, Body: http.NoBody, Request: r}, nil
					default:
						return &http.Response{StatusCode: 502, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
					}
				}
				return transport.RoundTrip(r)
			})
			const room = id.RoomID("!room:localhost")
			h.script(roomSync("b1", room), roomSync("b2", room, textEvent("@human:localhost", "$after-filter", "delivered")))
			s := watch(c)
			stop := runSync(t, c)
			waitFor(t, "delivery after bootstrap retry", func() bool { return len(s.messages()) == 1 })
			if err := stop(); !errors.Is(err, context.Canceled) {
				t.Fatalf("Sync = %v", err)
			}
			if calls.Load() != 2 || retries.Load() != 1 {
				t.Fatalf("filter requests = %d, notices = %d", calls.Load(), retries.Load())
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			opts.Login = nil
			restored, err := Open(ctx, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			before := h.filters.Load()
			stop = runSync(t, restored)
			waitFor(t, "warm sync", func() bool { return len(h.seenSinces()) >= 4 })
			if err := stop(); !errors.Is(err, context.Canceled) {
				t.Fatalf("warm Sync = %v", err)
			}
			if h.filters.Load() != before+1 {
				t.Fatal("warm Sync should recreate its filter once, as SQLCryptoStore does not persist filter IDs")
			}
		})
	}
}

func TestSyncFilterFatalErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   string
		want   error
	}{
		{"token", 401, "M_UNKNOWN_TOKEN", mautrix.MUnknownToken},
		{"forbidden", 403, "M_FORBIDDEN", mautrix.MForbidden},
		{"bad_request", 400, "M_BAD_JSON", mautrix.MBadJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHS(t)
			opts := testOptions(t, h, t.TempDir())
			opts.Logger = zerolog.Nop()
			notices := 0
			opts.OnSyncRetry = func() { notices++ }
			c, err := Open(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			originalHandler := h.ms.Server.Config.Handler
			h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_matrix/client/v3/user/"+testUser.String()+"/filter" {
					h.filters.Add(1)
					w.WriteHeader(tc.status)
					w.Write([]byte(`{"errcode":"` + tc.code + `","error":"synthetic failure"}`))
					return
				}
				originalHandler.ServeHTTP(w, r)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := c.Sync(ctx); !errors.Is(err, tc.want) {
				t.Fatalf("Sync = %v, want %v", err, tc.want)
			}
			if h.filters.Load() != 1 || notices != 0 || len(h.seenSinces()) != 0 {
				t.Fatalf("filter requests = %d, notices = %d, sync requests = %d", h.filters.Load(), notices, len(h.seenSinces()))
			}
		})
	}
}

type filterFailureStore struct {
	mautrix.SyncStore
	loadErr, saveErr         error
	filterID                 string
	nextLoadErr, nextSaveErr error
}

func (s filterFailureStore) LoadFilterID(context.Context, id.UserID) (string, error) {
	return s.filterID, s.loadErr
}
func (s filterFailureStore) SaveFilterID(context.Context, id.UserID, string) error { return s.saveErr }

func (s filterFailureStore) LoadNextBatch(ctx context.Context, user id.UserID) (string, error) {
	if s.nextLoadErr != nil {
		return "", s.nextLoadErr
	}
	return s.SyncStore.LoadNextBatch(ctx, user)
}
func (s filterFailureStore) SaveNextBatch(ctx context.Context, user id.UserID, next string) error {
	if s.nextSaveErr != nil {
		return s.nextSaveErr
	}
	return s.SyncStore.SaveNextBatch(ctx, user, next)
}

func TestSyncFilterStoreErrorsAreFatal(t *testing.T) {
	for _, phase := range []string{"load", "save", "next_load", "next_save"} {
		t.Run(phase, func(t *testing.T) {
			h := newTestHS(t)
			opts := testOptions(t, h, t.TempDir())
			opts.Logger = zerolog.Nop()
			notices := 0
			opts.OnSyncRetry = func() { notices++ }
			c, err := Open(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			// A store returning an error that looks transient still must not retry.
			sentinel := filterTimeout{}
			store := filterFailureStore{SyncStore: c.Store}
			switch phase {
			case "load":
				store.loadErr = sentinel
			case "save":
				store.saveErr = sentinel
			case "next_load":
				store.filterID = "cached"
				store.nextLoadErr = sentinel
			case "next_save":
				store.filterID = "cached"
				store.nextSaveErr = sentinel
				h.script(roomSync("b1", "!room:localhost"))
			}
			c.Store = store
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := c.Sync(ctx); !errors.Is(err, sentinel) {
				t.Fatalf("Sync = %v, want store error", err)
			}
			want := int32(0)
			if phase == "save" {
				want = 1
			}
			wantSync := 0
			if phase == "next_save" {
				wantSync = 1
			}
			if h.filters.Load() != want || notices != 0 || len(h.seenSinces()) != wantSync {
				t.Fatalf("filter requests = %d, notices = %d, sync requests = %d", h.filters.Load(), notices, len(h.seenSinces()))
			}
			if got, ok := c.Store.(filterFailureStore); !ok || got != store {
				t.Fatal("Sync did not restore original store")
			}
		})
	}
}

func TestSyncFilterCancellation(t *testing.T) {
	for _, phase := range []string{"request", "backoff"} {
		t.Run(phase, func(t *testing.T) {
			h := newTestHS(t)
			opts := testOptions(t, h, t.TempDir())
			opts.Logger = zerolog.Nop()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			notices := 0
			opts.OnSyncRetry = func() { notices++; cancel() }
			c, err := Open(ctx, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			calls := 0
			c.Client.Client.Transport = filterTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if phase == "request" {
					cancel()
				}
				return nil, filterTimeout{}
			})
			if err := c.Sync(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("Sync = %v", err)
			}
			want := 0
			if phase == "backoff" {
				want = 1
			}
			if calls != 1 || notices != want {
				t.Fatalf("requests = %d, notices = %d", calls, notices)
			}
			unlock, err := lockSync(opts.StateDir)
			if err != nil {
				t.Fatalf("sync lock not released: %v", err)
			}
			unlock()
		})
	}
}

func TestFilterRetryAfter(t *testing.T) {
	err := mautrix.HTTPError{Response: &http.Response{StatusCode: 503, Header: http.Header{"Retry-After": {"120"}}}}
	if delay, retry := startupRetryDelay(err, 1); !retry || delay != 120*time.Second {
		t.Fatalf("delay = %v, retry = %v", delay, retry)
	}
}

func TestSyncFilterRejectsMissingID(t *testing.T) {
	for _, response := range []string{"null", "{}"} {
		t.Run(response, func(t *testing.T) {
			h := newTestHS(t)
			opts := testOptions(t, h, t.TempDir())
			opts.Logger = zerolog.Nop()
			notices := 0
			opts.OnSyncRetry = func() { notices++ }
			c, err := Open(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			original := h.ms.Server.Config.Handler
			h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/_matrix/client/v3/user/"+testUser.String()+"/filter" {
					h.filters.Add(1)
					w.Write([]byte(response))
					return
				}
				original.ServeHTTP(w, r)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			if err := c.Sync(ctx); err == nil || ctx.Err() != nil {
				t.Fatalf("missing filter ID: err=%v, timed_out=%t", err, ctx.Err() != nil)
			}
			if notices != 0 || h.filters.Load() != 1 || len(h.seenSinces()) != 0 {
				t.Fatalf("notices=%d, filters=%d, syncs=%d", notices, h.filters.Load(), len(h.seenSinces()))
			}
		})
	}
}

// A truncated error body must not turn a permanent status into a retry.
func TestStartupRetryKeepsPermanentHTTPFatal(t *testing.T) {
	err := mautrix.HTTPError{Response: &http.Response{StatusCode: 403}, WrappedError: io.ErrUnexpectedEOF}
	if _, retry := startupRetryDelay(err, 1); retry {
		t.Fatal("permanent HTTP error was retried because its body was truncated")
	}
}
