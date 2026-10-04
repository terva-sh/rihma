package rihma

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
)

// This characterizes pinned upstream discovery, without contacting an SFU or
// claiming RTC membership/media support. Service URLs are never followed.
func TestRTCDiscoveryDependency(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags map[string]bool
		path  string
	}{
		{"unsupported", nil, ""},
		{"unstable", map[string]bool{"org.matrix.msc4143": true}, "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports"},
		{"stable", map[string]bool{"org.matrix.msc4143.stable": true}, "/_matrix/client/v1/rtc/transports"},
		{"both-prefers-unstable", map[string]bool{"org.matrix.msc4143": true, "org.matrix.msc4143.stable": true}, "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			secret := make([]byte, 32)
			if _, err := rand.Read(secret); err != nil {
				t.Fatal("fixture setup failed")
			}
			token := hex.EncodeToString(secret)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/_matrix/client/versions" {
					_ = json.NewEncoder(w).Encode(map[string]any{"versions": []string{"v1.19"}, "unstable_features": tc.flags})
					return
				}
				calls.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != tc.path || r.Header.Get("Authorization") != "Bearer "+token {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"rtc_transports": []map[string]any{{"type": "livekit", "livekit_service_url": "https://rtc.example.org"}, {"type": "org.example.future"}}})
			}))
			defer server.Close()
			cli, err := mautrix.NewClient(server.URL, "", token)
			if err != nil {
				t.Fatal("client preparation failed")
			}
			cli.Log = zerolog.Nop()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := cli.Versions(ctx); err != nil {
				t.Fatal("capability discovery failed")
			}
			result, err := cli.RTCTransports(ctx)
			if tc.path == "" {
				if err == nil || result != nil || calls.Load() != 0 {
					t.Fatal("unsupported capability issued a discovery request")
				}
				return
			}
			if err != nil || result == nil || len(result.RTCTransports) != 2 || calls.Load() != 1 {
				t.Fatal("transport discovery failed")
			}
			if result.RTCTransports[0].Type != mautrix.RTCTransportTypeLivekit || result.RTCTransports[0].LivekitServiceURL != "https://rtc.example.org" || result.RTCTransports[1].Type != "org.example.future" {
				t.Fatal("typed transport metadata changed")
			}
		})
	}
}

func TestRTCDiscoveryWireLimits(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		count      int
	}{
		{"empty", `{"rtc_transports":[]}`, 200, 0},
		// Latest proposal uses transports/m.livekit, which the pinned decoder
		// silently ignores. This characterization is a production prerequisite.
		{"latest-proposal-is-not-supported", `{"transports":[{"type":"m.livekit"}]}`, 200, 0},
		{"forbidden", `{"errcode":"M_FORBIDDEN","error":"fixture refusal"}`, 403, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			cli, err := mautrix.NewClient(server.URL, "", "")
			if err != nil {
				t.Fatal("client preparation failed")
			}
			cli.Log = zerolog.Nop()
			cli.SpecVersions = &mautrix.RespVersions{UnstableFeatures: map[string]bool{"org.matrix.msc4143.stable": true}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := cli.RTCTransports(ctx)
			if tc.status != 200 {
				var refusal mautrix.HTTPError
				if !errors.As(err, &refusal) || !refusal.IsStatus(tc.status) || !errors.Is(err, mautrix.MForbidden) {
					t.Fatal("Matrix refusal not preserved")
				}
				return
			}
			if err != nil || result == nil || len(result.RTCTransports) != tc.count {
				t.Fatal("discovery schema characterization changed")
			}
		})
	}
}

func TestRTCDiscoveryCancellation(t *testing.T) {
	entered, shutdown := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
		case <-shutdown:
		}
	}))
	defer func() { close(shutdown); server.Close() }()
	cli, err := mautrix.NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal("client preparation failed")
	}
	cli.Log = zerolog.Nop()
	cli.SpecVersions = &mautrix.RespVersions{UnstableFeatures: map[string]bool{"org.matrix.msc4143": true}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := cli.RTCTransports(ctx); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not arrive")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation not preserved")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not stop")
	}
}
