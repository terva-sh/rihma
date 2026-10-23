//go:build e2e

package rihma

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// TestE2ERTCDiscovery negotiates transport discovery with the throwaway
// Synapse, whose template enables MSC4143 with placeholder transports that
// nothing contacts. Synapse speaks only the unstable dialect.
func TestE2ERTCDiscovery(t *testing.T) {
	hs := e2eHomeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	user, password := "rtc-"+e2eTag(), "pw-"+e2eTag()
	register(t, ctx, hs, user, password)
	c, err := Open(ctx, e2eOptions(t, hs, user, password, filepath.Join(t.TempDir(), "rtc")))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.DiscoverRTCTransports(ctx, RTCTransportsStable); !errors.Is(err, ErrRTCUnsupported) {
		t.Fatalf("stable dialect not refused: %v", err)
	}
	result, err := c.DiscoverRTCTransports(ctx)
	if err != nil {
		t.Fatalf("discovery failed (does the harness template enable msc4143?): %v", err)
	}
	if result.Dialect != RTCTransportsUnstable || len(result.Transports) != 2 {
		t.Fatalf("negotiated %s with %d transports", result.Dialect, len(result.Transports))
	}
	live, future := result.Transports[0], result.Transports[1]
	if live.Type != "livekit" || live.LiveKit == nil || live.LiveKit.URL != "wss://sfu.example.org" || live.LiveKit.ServiceURL != "https://rtc.example.org" {
		t.Fatal("LiveKit transport metadata changed")
	}
	if future.Type != "org.example.future" || future.LiveKit != nil || string(future.Raw) != `{"type":"org.example.future","region":"eu"}` {
		t.Fatal("unknown transport not preserved")
	}

	// The pinned SDK reads the same unstable dialect; the two must agree.
	// Discovery leaves SpecVersions alone, so the SDK needs its own fetch.
	if c.SpecVersions != nil {
		t.Fatal("discovery wrote the shared versions cache")
	}
	if _, err := c.Versions(ctx); err != nil {
		t.Fatal(err)
	}
	sdk, err := c.Client.RTCTransports(ctx)
	if err != nil || len(sdk.RTCTransports) != 2 || sdk.RTCTransports[0].LivekitServiceURL != live.LiveKit.ServiceURL {
		t.Fatal("pinned SDK disagrees on the unstable dialect")
	}
}
