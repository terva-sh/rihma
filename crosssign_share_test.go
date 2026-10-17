package rihma

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/olm"
)

// Other clients send cross-signing seeds as unpadded base64. Only a 32-byte
// seed is a key, and its public half is what the server publishes.
func TestParseSeed(t *testing.T) {
	key, err := olm.NewPKSigning()
	if err != nil {
		t.Fatal(err)
	}
	raw := base64.RawStdEncoding.EncodeToString(key.Seed())
	for _, value := range []string{raw, base64.StdEncoding.EncodeToString(key.Seed()), " " + raw + "\n"} {
		seed, ok := parseSeed(value)
		if !ok || seedPublicKey(seed) != key.PublicKey() {
			t.Fatal("a well-formed seed was refused")
		}
	}
	for _, value := range []string{"", "not base64!", base64.RawStdEncoding.EncodeToString([]byte("short"))} {
		if _, ok := parseSeed(value); ok {
			t.Fatal("a malformed seed was accepted")
		}
	}
}

// Stored keys are shared only after Connect has checked them against the
// identity the server publishes. A failed check keeps them private for the
// next try, and keys from before a reset are deleted.
func TestStoredCrossSigningKeysAreSharedOnlyOnceChecked(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	c, err := Open(ctx, testOptions(t, h, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	mach := c.OlmMachine()
	keys, err := mach.GenerateCrossSigningKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := mach.ImportCrossSigningKeys(keys.Seeds()); err != nil {
		t.Fatal(err)
	}
	if err := c.storeCrossSigningSecrets(ctx, mach); err != nil {
		t.Fatal(err)
	}
	if !c.HasCrossSigningKeys() || !shared(t, mach) {
		t.Fatal("keys this device holds are not kept and shared")
	}
	restart := func() {
		mach.CrossSigningKeys = nil
		c.xsign.held.Store(false)
	}
	restart()
	failing := func(context.Context) (*crypto.CrossSigningPublicKeysCache, error) { return nil, errors.New("offline") }
	if err := c.loadCrossSigningSecrets(ctx, mach, failing); err == nil {
		t.Fatal("a failed check reported success")
	}
	if c.HasCrossSigningKeys() || mach.CrossSigningKeys != nil || shared(t, mach) {
		t.Fatal("unchecked keys were loaded or left shareable")
	}
	matching := func(context.Context) (*crypto.CrossSigningPublicKeysCache, error) { return keys.PublicKeys(), nil }
	if err := c.loadCrossSigningSecrets(ctx, mach, matching); err != nil {
		t.Fatal(err)
	}
	if !c.HasCrossSigningKeys() || !shared(t, mach) {
		t.Fatal("checked keys were not loaded and shared")
	}
	restart()
	other, err := mach.GenerateCrossSigningKeys()
	if err != nil {
		t.Fatal(err)
	}
	reset := func(context.Context) (*crypto.CrossSigningPublicKeysCache, error) { return other.PublicKeys(), nil }
	if err := c.loadCrossSigningSecrets(ctx, mach, reset); err != nil {
		t.Fatal(err)
	}
	if c.HasCrossSigningKeys() || shared(t, mach) {
		t.Fatal("keys from before a reset were loaded or shared")
	}
	if err := c.loadCrossSigningSecrets(ctx, mach, matching); err != nil || c.HasCrossSigningKeys() {
		t.Fatal("keys from before a reset were kept")
	}
}

func shared(t *testing.T, mach *crypto.OlmMachine) bool {
	t.Helper()
	for _, secret := range crossSigningSecrets {
		value, err := mach.CryptoStore.GetSecret(context.Background(), secret.name)
		if err != nil {
			t.Fatal(err)
		}
		if value == "" {
			return false
		}
	}
	return true
}

// A request queued behind another honours its own wait and cancellation.
func TestQueuedCrossSigningRequestHonoursItsBounds(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	c, err := Open(ctx, testOptions(t, h, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.xsign.admit() <- struct{}{} // another request is running
	start := time.Now()
	if err := c.RequestCrossSigningKeys(ctx, 50*time.Millisecond); !errors.Is(err, ErrCrossSigningKeysNotShared) {
		t.Fatalf("queued request past its wait = %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := c.RequestCrossSigningKeys(cancelled, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled queued request = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("queued requests waited for the running one")
	}
}

// The wait bounds the whole request, including the server lookups before any
// secret is requested.
func TestSecretRequestsBoundServerLookups(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	c, err := Open(ctx, testOptions(t, h, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	router, release := h.ms.Server.Config.Handler, make(chan struct{})
	t.Cleanup(func() { close(release) }) // before the server closes
	h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/keys/query") || strings.HasSuffix(r.URL.Path, "/room_keys/version") {
			select { // a stalled server
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		router.ServeHTTP(w, r)
	})
	start := time.Now()
	if err := c.RequestCrossSigningKeys(ctx, 100*time.Millisecond); !errors.Is(err, ErrCrossSigningKeysNotShared) {
		t.Fatalf("cross-signing request against a stalled server = %v", err)
	}
	if err := c.RequestKeyBackup(ctx, 100*time.Millisecond); !errors.Is(err, ErrBackupKeyNotShared) {
		t.Fatalf("backup request against a stalled server = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("requests outlived their wait")
	}
}

// The first request after a restart connects, and Connect checks stored keys
// against the server; that lookup is inside the wait too.
func TestFirstSecretRequestAfterRestartIsBounded(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	mach := c.OlmMachine()
	keys, err := mach.GenerateCrossSigningKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := mach.ImportCrossSigningKeys(keys.Seeds()); err != nil {
		t.Fatal(err)
	}
	if err := c.storeCrossSigningSecrets(ctx, mach); err != nil {
		t.Fatal(err)
	}
	c.Close()
	router, release := h.ms.Server.Config.Handler, make(chan struct{})
	t.Cleanup(func() { close(release) }) // before the server closes
	h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/keys/query") {
			select { // a stalled server
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		router.ServeHTTP(w, r)
	})
	for _, request := range []struct {
		name string
		call func(*Client) error
		want error
	}{
		{"cross-signing", func(c *Client) error { return c.RequestCrossSigningKeys(ctx, 100*time.Millisecond) }, ErrCrossSigningKeysNotShared},
		{"backup", func(c *Client) error { return c.RequestKeyBackup(ctx, 100*time.Millisecond) }, ErrBackupKeyNotShared},
	} {
		opts.Login = nil
		c, err := Open(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if err := request.call(c); !errors.Is(err, request.want) {
			t.Fatalf("%s request while connecting to a stalled server = %v", request.name, err)
		}
		if time.Since(start) > 5*time.Second {
			t.Fatalf("%s request outlived its wait", request.name)
		}
		c.Close()
	}
}
