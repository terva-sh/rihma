package connector

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A login that fails must leave the working session as it was: the
// session in config.json, the store, and the homeserver it points at.
func TestSetupFailedLoginKeepsSession(t *testing.T) {
	tervaHome(t, true)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/versions"):
			_, _ = w.Write([]byte(`{"versions":["v1.11"]}`))
		case strings.HasSuffix(r.URL.Path, "/login"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"Invalid password"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errcode":"M_UNRECOGNIZED"}`))
		}
	}))
	defer hs.Close()

	old := fileConfig{HomeserverURL: "https://old.example", UserID: "@bot:old.example", DeviceID: "OLDDEVICE",
		Session: &sessionSecrets{AccessToken: "old-token-0123456789", PickleKey: "cGlja2xl"}}
	if err := saveConfig(old); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(storeDir(), "marker")
	if err := os.MkdirAll(storeDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	in, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.WriteString(hs.URL + "\n@bot:new.example\nwrong\n")
	w.Close()
	var out strings.Builder
	setupErr := setup(in, &out)

	got, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.HomeserverURL != old.HomeserverURL || got.DeviceID != old.DeviceID ||
		got.Session == nil || got.Session.AccessToken != old.Session.AccessToken {
		t.Fatalf("config after a failed login = %+v, want the old session kept", got)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the store was touched: %v", err)
	}
	if _, err := os.Stat(stagingDir()); !os.IsNotExist(err) {
		t.Fatalf("the staging store was left behind: %v", err)
	}
	if setupErr == nil || !strings.Contains(setupErr.Error(), "untouched") {
		t.Fatalf("setup = %v, want a login failure that says the session is untouched", setupErr)
	}
	if strings.Contains(out.String(), "replacing") {
		t.Fatalf("setup announced a replacement before the login worked:\n%s", out.String())
	}
}
