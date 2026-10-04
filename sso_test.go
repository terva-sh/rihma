package rihma

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
)

func TestSSOLoginDiscoveryAndRedirect(t *testing.T) {
	for _, flows := range []string{
		`{"flows":[{"type":"m.login.sso"},{"type":"m.login.token"},{"type":"m.login.password"}]}`,
		`{"flows":[{"type":"m.login.sso"}]}`,
		`{"flows":[{"type":"m.login.password"}]}`,
		`{"flows":[{"type":"example.unknown"}]}`,
	} {
		t.Run(flows, func(t *testing.T) {
			hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/tenant/_matrix/client/v3/login" || r.Header.Get("Authorization") != "" {
					t.Error("discovery used authentication or incorrect endpoint")
				}
				w.Write([]byte(flows))
			}))
			defer hs.Close()
			caps, err := DiscoverLoginFlows(context.Background(), hs.URL+"/tenant")
			if err != nil {
				t.Fatal("discovery failed")
			}
			callback := "http://127.0.0.1:32123/callback?state=synthetic%2Bbinding%26nonce"
			browser, err := caps.SSORedirectURL(callback)
			if !caps.SSO || !caps.Token {
				if browser != "" || !errors.Is(err, ErrSSOUnsupported) {
					t.Fatal("incomplete classic flows exposed SSO")
				}
				return
			}
			if err != nil || !caps.Password {
				t.Fatal("advertised capabilities lost")
			}
			u, err := url.Parse(browser)
			if err != nil || u.Scheme+"://"+u.Host != hs.URL || u.Path != "/tenant/_matrix/client/v3/login/sso/redirect" || u.Query().Get("redirectUrl") != callback || len(u.Query()) != 1 {
				t.Fatal("redirect escaped discovered server or changed callback")
			}
			for _, callback := range []string{
				"https://callback.example.invalid/sso", "http://[::1]:32123/callback", "http://localhost:32123/callback",
			} {
				if _, err := caps.SSORedirectURL(callback); err != nil {
					t.Fatal("valid callback rejected")
				}
			}
			for _, callback := range []string{
				"", "/callback", "javascript:alert(1)", "http://callback.example.invalid/sso", "http://localhost/callback",
				"http://127.0.0.1:0/callback", "https://callback.example.invalid:99999/sso",
				"https://user:synthetic-secret@callback.example.invalid/sso", "https://callback.example.invalid/sso#fragment",
				"https://callback.example.invalid/sso?loginToken=synthetic-secret", "https://callback.example.invalid/sso?state=%zz",
			} {
				if browser, err := caps.SSORedirectURL(callback); browser != "" || !errors.Is(err, ErrSSOCallback) {
					t.Fatal("invalid callback escaped fixed error")
				}
			}
		})
	}
}

func TestSSODiscoveryFailureAndCancellation(t *testing.T) {
	for _, homeserver := range []string{"", "http://example.invalid", "https://user:synthetic-secret@example.invalid", "https://example.invalid/?synthetic-secret", "https://example.invalid/#fragment"} {
		if _, err := DiscoverLoginFlows(context.Background(), homeserver); !errors.Is(err, ErrLoginDiscovery) {
			t.Fatal("invalid homeserver exposed unsafe error")
		}
	}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"synthetic-remote-secret"}`))
	}))
	defer hs.Close()
	if _, err := DiscoverLoginFlows(context.Background(), hs.URL); !errors.Is(err, ErrLoginDiscovery) {
		t.Fatal("discovery returned remote reason")
	}
	null := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`null`))
	}))
	defer null.Close()
	if _, err := DiscoverLoginFlows(context.Background(), null.URL); !errors.Is(err, ErrLoginDiscovery) {
		t.Fatal("null capability response accepted")
	}
	entered := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	defer slow.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := DiscoverLoginFlows(ctx, slow.URL); done <- err }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("discovery did not preserve caller cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("discovery cancellation did not terminate")
	}
}

func TestSSOTokenExchangePreservesStoredSessionAndRejectsReuse(t *testing.T) {
	h := newTestHS(t)
	const token = "synthetic-single-use-sso-token"
	var consumed atomic.Bool
	var exchanges atomic.Int32
	inner := h.ms.Server.Config.Handler
	h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/_matrix/client/v3/login" {
			inner.ServeHTTP(w, r)
			return
		}
		exchanges.Add(1)
		var login mautrix.ReqLogin
		if json.NewDecoder(r.Body).Decode(&login) != nil || login.Type != mautrix.AuthTypeToken || login.Token != token || login.Password != "" || login.Identifier.User != "" {
			t.Error("incorrect single-use login request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if consumed.Swap(true) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"token already consumed"}`))
			return
		}
		// The mock homeserver resolves this token to its fixture account. Its
		// normal login endpoint uses Identifier to build the authenticated device.
		login.Identifier = mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: testUser.String()}
		body, _ := json.Marshal(login)
		r.Body = io.NopCloser(bytes.NewReader(body))
		inner.ServeHTTP(w, r)
	})
	ctx := context.Background()
	opts := testOptions(t, h, t.TempDir())
	opts.Login = &mautrix.ReqLogin{Type: mautrix.AuthTypeToken, Token: token}
	var logs bytes.Buffer
	opts.Logger = zerolog.New(&logs).Level(zerolog.TraceLevel)
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal("token initialization failed")
	}
	device := c.DeviceID
	if err := c.Close(); err != nil {
		t.Fatal("token client close failed")
	}
	sess, err := opts.Sessions.Load(ctx)
	if err != nil || sess == nil || sess.UserID != testUser || sess.DeviceID != device || sess.AccessToken == "" || len(sess.PickleKey) != 32 || exchanges.Load() != 1 {
		t.Fatal("token login did not persist complete session")
	}
	for _, secret := range []string{token, sess.AccessToken} {
		if bytes.Contains(logs.Bytes(), []byte(secret)) {
			t.Fatal("authentication value reached logs")
		}
	}
	opts.Login = &mautrix.ReqLogin{Type: mautrix.AuthTypeToken, Token: "synthetic-other-token"}
	restored, err := Open(ctx, opts)
	if err != nil {
		t.Fatal("existing session restore failed")
	}
	if restored.DeviceID != device || exchanges.Load() != 1 {
		t.Fatal("SSO token replaced existing session")
	}
	restored.Close()
	fresh := testOptions(t, h, t.TempDir())
	fresh.Login = &mautrix.ReqLogin{Type: mautrix.AuthTypeToken, Token: token}
	fresh.Logger = zerolog.New(&logs).Level(zerolog.TraceLevel)
	if c, err := Open(ctx, fresh); err == nil {
		c.Close()
		t.Fatal("consumed SSO token reused")
	}
	if sess, err := fresh.Sessions.Load(ctx); err != nil || sess != nil {
		t.Fatal("failed token exchange persisted a session")
	}
	if bytes.Contains(logs.Bytes(), []byte(token)) {
		t.Fatal("failed token exchange logged credential")
	}
}
