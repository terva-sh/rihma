package rihma

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/id"
)

var oauthTestClient = OAuthClientMetadata{
	ClientName: "Synthetic client",
	ClientURI:  "https://app.example.org/",
	PolicyURI:  "https://docs.app.example.org/privacy",
}

const oauthTestRedirect = "http://127.0.0.1:43123/callback"

// oauthFake is a hermetic Matrix Authentication Service stand-in. The test
// homeserver serves its metadata and whoami; the issuer registers clients,
// redeems codes against their PKCE challenge, rotates refresh tokens and
// revokes sessions. Access tokens are minted through the mock homeserver's
// login so its other endpoints accept them.
type oauthFake struct {
	t   *testing.T
	hs  *testHS
	srv *httptest.Server

	hsRequests     atomic.Int32
	issuerRequests atomic.Int32
	hsMu           sync.Mutex // the mock homeserver's token map is not synchronized

	mu                 sync.Mutex
	tweak              func(map[string]any)
	stableMissing      bool
	issParam           bool
	expiresIn          int
	omitRefresh        bool
	refuseRefresh      bool
	exchangeStatus     int
	registerStatus     int
	registerAuthMethod string
	revokeStatus       int
	whoamiDevice       id.DeviceID
	blockToken         chan struct{}
	blockWhoami        chan struct{}
	onFirstUse         func(access string)
	clients            map[string]map[string]any
	codes              map[string]*fakeCode
	refresh            map[string]*fakeRefresh
	fresh              map[string]bool
	secrets            []string
	exchanges          int
	refreshes          int
	revokes            int
	logouts            int
	lastRevoke         url.Values
	lastRegistration   map[string]any
	serial             int
}

type fakeCode struct {
	clientID, redirectURI, challenge string
	device                           id.DeviceID
	used                             bool
}

type fakeRefresh struct {
	clientID      string
	device        id.DeviceID
	access        string
	next          string
	used, revoked bool
}

func newOAuthFake(t *testing.T) *oauthFake {
	f := &oauthFake{t: t, hs: newTestHS(t), expiresIn: 300,
		clients: map[string]map[string]any{}, codes: map[string]*fakeCode{}, refresh: map[string]*fakeRefresh{}, fresh: map[string]bool{}}
	issuer := http.NewServeMux()
	issuer.HandleFunc("POST /oauth2/registration", f.register)
	issuer.HandleFunc("POST /oauth2/token", f.token)
	issuer.HandleFunc("POST /oauth2/revoke", f.revoke)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.issuerRequests.Add(1)
		issuer.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	inner := f.hs.ms.Server.Config.Handler
	f.hs.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hsRequests.Add(1)
		f.noteUse(r)
		switch r.URL.Path {
		case "/_matrix/client/v1/auth_metadata", "/_matrix/client/unstable/org.matrix.msc2965/auth_metadata":
			f.metadata(w, r)
			return
		case "/_matrix/client/v3/account/whoami":
			f.whoami(w, r)
			return
		case "/_matrix/client/v3/logout":
			f.mu.Lock()
			f.logouts++
			f.mu.Unlock()
		}
		if !strings.HasSuffix(r.URL.Path, "/sync") {
			f.hsMu.Lock()
			defer f.hsMu.Unlock()
		}
		inner.ServeHTTP(w, r)
	})
	return f
}

func (f *oauthFake) issuer() string { return f.srv.URL + "/" }

func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q,"error_description":"synthetic-remote-secret"}`, code)
}

func (f *oauthFake) metadata(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "" {
		f.t.Error("metadata discovery sent authentication")
	}
	if f.stableMissing && strings.Contains(r.URL.Path, "/v1/") {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"errcode":"M_UNRECOGNIZED","error":"Unrecognized request"}`))
		return
	}
	m := map[string]any{
		"issuer":                                         f.issuer(),
		"authorization_endpoint":                         f.srv.URL + "/authorize",
		"token_endpoint":                                 f.srv.URL + "/oauth2/token",
		"registration_endpoint":                          f.srv.URL + "/oauth2/registration",
		"revocation_endpoint":                            f.srv.URL + "/oauth2/revoke",
		"account_management_uri":                         "https://account.example.org/manage",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query", "fragment"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"scopes_supported":                               []string{"openid", "urn:matrix:client:api:*", "urn:matrix:org.matrix.msc2967.client:api:*"},
		"authorization_response_iss_parameter_supported": f.issParam,
	}
	if f.tweak != nil {
		f.tweak(m)
	}
	json.NewEncoder(w).Encode(m)
}

// noteUse calls onFirstUse the first time a refreshed access token reaches
// the homeserver, so a test can check it was stored before it was used.
func (f *oauthFake) noteUse(r *http.Request) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	first := f.fresh[bearer]
	delete(f.fresh, bearer)
	hook := f.onFirstUse
	f.mu.Unlock()
	if first && hook != nil {
		hook(bearer)
	}
}

func (f *oauthFake) whoami(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	block, device := f.blockWhoami, f.whoamiDevice
	f.blockWhoami = nil
	f.mu.Unlock()
	if block != nil {
		close(block)
		<-r.Context().Done()
		return
	}
	f.hsMu.Lock()
	who, ok := f.hs.ms.AccessTokenToUserID[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	f.hsMu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"errcode":"M_UNKNOWN_TOKEN","error":"Unknown token"}`))
		return
	}
	if device == "" {
		device = who.DeviceID
	}
	json.NewEncoder(w).Encode(mautrix.RespWhoami{UserID: who.UserID, DeviceID: device})
}

func (f *oauthFake) register(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if json.NewDecoder(r.Body).Decode(&body) != nil || r.Header.Get("Authorization") != "" {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastRegistration = body
	if f.registerStatus != 0 {
		oauthError(w, f.registerStatus, "invalid_client_metadata")
		return
	}
	f.serial++
	clientID := fmt.Sprintf("synthetic-client-%d", f.serial)
	body["client_id"] = clientID
	if f.registerAuthMethod != "" {
		body["token_endpoint_auth_method"] = f.registerAuthMethod
	}
	f.clients[clientID] = body
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(body)
}

// authorize plays the browser and the issuer's consent page: it checks the
// authorization request and returns the callback the issuer redirects to.
func (f *oauthFake) authorize(t *testing.T, authURL string) (string, id.DeviceID) {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil || u.Scheme+"://"+u.Host+u.Path != f.srv.URL+"/authorize" {
		t.Fatal("authorization URL left the discovered endpoint")
	}
	q := u.Query()
	f.mu.Lock()
	defer f.mu.Unlock()
	client := f.clients[q.Get("client_id")]
	registered, _ := client["redirect_uris"].([]any)
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if client == nil || err != nil || len(registered) != 1 {
		t.Fatal("authorization used an unregistered client")
	}
	portless := *redirect
	if portless.Scheme == "http" {
		portless.Host = redirect.Hostname()
		if strings.Contains(portless.Host, ":") {
			portless.Host = "[" + portless.Host + "]"
		}
	}
	if portless.String() != registered[0] {
		t.Fatal("authorization used an unregistered redirect")
	}
	prefix := "urn:matrix:client:"
	if strings.Contains(q.Get("scope"), "msc2967") {
		prefix = "urn:matrix:org.matrix.msc2967.client:"
	}
	scopes := strings.Fields(q.Get("scope"))
	if len(scopes) != 2 || scopes[0] != prefix+"api:*" || !strings.HasPrefix(scopes[1], prefix+"device:") {
		t.Fatalf("scope = %q", q.Get("scope"))
	}
	device := id.DeviceID(strings.TrimPrefix(scopes[1], prefix+"device:"))
	if len(device) < 10 || strings.Trim(string(device), "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
		t.Fatal("device ID is short or outside the unreserved set")
	}
	if q.Get("response_type") != "code" || q.Get("response_mode") != "query" || q.Get("code_challenge_method") != "S256" ||
		len(q.Get("code_challenge")) != 43 || len(q.Get("state")) < 43 || len(q) != 8 {
		t.Fatal("authorization request lacks PKCE, state or query response mode")
	}
	f.serial++
	code := fmt.Sprintf("synthetic-code-%d-%s", f.serial, randomURLToken())
	f.codes[code] = &fakeCode{clientID: q.Get("client_id"), redirectURI: redirect.String(), challenge: q.Get("code_challenge"), device: device}
	f.secrets = append(f.secrets, code, q.Get("state"))
	back := url.Values{"code": {code}, "state": {q.Get("state")}}
	if f.issParam {
		back.Set("iss", f.issuer())
	}
	redirect.RawQuery = back.Encode()
	return redirect.String(), device
}

func (f *oauthFake) token(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Authorization") != "" || r.ParseForm() != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	f.mu.Lock()
	block := f.blockToken
	f.blockToken = nil
	f.mu.Unlock()
	if block != nil {
		close(block)
		<-r.Context().Done()
		return
	}
	form := r.PostForm
	f.mu.Lock()
	defer f.mu.Unlock()
	switch form.Get("grant_type") {
	case "authorization_code":
		f.exchanges++
		f.secrets = append(f.secrets, form.Get("code_verifier"))
		c := f.codes[form.Get("code")]
		sum := sha256.Sum256([]byte(form.Get("code_verifier")))
		if f.exchangeStatus != 0 || c == nil || c.used || c.clientID != form.Get("client_id") || c.redirectURI != form.Get("redirect_uri") ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			oauthError(w, max(f.exchangeStatus, http.StatusBadRequest), "invalid_grant")
			return
		}
		c.used = true
		f.grant(w, c.clientID, c.device)
	case "refresh_token":
		f.refreshes++
		rt := f.refresh[form.Get("refresh_token")]
		if f.refuseRefresh || rt == nil || rt.revoked || rt.clientID != form.Get("client_id") || rt.next != "" && f.refresh[rt.next].used {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		if rt.next != "" { // MSC2964: a lost response may be retried with the old token
			f.revokeRefresh(f.refresh[rt.next])
		}
		rt.used = true
		rt.next = f.grant(w, rt.clientID, rt.device)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

// grant mints a token pair; f.mu is held.
func (f *oauthFake) grant(w http.ResponseWriter, clientID string, device id.DeviceID) string {
	body := fmt.Sprintf(`{"type":"m.login.password","identifier":{"type":"m.id.user","user":%q},"password":"pw","device_id":%q}`, testUser, device)
	rec := httptest.NewRecorder()
	f.hsMu.Lock()
	f.hs.ms.Router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/login", strings.NewReader(body)))
	f.hsMu.Unlock()
	var login mautrix.RespLogin
	if json.Unmarshal(rec.Body.Bytes(), &login) != nil || login.AccessToken == "" {
		f.t.Error("fixture could not mint an access token")
	}
	f.serial++
	refresh := fmt.Sprintf("synthetic-refresh-%d-%s", f.serial, randomURLToken())
	f.refresh[refresh] = &fakeRefresh{clientID: clientID, device: device, access: login.AccessToken}
	f.fresh[login.AccessToken] = true
	f.secrets = append(f.secrets, login.AccessToken, refresh)
	resp := map[string]any{"access_token": login.AccessToken, "token_type": "Bearer", "expires_in": f.expiresIn,
		"scope": "urn:matrix:client:api:* urn:matrix:client:device:" + string(device)}
	if !f.omitRefresh {
		resp["refresh_token"] = refresh
	}
	json.NewEncoder(w).Encode(resp)
	return refresh
}

// revokeRefresh ends a pair; f.mu is held.
func (f *oauthFake) revokeRefresh(rt *fakeRefresh) {
	rt.revoked = true
	f.hsMu.Lock()
	delete(f.hs.ms.AccessTokenToUserID, rt.access)
	f.hsMu.Unlock()
}

func (f *oauthFake) revoke(w http.ResponseWriter, r *http.Request) {
	if r.ParseForm() != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokes++
	f.lastRevoke = r.PostForm
	if f.revokeStatus != 0 {
		oauthError(w, f.revokeStatus, "temporarily_unavailable")
		return
	}
	token := r.PostForm.Get("token")
	for key, rt := range f.refresh {
		if key == token || rt.access == token {
			f.revokeRefresh(rt)
		}
	}
	w.Write([]byte(`{}`))
}

func (f *oauthFake) set(edit func(f *oauthFake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	edit(f)
}

func (f *oauthFake) counts() (exchanges, refreshes, revokes, logouts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exchanges, f.refreshes, f.revokes, f.logouts
}

// assertNoSecrets checks that no code, state, verifier or token reached logs.
func (f *oauthFake) assertNoSecrets(t *testing.T, logs *lockedBuffer) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, secret := range f.secrets {
		if secret != "" && logs.contains(secret) {
			t.Fatal("an OAuth credential reached logs")
		}
	}
	if logs.contains("synthetic-remote-secret") {
		t.Fatal("remote error text reached logs")
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) contains(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return bytes.Contains(l.b.Bytes(), []byte(s))
}

func (f *oauthFake) options(t *testing.T, dir string, logs *lockedBuffer) Options {
	opts := testOptions(t, f.hs, dir)
	opts.Login = nil
	if logs != nil {
		opts.Logger = zerolog.New(logs).Level(zerolog.TraceLevel)
	}
	return opts
}

func (f *oauthFake) begin(t *testing.T, ctx context.Context) *OAuthAuthorization {
	t.Helper()
	server, err := DiscoverOAuth(ctx, f.hs.ms.Server.URL)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	attempt, err := server.BeginLogin(ctx, oauthTestClient, oauthTestRedirect)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	return attempt
}

func (f *oauthFake) accepted(t *testing.T, ctx context.Context) (*OAuthLogin, id.DeviceID) {
	t.Helper()
	attempt := f.begin(t, ctx)
	callback, device := f.authorize(t, attempt.URL)
	login, err := attempt.Accept(callback)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	return login, device
}

func (f *oauthFake) open(t *testing.T, ctx context.Context, opts Options) (*Client, id.DeviceID) {
	t.Helper()
	login, device := f.accepted(t, ctx)
	opts.OAuthLogin = login
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatalf("OAuth Open: %v", err)
	}
	return c, device
}

// expire marks the stored access token as expired, so the next request
// refreshes it.
func expire(t *testing.T, store SessionStore) *Session {
	t.Helper()
	ctx := context.Background()
	sess, err := store.Load(ctx)
	if err != nil || sess == nil || sess.OAuth == nil {
		t.Fatal("no stored OAuth session")
	}
	sess.OAuth.ExpiresAt = time.Now().Add(-time.Minute)
	if err := store.Save(ctx, sess); err != nil {
		t.Fatal(err)
	}
	return sess
}

// faultyStore is a FileSessionStore whose saves can fail or wait.
type faultyStore struct {
	FileSessionStore
	fail atomic.Bool
	gate atomic.Pointer[chan struct{}]
}

func (s *faultyStore) Save(ctx context.Context, sess *Session) error {
	if gate := s.gate.Swap(nil); gate != nil {
		<-*gate
	}
	if s.fail.Load() {
		return errors.New("synthetic store failure")
	}
	return s.FileSessionStore.Save(ctx, sess)
}

func TestOAuthDiscoveryValidatesMetadata(t *testing.T) {
	ctx := context.Background()
	f := newOAuthFake(t)
	server, err := DiscoverOAuth(ctx, f.hs.ms.Server.URL+"/")
	if err != nil || server.Issuer != f.issuer() || server.AccountManagementURI != "https://account.example.org/manage" {
		t.Fatalf("discovery = %+v, %v", server, err)
	}
	f.set(func(f *oauthFake) { f.stableMissing = true })
	if _, err := DiscoverOAuth(ctx, f.hs.ms.Server.URL); err != nil {
		t.Fatal("unstable MSC2965 metadata endpoint not used as fallback")
	}
	f.set(func(f *oauthFake) { f.stableMissing = false })

	for name, tweak := range map[string]func(map[string]any){
		"no S256":            func(m map[string]any) { m["code_challenge_methods_supported"] = []string{"plain"} },
		"no refresh grant":   func(m map[string]any) { m["grant_types_supported"] = []string{"authorization_code"} },
		"no query mode":      func(m map[string]any) { m["response_modes_supported"] = []string{"fragment"} },
		"no code response":   func(m map[string]any) { delete(m, "response_types_supported") },
		"plain HTTP token":   func(m map[string]any) { m["token_endpoint"] = "http://auth.example.org/token" },
		"missing revocation": func(m map[string]any) { delete(m, "revocation_endpoint") },
		"userinfo endpoint":  func(m map[string]any) { m["authorization_endpoint"] = "https://user:synthetic@auth.example.org/" },
		"issuer with query":  func(m map[string]any) { m["issuer"] = "https://auth.example.org/?x=1" },
		"missing issuer":     func(m map[string]any) { delete(m, "issuer") },
	} {
		t.Run(name, func(t *testing.T) {
			f.set(func(f *oauthFake) { f.tweak = tweak })
			defer f.set(func(f *oauthFake) { f.tweak = nil })
			if _, err := DiscoverOAuth(ctx, f.hs.ms.Server.URL); !errors.Is(err, ErrOAuthDiscovery) {
				t.Fatalf("invalid metadata accepted: %v", err)
			}
		})
	}
	f.set(func(f *oauthFake) {
		f.tweak = func(m map[string]any) { m["account_management_uri"] = "javascript:alert(1)" }
	})
	if server, err := DiscoverOAuth(ctx, f.hs.ms.Server.URL); err != nil || server.AccountManagementURI != "" {
		t.Fatal("unsafe account management link exposed")
	}

	unsupported := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"errcode":"M_UNRECOGNIZED","error":"Unrecognized request"}`))
	}))
	defer unsupported.Close()
	if _, err := DiscoverOAuth(ctx, unsupported.URL); !errors.Is(err, ErrOAuthUnsupported) {
		t.Fatalf("classic-only homeserver = %v, want ErrOAuthUnsupported", err)
	}
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"synthetic-remote-secret"}`))
	}))
	defer broken.Close()
	if _, err := DiscoverOAuth(ctx, broken.URL); !errors.Is(err, ErrOAuthDiscovery) || strings.Contains(err.Error(), "synthetic") {
		t.Fatal("discovery failure exposed remote text")
	}
	null := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`null`)) }))
	defer null.Close()
	if _, err := DiscoverOAuth(ctx, null.URL); !errors.Is(err, ErrOAuthDiscovery) {
		t.Fatal("null metadata accepted")
	}
	for _, hs := range []string{"", "http://example.org", "https://user:synthetic@example.org", "https://example.org/?q", "https://example.org/#f"} {
		if _, err := DiscoverOAuth(ctx, hs); !errors.Is(err, ErrOAuthDiscovery) {
			t.Fatalf("unsafe homeserver %q accepted", hs)
		}
	}

	entered := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	defer slow.Close()
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { _, err := DiscoverOAuth(cctx, slow.URL); done <- err }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled discovery = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("discovery ignored cancellation")
	}
}

func TestOAuthBeginLoginRegistersNativePublicClient(t *testing.T) {
	ctx := context.Background()
	f := newOAuthFake(t)
	server, err := DiscoverOAuth(ctx, f.hs.ms.Server.URL)
	if err != nil {
		t.Fatal(err)
	}
	first, err := server.BeginLogin(ctx, oauthTestClient, oauthTestRedirect)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	reg := f.lastRegistration
	f.mu.Unlock()
	want := map[string]any{
		"application_type": "native", "token_endpoint_auth_method": "none", "client_uri": oauthTestClient.ClientURI,
		"client_name": oauthTestClient.ClientName, "policy_uri": oauthTestClient.PolicyURI,
	}
	for k, v := range want {
		if reg[k] != v {
			t.Fatalf("registration %s = %v, want %v", k, reg[k], v)
		}
	}
	if fmt.Sprint(reg["grant_types"]) != "[authorization_code refresh_token]" || fmt.Sprint(reg["response_types"]) != "[code]" ||
		fmt.Sprint(reg["redirect_uris"]) != "[http://127.0.0.1/callback]" {
		t.Fatalf("registration grants/redirects = %v %v %v", reg["grant_types"], reg["response_types"], reg["redirect_uris"])
	}
	_, firstDevice := f.authorize(t, first.URL)
	second, err := server.BeginLogin(ctx, oauthTestClient, "http://[::1]:43124/callback")
	if err != nil {
		t.Fatal(err)
	}
	_, secondDevice := f.authorize(t, second.URL)
	if first.state == second.state || first.verifier == second.verifier || firstDevice == secondDevice || first.clientID == second.clientID {
		t.Fatal("attempts share state, verifier, device or registration")
	}
	if fmt.Sprint(f.lastRegistration["redirect_uris"]) != "[http://[::1]/callback]" {
		t.Fatal("IPv6 loopback registered with its port")
	}
	private := oauthTestClient
	private.ClientURI = "https://chat.example.org"
	private.PolicyURI = ""
	if _, err := server.BeginLogin(ctx, private, "org.example.chat:/oauth"); err != nil {
		t.Fatalf("private-use redirect refused: %v", err)
	}

	for _, redirect := range []string{
		"", "https://app.example.org/callback", "http://app.example.org:8080/callback", "http://127.0.0.1/callback",
		"http://127.0.0.2:43123/callback", "http://127.0.0.1:43123/callback?x=1", "http://127.0.0.1:43123/callback#f",
		"http://user@127.0.0.1:43123/callback", "org.example.other:/callback", "app.example.org:/callback",
		"org.example.app://callback", "org.example.app:callback", "org.example.app:/callback#f",
		"javascript:alert(1)",
	} {
		if _, err := server.BeginLogin(ctx, oauthTestClient, redirect); !errors.Is(err, ErrOAuthClient) {
			t.Fatalf("redirect %q = %v, want ErrOAuthClient", redirect, err)
		}
	}
	for _, client := range []OAuthClientMetadata{
		{ClientURI: "http://app.example.org/"},
		{ClientURI: "https://user:pw@app.example.org/"},
		{ClientURI: ""},
		{ClientURI: "https://app.example.org/", LogoURI: "https://cdn.example.net/logo.png"},
		{ClientURI: "https://app.example.org/", TOSURI: "http://app.example.org/tos"},
		{ClientURI: "https://app.example.org/", PolicyURI: "https://evilapp.example.org/"},
	} {
		if _, err := server.BeginLogin(ctx, client, oauthTestRedirect); !errors.Is(err, ErrOAuthClient) {
			t.Fatalf("client %+v = %v, want ErrOAuthClient", client, err)
		}
	}
	f.set(func(f *oauthFake) { f.registerStatus = http.StatusBadRequest })
	if _, err := server.BeginLogin(ctx, oauthTestClient, oauthTestRedirect); !errors.Is(err, ErrOAuthRegistration) || strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("refused registration = %v", err)
	}
	f.set(func(f *oauthFake) { f.registerStatus, f.registerAuthMethod = 0, "client_secret_basic" })
	if _, err := server.BeginLogin(ctx, oauthTestClient, oauthTestRedirect); !errors.Is(err, ErrOAuthRegistration) {
		t.Fatal("confidential registration accepted for a public client")
	}
	f.set(func(f *oauthFake) {
		f.registerAuthMethod = ""
		f.tweak = func(m map[string]any) { m["scopes_supported"] = []string{"urn:matrix:org.matrix.msc2967.client:api:*"} }
	})
	unstable, err := DiscoverOAuth(ctx, f.hs.ms.Server.URL)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := unstable.BeginLogin(ctx, oauthTestClient, oauthTestRedirect)
	if err != nil || !strings.Contains(attempt.URL, "org.matrix.msc2967.client%3Adevice%3A") {
		t.Fatal("unstable-only issuer not given unstable scopes")
	}
	if _, err := (*OAuthServer)(nil).BeginLogin(ctx, oauthTestClient, oauthTestRedirect); !errors.Is(err, ErrOAuthUnsupported) {
		t.Fatal("nil server accepted")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := server.BeginLogin(cctx, oauthTestClient, oauthTestRedirect); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled begin did not return the context error")
	}
}

func TestOAuthAcceptBindsCallbackToAttempt(t *testing.T) {
	ctx := context.Background()
	f := newOAuthFake(t)
	f.set(func(f *oauthFake) { f.issParam = true })
	attempt := f.begin(t, ctx)
	callback, _ := f.authorize(t, attempt.URL)
	good, _ := url.Parse(callback)
	with := func(edit func(u *url.URL, q url.Values)) string {
		u := *good
		q := u.Query()
		edit(&u, q)
		u.RawQuery = q.Encode()
		return u.String()
	}
	for name, bad := range map[string]string{
		"wrong state":     with(func(_ *url.URL, q url.Values) { q.Set("state", "synthetic-forged") }),
		"two states":      with(func(_ *url.URL, q url.Values) { q.Add("state", q.Get("state")) }),
		"no state":        with(func(_ *url.URL, q url.Values) { q.Del("state") }),
		"wrong issuer":    with(func(_ *url.URL, q url.Values) { q.Set("iss", "https://other.example.org/") }),
		"missing issuer":  with(func(_ *url.URL, q url.Values) { q.Del("iss") }),
		"no code":         with(func(_ *url.URL, q url.Values) { q.Del("code") }),
		"empty code":      with(func(_ *url.URL, q url.Values) { q.Set("code", "") }),
		"two codes":       with(func(_ *url.URL, q url.Values) { q.Add("code", "synthetic-second") }),
		"wrong path":      with(func(u *url.URL, _ url.Values) { u.Path = "/other" }),
		"wrong port":      with(func(u *url.URL, _ url.Values) { u.Host = "127.0.0.1:43124" }),
		"wrong scheme":    with(func(u *url.URL, _ url.Values) { u.Scheme = "https" }),
		"fragment":        with(func(u *url.URL, _ url.Values) { u.Fragment = "x" }),
		"not a URL":       "%zz",
		"relative":        "/callback?" + good.RawQuery,
		"bad query":       good.Scheme + "://" + good.Host + good.Path + "?state=%zz",
		"different place": "https://app.example.org/callback?" + good.RawQuery,
	} {
		if _, err := attempt.Accept(bad); !errors.Is(err, ErrOAuthCallback) {
			t.Fatalf("%s: %v, want ErrOAuthCallback", name, err)
		}
	}
	login, err := attempt.Accept(callback)
	if err != nil || login == nil {
		t.Fatal("stray callbacks consumed the pending attempt")
	}
	if _, err := attempt.Accept(callback); !errors.Is(err, ErrOAuthCallback) {
		t.Fatal("completed attempt accepted a second callback")
	}

	denied := f.begin(t, ctx)
	callback, _ = f.authorize(t, denied.URL)
	u, _ := url.Parse(callback)
	q := u.Query()
	q.Del("code")
	q.Set("error", "access_denied")
	q.Set("error_description", "synthetic-remote-secret")
	u.RawQuery = q.Encode()
	if _, err := denied.Accept(u.String()); !errors.Is(err, ErrOAuthDenied) || !strings.Contains(err.Error(), "access_denied") || strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("denial = %v", err)
	}
	q.Set("code", "synthetic-late")
	q.Del("error")
	u.RawQuery = q.Encode()
	if _, err := denied.Accept(u.String()); !errors.Is(err, ErrOAuthCallback) {
		t.Fatal("denied attempt accepted a later code")
	}
	odd := f.begin(t, ctx)
	callback, _ = f.authorize(t, odd.URL)
	u, _ = url.Parse(callback)
	q = u.Query()
	q.Set("error", "Synthetic Remote Secret")
	u.RawQuery = q.Encode()
	if _, err := odd.Accept(u.String()); !errors.Is(err, ErrOAuthDenied) || strings.Contains(err.Error(), "Synthetic") {
		t.Fatal("malformed error code reached the caller")
	}
	if _, err := (*OAuthAuthorization)(nil).Accept(callback); !errors.Is(err, ErrOAuthCallback) {
		t.Fatal("nil attempt accepted")
	}
}

func TestOAuthLoginRefreshRestoreAndLogout(t *testing.T) {
	ctx := context.Background()
	f := newOAuthFake(t)
	dir := t.TempDir()
	logs := &lockedBuffer{}
	opts := f.options(t, dir, logs)
	login, device := f.accepted(t, ctx)
	opts.OAuthLogin = login
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatalf("OAuth Open: %v", err)
	}
	if c.DeviceID != device || c.UserID != testUser {
		t.Fatal("client does not hold the authorized device")
	}
	c.Close()
	sess, err := opts.Sessions.Load(ctx)
	if err != nil || sess == nil || sess.OAuth == nil {
		t.Fatal("OAuth login did not persist a session")
	}
	if sess.UserID != testUser || sess.DeviceID != device || sess.AccessToken == "" || len(sess.PickleKey) != 32 ||
		sess.OAuth.Issuer != f.issuer() || !strings.HasPrefix(sess.OAuth.ClientID, "synthetic-client-") ||
		sess.OAuth.TokenEndpoint != f.srv.URL+"/oauth2/token" || sess.OAuth.RevocationEndpoint != f.srv.URL+"/oauth2/revoke" ||
		!strings.HasPrefix(sess.OAuth.RefreshToken, "synthetic-refresh-") || time.Until(sess.OAuth.ExpiresAt) < 4*time.Minute {
		t.Fatalf("incomplete OAuth session for %s", sess.DeviceID)
	}
	if exchanges, _, _, _ := f.counts(); exchanges != 1 {
		t.Fatalf("exchanges = %d, want 1", exchanges)
	}
	if _, err := Open(ctx, f.options(t, t.TempDir(), logs)); !errors.Is(err, ErrNoSession) {
		t.Fatal("reopen without login options did not report ErrNoSession")
	}
	reuse := f.options(t, t.TempDir(), logs)
	reuse.OAuthLogin = login
	if _, err := Open(ctx, reuse); !errors.Is(err, ErrOAuthLogin) {
		t.Fatal("authorization reused")
	}
	if exchanges, _, _, _ := f.counts(); exchanges != 1 {
		t.Fatal("reused authorization reached the token endpoint")
	}

	opts.OAuthLogin = nil
	hs, issuer := f.hsRequests.Load(), f.issuerRequests.Load()
	c, err = Open(ctx, opts)
	if err != nil || f.hsRequests.Load() != hs || f.issuerRequests.Load() != issuer {
		t.Fatal("restoring an OAuth session used the network")
	}
	c.Close()

	expire(t, opts.Sessions)
	var checked atomic.Bool
	f.set(func(f *oauthFake) {
		f.onFirstUse = func(access string) {
			stored, err := opts.Sessions.Load(ctx)
			if err != nil || stored == nil || stored.AccessToken != access {
				t.Error("rotated token used before it was stored")
			}
			checked.Store(true)
		}
	})
	c, err = Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	who, err := c.Whoami(ctx)
	if err != nil || who.DeviceID != device {
		t.Fatalf("whoami after expiry: %v", err)
	}
	rotated, _ := opts.Sessions.Load(ctx)
	if _, refreshes, _, _ := f.counts(); refreshes != 1 || !checked.Load() {
		t.Fatalf("refreshes = %d, checked = %v", refreshes, checked.Load())
	}
	if rotated.OAuth.RefreshToken == sess.OAuth.RefreshToken || rotated.AccessToken == sess.AccessToken ||
		time.Until(rotated.OAuth.ExpiresAt) < 4*time.Minute || rotated.OAuth.ClientID != sess.OAuth.ClientID || string(rotated.PickleKey) != string(sess.PickleKey) {
		t.Fatal("rotation did not replace the stored pair or lost session fields")
	}

	f.set(func(f *oauthFake) { f.revokeStatus = http.StatusServiceUnavailable })
	if err := c.Logout(ctx); !errors.Is(err, ErrOAuthRevoke) || strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("failed revocation = %v, want sanitized ErrOAuthRevoke", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err := c.Logout(cancelled); !errors.Is(err, ErrOAuthRevoke) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled revocation = %v", err)
	}
	if kept, _ := opts.Sessions.Load(ctx); kept == nil {
		t.Fatal("failed revocation cleared the session")
	}
	if _, err := os.Stat(opts.StateDir); err != nil {
		t.Fatal("failed revocation removed state")
	}
	f.set(func(f *oauthFake) { f.revokeStatus = 0 })
	if err := c.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	_, _, revokes, logouts := f.counts()
	f.mu.Lock()
	last := f.lastRevoke
	f.mu.Unlock()
	if revokes != 2 || logouts != 0 || last.Get("token") != rotated.OAuth.RefreshToken ||
		last.Get("token_type_hint") != "refresh_token" || last.Get("client_id") != sess.OAuth.ClientID {
		t.Fatal("logout did not revoke the current refresh token at the issuer")
	}
	if gone, err := opts.Sessions.Load(ctx); err != nil || gone != nil {
		t.Fatal("logout left the session")
	}
	if _, err := os.Stat(opts.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("logout left the state directory")
	}
	f.assertNoSecrets(t, logs)
}

func TestOAuthRefreshSaveFailureKeepsStoredPair(t *testing.T) {
	ctx := context.Background()
	f := newOAuthFake(t)
	dir := t.TempDir()
	logs := &lockedBuffer{}
	opts := f.options(t, dir, logs)
	store := &faultyStore{FileSessionStore: FileSessionStore{Path: filepath.Join(dir, "session.json")}}
	opts.Sessions = store
	c, _ := f.open(t, ctx, opts)
	c.Close()
	before := expire(t, store)
	opts.OAuthLogin = nil
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	store.fail.Store(true)
	cctx, cancel := context.WithCancel(ctx)
	f.set(func(f *oauthFake) { f.onFirstUse = func(string) { t.Error("unsaved rotated token was used") } })
	_, err = c.Whoami(cctx)
	cancel()
	if !errors.Is(err, mautrix.ErrFailedToRefreshToken) {
		t.Fatalf("whoami with a failing store = %v", err)
	}
	if stored, _ := store.FileSessionStore.Load(ctx); stored.OAuth.RefreshToken != before.OAuth.RefreshToken {
		t.Fatal("failed save changed the stored refresh token")
	}
	store.fail.Store(false)
	f.set(func(f *oauthFake) { f.onFirstUse = nil })
	if _, err := c.Whoami(ctx); err != nil {
		t.Fatalf("retry with the still-stored refresh token: %v", err)
	}
	after, _ := store.Load(ctx)
	if _, refreshes, _, _ := f.counts(); refreshes != 2 || after.OAuth.RefreshToken == before.OAuth.RefreshToken {
		t.Fatal("refresh was not retried from the stored pair")
	}
	f.assertNoSecrets(t, logs)
}

func TestOAuthRefusedRefreshEndsSync(t *testing.T) {
	ctx := context.Background()
	f := newOAuthFake(t)
	logs := &lockedBuffer{}
	opts := f.options(t, t.TempDir(), logs)
	c, _ := f.open(t, ctx, opts)
	c.Close()
	expire(t, opts.Sessions)
	f.set(func(f *oauthFake) { f.refuseRefresh = true })
	opts.OAuthLogin = nil
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = c.Sync(sctx)
	if !errors.Is(err, ErrOAuthSessionEnded) || !errors.Is(err, mautrix.MUnknownToken) || sctx.Err() != nil {
		t.Fatalf("Sync after a refused refresh = %v", err)
	}
	if strings.Contains(err.Error(), "synthetic") {
		t.Fatal("session-end error carries remote text")
	}
	f.assertNoSecrets(t, logs)
}

// TestOAuthRevokedSessionFailsPromptly: when the homeserver rejects a
// current, unexpired OAuth access token (the session was ended elsewhere),
// requests and Sync must report M_UNKNOWN_TOKEN instead of retrying it.
func TestOAuthRevokedSessionFailsPromptly(t *testing.T) {
	ctx := context.Background()
	f := newOAuthFake(t)
	opts := f.options(t, t.TempDir(), nil)
	c, _ := f.open(t, ctx, opts)
	defer c.Close()
	sess, _ := opts.Sessions.Load(ctx)
	f.hsMu.Lock()
	delete(f.hs.ms.AccessTokenToUserID, sess.AccessToken)
	f.hsMu.Unlock()
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := c.Whoami(rctx); !errors.Is(err, mautrix.MUnknownToken) || rctx.Err() != nil {
		t.Fatalf("request with a revoked token = %v", err)
	}
	if _, refreshes, _, _ := f.counts(); refreshes != 0 {
		t.Fatal("an unexpired rejected token was refreshed")
	}
}

func TestOAuthRefreshClassification(t *testing.T) {
	refused := func(status int) error {
		return fmt.Errorf("%w in sync loop: %w", mautrix.ErrFailedToRefreshToken, mautrix.HTTPError{
			Response:  &http.Response{StatusCode: status},
			RespError: &mautrix.RespError{ErrCode: "invalid_grant", Err: "synthetic-remote-secret", OAuth: true},
		})
	}
	s := newSyncer()
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden} {
		delay, err := s.OnFailedSync(nil, refused(status))
		if delay != 0 || !errors.Is(err, ErrOAuthSessionEnded) || !errors.Is(err, mautrix.MUnknownToken) || !errors.Is(err, mautrix.ErrFailedToRefreshToken) {
			t.Fatalf("refused refresh (HTTP %d) = %v, %v", status, delay, err)
		}
	}
	for _, transient := range []error{
		refused(http.StatusTooManyRequests),
		refused(http.StatusServiceUnavailable),
		fmt.Errorf("%w: %w", mautrix.ErrFailedToRefreshToken, mautrix.HTTPError{Message: "request error", WrappedError: io.ErrUnexpectedEOF}),
		mautrix.HTTPError{Response: &http.Response{StatusCode: http.StatusBadRequest}, RespError: &mautrix.RespError{ErrCode: "M_UNKNOWN"}},
	} {
		if delay, err := s.OnFailedSync(nil, transient); delay == 0 || err != nil {
			t.Fatalf("%v ended the session", transient)
		}
		if errors.Is(classifySessionEnd(transient), ErrOAuthSessionEnded) {
			t.Fatal("transient failure classified as session end")
		}
	}
}

func TestOAuthLoginPreservesStoredSessionAndBinding(t *testing.T) {
	ctx := context.Background()
	f := newOAuthFake(t)
	dir := t.TempDir()
	classic := testOptions(t, f.hs, dir)
	c, err := Open(ctx, classic)
	if err != nil {
		t.Fatal(err)
	}
	device := c.DeviceID
	c.Close()

	login, _ := f.accepted(t, ctx)
	both := classic
	both.OAuthLogin = login
	if _, err := Open(ctx, both); err == nil || !strings.Contains(err.Error(), "exclusive") {
		t.Fatal("Login and OAuthLogin accepted together")
	}
	opts := classic
	opts.Login, opts.OAuthLogin = nil, login
	c, err = Open(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	stored, _ := opts.Sessions.Load(ctx)
	if exchanges, _, _, _ := f.counts(); exchanges != 0 || c.DeviceID != device || stored.DeviceID != device || stored.OAuth != nil {
		t.Fatal("OAuth authorization replaced a stored session")
	}

	other := newOAuthFake(t)
	foreign, _ := other.accepted(t, ctx)
	stale := classic
	stale.Login, stale.OAuthLogin = nil, foreign
	c, err = Open(ctx, stale)
	if err != nil || c.DeviceID != device {
		t.Fatalf("an unused foreign authorization blocked the stored session: %v", err)
	}
	c.Close()
	elsewhere := f.options(t, t.TempDir(), nil)
	elsewhere.OAuthLogin = foreign
	if _, err := Open(ctx, elsewhere); !errors.Is(err, ErrOAuthLogin) {
		t.Fatalf("foreign homeserver authorization = %v", err)
	}
	if exchanges, _, _, _ := other.counts(); exchanges != 0 {
		t.Fatal("foreign authorization was exchanged")
	}
	if sess, _ := elsewhere.Sessions.Load(ctx); sess != nil {
		t.Fatal("refused binding stored a session")
	}
	slash := elsewhere
	slash.Homeserver = other.hs.ms.Server.URL + "/"
	slash.OAuthLogin = foreign
	c, err = Open(ctx, slash)
	if err != nil {
		t.Fatalf("same homeserver with a trailing slash refused: %v", err)
	}
	c.Close()
}

func TestOAuthLoginFailuresStoreNothingAndRevoke(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(f *oauthFake, store *faultyStore)
		cancel  bool
		want    error
		revokes int
	}{
		{name: "code refused", setup: func(f *oauthFake, _ *faultyStore) { f.exchangeStatus = http.StatusBadRequest }, want: ErrOAuthLogin},
		{name: "no refresh token", setup: func(f *oauthFake, _ *faultyStore) { f.omitRefresh = true }, want: ErrOAuthLogin, revokes: 1},
		{name: "no expiry", setup: func(f *oauthFake, _ *faultyStore) { f.expiresIn = 0 }, want: ErrOAuthLogin, revokes: 1},
		{name: "other device", setup: func(f *oauthFake, _ *faultyStore) { f.whoamiDevice = "SYNTHETICOTHER" }, want: ErrOAuthLogin, revokes: 1},
		{name: "save fails", setup: func(_ *oauthFake, s *faultyStore) { s.fail.Store(true) }, revokes: 1},
		{name: "cancel exchange", setup: func(f *oauthFake, _ *faultyStore) { f.blockToken = make(chan struct{}) }, cancel: true, want: context.Canceled},
		{name: "cancel whoami", setup: func(f *oauthFake, _ *faultyStore) { f.blockWhoami = make(chan struct{}) }, cancel: true, want: context.Canceled, revokes: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newOAuthFake(t)
			dir := t.TempDir()
			logs := &lockedBuffer{}
			opts := f.options(t, dir, logs)
			store := &faultyStore{FileSessionStore: FileSessionStore{Path: filepath.Join(dir, "session.json")}}
			opts.Sessions = store
			login, _ := f.accepted(t, ctx)
			opts.OAuthLogin = login
			f.mu.Lock()
			tc.setup(f, store)
			entered := f.blockToken
			if entered == nil {
				entered = f.blockWhoami
			}
			f.mu.Unlock()
			if tc.cancel {
				go func() { <-entered; cancel() }()
			}
			c, err := Open(ctx, opts)
			if err == nil {
				c.Close()
				t.Fatal("failed login opened a client")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Open = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "synthetic-remote-secret") {
				t.Fatal("login error carries remote text")
			}
			if sess, _ := store.FileSessionStore.Load(context.Background()); sess != nil {
				t.Fatal("failed login stored a session")
			}
			if _, _, revokes, _ := f.counts(); revokes != tc.revokes {
				t.Fatalf("revocations = %d, want %d", revokes, tc.revokes)
			}
			f.assertNoSecrets(t, logs)
		})
	}
}

// TestSessionWritesAreSerialized holds a key-backup save open while a token
// rotation arrives: the rotation must wait and then keep the backup key, and
// the backup save must not write back the older token pair.
func TestSessionWritesAreSerialized(t *testing.T) {
	ctx := context.Background()
	f := newOAuthFake(t)
	dir := t.TempDir()
	opts := f.options(t, dir, nil)
	store := &faultyStore{FileSessionStore: FileSessionStore{Path: filepath.Join(dir, "session.json")}}
	opts.Sessions = store
	c, _ := f.open(t, ctx, opts)
	defer c.Close()
	key, err := backup.NewMegolmBackupKey()
	if err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	store.gate.Store(&gate)
	backupDone := make(chan error, 1)
	go func() { backupDone <- c.useBackup(ctx, key, "7") }()
	for store.gate.Load() != nil {
		time.Sleep(time.Millisecond)
	}
	rotated := make(chan error, 1)
	go func() {
		rotated <- c.saveRefreshedTokens(ctx, "synthetic-refresh-rotated", "synthetic-access-rotated", time.Now().Add(time.Hour))
	}()
	time.Sleep(50 * time.Millisecond)
	close(gate)
	if err := <-backupDone; err != nil {
		t.Fatal(err)
	}
	if err := <-rotated; err != nil {
		t.Fatal(err)
	}
	stored, _ := store.Load(ctx)
	if stored.OAuth.RefreshToken != "synthetic-refresh-rotated" || stored.AccessToken != "synthetic-access-rotated" ||
		stored.BackupVersion != "7" || len(stored.BackupKey) == 0 {
		t.Fatal("concurrent session writes lost an update")
	}
	if c.session.OAuth.RefreshToken != stored.OAuth.RefreshToken || c.KeyBackupVersion() != "7" {
		t.Fatal("memory and store disagree after concurrent writes")
	}
}

func TestSessionJSONCompatibility(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	legacy := `{"user_id":"@bot:example.org","device_id":"DEV","access_token":"synthetic-access",` +
		`"pickle_key":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=","backup_version":"3"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	store := FileSessionStore{Path: path}
	sess, err := store.Load(ctx)
	if err != nil || sess.OAuth != nil || sess.AccessToken != "synthetic-access" || sess.BackupVersion != "3" {
		t.Fatal("pre-OAuth session did not load unchanged")
	}
	if err := store.Save(ctx, sess); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var a, b map[string]any
	json.Unmarshal(raw, &a)
	json.Unmarshal([]byte(legacy), &b)
	if fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatalf("classic session changed shape: %s", raw)
	}
	expiry := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	sess.OAuth = &OAuthSession{Issuer: "https://auth.example.org/", ClientID: "synthetic-client", TokenEndpoint: "https://auth.example.org/token",
		RevocationEndpoint: "https://auth.example.org/revoke", RefreshToken: "synthetic-refresh", ExpiresAt: expiry}
	if err := store.Save(ctx, sess); err != nil {
		t.Fatal(err)
	}
	back, err := store.Load(ctx)
	if err != nil || back.OAuth == nil || *back.OAuth != *sess.OAuth {
		t.Fatal("OAuth session did not round-trip")
	}

	h := newTestHS(t)
	opts := testOptions(t, h, dir)
	opts.Login = nil
	opts.Homeserver = h.ms.Server.URL
	back.OAuth.RefreshToken = ""
	if err := store.Save(ctx, back); err != nil {
		t.Fatal(err)
	}
	if c, err := Open(ctx, opts); err == nil {
		c.Close()
		t.Fatal("incomplete stored OAuth session restored")
	}
}
