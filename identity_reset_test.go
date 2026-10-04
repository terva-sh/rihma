package rihma

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// The approval page is synthetic. Its query stands in for anything a
// server might put there that must not reach a log or an error.
const (
	testApprovalURL = "https://auth.example.org/account/?action=org.matrix.cross_signing_reset&marker=approval-url-private"
	testXSPassword  = "synthetic-uia-password-private"
)

// uiaHS answers POST /keys/device_signing/upload the way Synapse does:
// a first upload or an identical re-upload passes without auth, and
// replacing a master key needs a password (mode "password") or a MAS
// approval (mode "oauth") that the test grants by calling approve.
type uiaHS struct {
	*testHS
	mode string

	// mu serializes the handler with the test's reads and settings.
	mu         sync.Mutex
	approved   bool
	forceExist bool                      // challenge even a first upload, as servers before Matrix v1.11 did
	preempt    *mautrix.CrossSigningKeys // another device's master key, landing just before the next upload
	failUpload *rawReply                 // answer every upload with this instead
	flows      []mautrix.UIAFlow         // overrides the challenge's flows
	params     map[string]any            // overrides the challenge's params
	auths      []json.RawMessage         // the auth dict of every upload, nil when absent
	failData   map[string]int            // account data type -> remaining 400s
	urlParam   string                    // the approval URL in params; testApprovalURL by default
}

func newUIAHS(t *testing.T, mode string) *uiaHS {
	u := &uiaHS{testHS: newTestHS(t), mode: mode, failData: map[string]int{}, urlParam: testApprovalURL}
	inner := u.ms.Server.Config.Handler
	u.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		defer u.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/_matrix/client/v3/keys/device_signing/upload":
			u.upload(w, r, inner)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/account_data/") && u.takeDataFailure(r.URL.Path):
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"injected"}`))
		default:
			inner.ServeHTTP(w, r)
		}
	})
	return u
}

// set changes the server's behaviour under its lock.
func (u *uiaHS) set(f func(u *uiaHS)) {
	u.mu.Lock()
	f(u)
	u.mu.Unlock()
}

func (u *uiaHS) approve() {
	u.mu.Lock()
	u.approved = true
	u.mu.Unlock()
}

func (u *uiaHS) failAccountData(typ string, n int) {
	u.mu.Lock()
	u.failData[typ] = n
	u.mu.Unlock()
}

func (u *uiaHS) takeDataFailure(path string) bool {
	for typ, n := range u.failData {
		if n > 0 && strings.HasSuffix(path, "/account_data/"+typ) {
			u.failData[typ] = n - 1
			return true
		}
	}
	return false
}

func (u *uiaHS) seenAuths() []json.RawMessage {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]json.RawMessage(nil), u.auths...)
}

type rawReply struct {
	status int
	body   string
}

// upload runs under u.mu.
func (u *uiaHS) upload(w http.ResponseWriter, r *http.Request, inner http.Handler) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		Master mautrix.CrossSigningKeys `json:"master_key"`
		Auth   json.RawMessage          `json:"auth"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	u.auths = append(u.auths, req.Auth)
	if u.failUpload != nil {
		w.WriteHeader(u.failUpload.status)
		w.Write([]byte(u.failUpload.body))
		return
	}
	if u.preempt != nil {
		u.ms.MasterKeys[testUser], u.preempt = *u.preempt, nil
	}
	stored := u.ms.MasterKeys[testUser]
	exists := len(stored.Keys) > 0 || u.forceExist
	same := len(stored.Keys) > 0 && reflect.DeepEqual(stored.Keys, req.Master.Keys)
	allow := !exists || same
	var challenge map[string]any
	if !allow {
		switch u.mode {
		case "oauth":
			allow = u.approved
			if !allow {
				challenge = map[string]any{
					"session": "dummy",
					"flows":   []map[string]any{{"stages": []string{"m.oauth"}}, {"stages": []string{"org.matrix.cross_signing_reset"}}},
					"params": map[string]any{
						"m.oauth":                        map[string]any{"url": u.urlParam},
						"org.matrix.cross_signing_reset": map[string]any{"url": u.urlParam},
					},
					"msg": "To reset your end-to-end encryption cross-signing identity, you first need to approve it at " + u.urlParam + " and then try again.",
				}
			}
		case "password":
			var a struct {
				Type     string `json:"type"`
				Session  string `json:"session"`
				User     string `json:"user"`
				Password string `json:"password"`
			}
			_ = json.Unmarshal(req.Auth, &a)
			allow = a.Type == "m.login.password" && a.Session == "uia-1" && a.User == testUser.String() && a.Password == testXSPassword
			if !allow {
				challenge = map[string]any{
					"session": "uia-1",
					"flows":   []map[string]any{{"stages": []string{"m.login.password"}}},
					"params":  map[string]any{},
				}
				if len(req.Auth) > 0 {
					challenge["errcode"], challenge["error"] = "M_FORBIDDEN", "Invalid username or password"
				}
			}
		}
		if challenge != nil && u.flows != nil {
			challenge["flows"] = u.flows
		}
		if challenge != nil && u.params != nil {
			challenge["params"] = u.params
		}
	}
	if !allow {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(challenge)
		return
	}
	if same {
		w.Write([]byte(`{}`))
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	inner.ServeHTTP(w, r)
}

// accountState is what a failed reset must leave as it found: the
// server's master key, the account data (secret storage), and this
// device's private cross-signing keys.
type accountState struct {
	master      string
	accountData map[event.Type]string
	localMaster string
}

func (u *uiaHS) state(t *testing.T, c *Client) accountState {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	master, _ := json.Marshal(u.ms.MasterKeys[testUser])
	s := accountState{master: string(master), accountData: map[event.Type]string{}}
	for typ, data := range u.ms.AccountData[testUser] {
		s.accountData[typ] = string(data)
	}
	if keys := c.OlmMachine().CrossSigningKeys; keys != nil {
		s.localMaster = keys.MasterKey.PublicKey().String()
	}
	return s
}

func (u *uiaHS) assertUnchanged(t *testing.T, c *Client, before accountState) {
	t.Helper()
	if after := u.state(t, c); !reflect.DeepEqual(before, after) {
		t.Fatal("a refused reset changed the account's identity, secret storage, or this device's keys")
	}
}

// withIdentity opens a client and gives the account its first identity,
// which needs no auth on either kind of server.
func withIdentity(t *testing.T, u *uiaHS) (*Client, string) {
	t.Helper()
	ctx := context.Background()
	c, err := Open(ctx, testOptions(t, u.testHS, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	key, err := c.CreateRecoveryKey(ctx, "")
	if err != nil {
		t.Fatalf("first identity: %v", err)
	}
	if auths := u.seenAuths(); len(auths) != 1 || auths[0] != nil {
		t.Fatalf("first identity sent %d uploads, auth %s; want one without auth", len(auths), auths)
	}
	return c, key
}

// assertRestores proves the new recovery key restores the new identity
// on another device, and the old one no longer does.
func assertRestores(t *testing.T, u *uiaHS, c *Client, oldKey, newKey string) {
	t.Helper()
	ctx := context.Background()
	if newKey == "" || newKey == oldKey {
		t.Fatal("reset did not return a new recovery key")
	}
	u.mu.Lock()
	master := u.ms.MasterKeys[testUser]
	u.mu.Unlock()
	if got, want := c.OlmMachine().CrossSigningKeys.MasterKey.PublicKey(), master.FirstKey(); got != want {
		t.Fatalf("server master key %s, want this device's new %s", want, got)
	}
	other, err := Open(ctx, testOptions(t, u.testHS, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.RestoreFromRecoveryKey(ctx, oldKey); err == nil {
		t.Fatal("the old recovery key still restores after a reset")
	}
	if err := other.RestoreFromRecoveryKey(ctx, newKey); err != nil {
		t.Fatalf("restore with the new recovery key: %v", err)
	}
	if got, want := other.OlmMachine().CrossSigningKeys.MasterKey.PublicKey(), c.OlmMachine().CrossSigningKeys.MasterKey.PublicKey(); got != want {
		t.Fatal("restored a different identity from the new recovery key")
	}
}

func failApprove(t *testing.T) func(context.Context, CrossSigningApproval) error {
	return func(context.Context, CrossSigningApproval) error {
		t.Error("Approve called where the server asked for no approval")
		return errors.New("unexpected approval")
	}
}

func TestFirstIdentityNeedsNoAuth(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"oauth", "password"} {
		t.Run("create/"+mode, func(t *testing.T) {
			withIdentity(t, newUIAHS(t, mode))
		})
		t.Run("reset/"+mode, func(t *testing.T) {
			u := newUIAHS(t, mode)
			c, err := Open(ctx, testOptions(t, u.testHS, t.TempDir()))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			key, err := c.ResetCrossSigningIdentity(ctx, CrossSigningAuth{Approve: failApprove(t)})
			if err != nil {
				t.Fatalf("reset on an account with no identity: %v", err)
			}
			if auths := u.seenAuths(); len(auths) != 1 || auths[0] != nil || key == "" {
				t.Fatalf("uploads %s, key %t; want one upload without auth and a key", auths, key != "")
			}
			if ok, err := c.DeviceVerified(ctx); err != nil || !ok {
				t.Fatalf("device verified after reset = %v, %v", ok, err)
			}
		})
	}
}

func TestResetIdentityWithPassword(t *testing.T) {
	ctx := context.Background()
	u := newUIAHS(t, "password")
	c, oldKey := withIdentity(t, u)
	before := u.state(t, c)

	if _, err := c.ResetCrossSigningIdentity(ctx, CrossSigningAuth{}); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("reset without a password = %v, want ErrPasswordRequired", err)
	}
	u.assertUnchanged(t, c, before)

	_, err := c.ResetCrossSigningIdentity(ctx, CrossSigningAuth{Password: "wrong-" + testXSPassword})
	if !errors.Is(err, mautrix.MForbidden) {
		t.Fatalf("reset with a wrong password = %v, want M_FORBIDDEN", err)
	}
	if strings.Contains(err.Error(), testXSPassword) {
		t.Fatal("the password reached the error")
	}
	u.assertUnchanged(t, c, before)

	// The bot's password path: CreateRecoveryKey still refuses outright.
	if _, err := c.CreateRecoveryKey(ctx, testXSPassword); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("create on an existing identity = %v, want ErrIdentityExists", err)
	}
	u.assertUnchanged(t, c, before)

	newKey, err := c.ResetCrossSigningIdentity(ctx, CrossSigningAuth{Password: testXSPassword, Approve: failApprove(t)})
	if err != nil {
		t.Fatalf("reset with the password: %v", err)
	}
	assertRestores(t, u, c, oldKey, newKey)
	if ok, err := c.DeviceVerified(ctx); err != nil || !ok {
		t.Fatalf("device verified after reset = %v, %v", ok, err)
	}
}

func TestResetIdentityWithApproval(t *testing.T) {
	ctx := context.Background()
	u := newUIAHS(t, "oauth")
	c, oldKey := withIdentity(t, u)

	var calls []CrossSigningApproval
	newKey, err := c.ResetCrossSigningIdentity(ctx, CrossSigningAuth{
		Password: "ignored-by-a-delegated-server",
		Approve: func(_ context.Context, a CrossSigningApproval) error {
			calls = append(calls, a)
			u.approve() // the person approves on the account page
			return nil
		},
	})
	if err != nil {
		t.Fatalf("approved reset: %v", err)
	}
	if len(calls) != 1 || calls[0].URL != testApprovalURL || calls[0].Attempt != 1 {
		t.Fatalf("Approve calls = %d (first attempt %v, URL as sent %t)", len(calls), calls != nil && calls[0].Attempt == 1, calls != nil && calls[0].URL == testApprovalURL)
	}
	// One upload drew the challenge; the retry carried just the session (Matrix v1.17).
	auths := u.seenAuths()
	if len(auths) != 3 || auths[1] != nil || string(auths[2]) != `{"session":"dummy"}` {
		t.Fatalf("uploads carried auth %s", auths)
	}
	assertRestores(t, u, c, oldKey, newKey)
}

func TestResetIdentityApprovalNotYetSeen(t *testing.T) {
	ctx := context.Background()
	u := newUIAHS(t, "oauth")
	c, oldKey := withIdentity(t, u)

	var attempts []int
	newKey, err := c.ResetCrossSigningIdentity(ctx, CrossSigningAuth{
		Approve: func(_ context.Context, a CrossSigningApproval) error {
			attempts = append(attempts, a.Attempt)
			if a.Attempt == 2 { // the person returns before approving the first time
				u.approve()
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("reset approved on the second attempt: %v", err)
	}
	if !reflect.DeepEqual(attempts, []int{1, 2}) {
		t.Fatalf("Approve attempts = %v, want [1 2]", attempts)
	}
	assertRestores(t, u, c, oldKey, newKey)
}

func TestResetIdentityApprovalRefused(t *testing.T) {
	errDenied := errors.New("the person cancelled the reset")
	cases := map[string]struct {
		auth func(cancel context.CancelFunc) CrossSigningAuth
		want error
	}{
		"no approver": {
			auth: func(context.CancelFunc) CrossSigningAuth { return CrossSigningAuth{Password: testXSPassword} },
			want: ErrApprovalRequired,
		},
		"denied": {
			auth: func(context.CancelFunc) CrossSigningAuth {
				return CrossSigningAuth{Approve: func(context.Context, CrossSigningApproval) error { return errDenied }}
			},
			want: errDenied,
		},
		"denied, error names the page": {
			auth: func(context.CancelFunc) CrossSigningAuth {
				return CrossSigningAuth{Approve: func(_ context.Context, a CrossSigningApproval) error {
					return fmt.Errorf("open %s: %w", a.URL, errDenied) // a browser launch failing
				}}
			},
			want: errDenied,
		},
		"never approved": {
			auth: func(context.CancelFunc) CrossSigningAuth {
				return CrossSigningAuth{Approve: func(_ context.Context, a CrossSigningApproval) error {
					if a.Attempt == 3 {
						return errDenied // the person gives up after two tries
					}
					return nil
				}}
			},
			want: errDenied,
		},
		"cancelled while waiting": {
			auth: func(cancel context.CancelFunc) CrossSigningAuth {
				return CrossSigningAuth{Approve: func(ctx context.Context, _ CrossSigningApproval) error {
					go cancel()
					<-ctx.Done()
					return ctx.Err()
				}}
			},
			want: context.Canceled,
		},
		"cancelled, approver ignores it": {
			auth: func(cancel context.CancelFunc) CrossSigningAuth {
				return CrossSigningAuth{Approve: func(ctx context.Context, _ CrossSigningApproval) error {
					cancel()
					<-ctx.Done()
					return nil
				}}
			},
			want: context.Canceled,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			u := newUIAHS(t, "oauth")
			c, _ := withIdentity(t, u)
			before := u.state(t, c)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			key, err := c.ResetCrossSigningIdentity(ctx, tc.auth(cancel))
			if !errors.Is(err, tc.want) || key != "" {
				t.Fatalf("reset = %q, %v; want no key and %v", key, err, tc.want)
			}
			if errors.Is(err, ErrIdentityIncomplete) || strings.Contains(err.Error(), "approval-url-private") {
				t.Fatalf("refused reset error %q", err)
			}
			u.assertUnchanged(t, c, before)
		})
	}
}

// Another device creates an identity after CreateRecoveryKey's first
// check, so the upload draws a challenge. Create must refuse rather than
// answer it, on either kind of server, and must not send the password.
func TestCreateRefusesConcurrentIdentity(t *testing.T) {
	other := mautrix.CrossSigningKeys{
		UserID: testUser,
		Usage:  []id.CrossSigningUsage{id.XSUsageMaster},
		Keys:   map[id.KeyID]id.Ed25519{"ed25519:other-device-master": "other-device-master"},
	}
	for _, mode := range []string{"password", "oauth"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			u := newUIAHS(t, mode)
			c, err := Open(ctx, testOptions(t, u.testHS, t.TempDir()))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			before := u.state(t, c)
			u.set(func(u *uiaHS) { u.preempt = &other })
			if _, err := c.CreateRecoveryKey(ctx, testXSPassword); !errors.Is(err, ErrIdentityExists) {
				t.Fatalf("create racing another identity = %v, want ErrIdentityExists", err)
			}
			if auths := u.seenAuths(); len(auths) != 1 || auths[0] != nil {
				t.Fatalf("create answered the challenge: uploads carried auth %s", auths)
			}
			after := u.state(t, c)
			want, _ := json.Marshal(other)
			if after.master != string(want) || !reflect.DeepEqual(after.accountData, before.accountData) || after.localMaster != before.localMaster {
				t.Fatal("create changed the other device's identity, secret storage, or this device's keys")
			}
		})
	}
	// An approval challenge with no identity on the server still refuses:
	// that stage only ever approves a replacement.
	t.Run("approval without identity", func(t *testing.T) {
		ctx := context.Background()
		u := newUIAHS(t, "oauth")
		u.set(func(u *uiaHS) { u.forceExist = true })
		c, err := Open(ctx, testOptions(t, u.testHS, t.TempDir()))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		before := u.state(t, c)
		if _, err := c.CreateRecoveryKey(ctx, testXSPassword); !errors.Is(err, ErrIdentityExists) {
			t.Fatalf("create against an approval challenge = %v, want ErrIdentityExists", err)
		}
		u.assertUnchanged(t, c, before)
	})
}

// A server from before Matrix v1.11 asks for the password even for the
// first identity; the bot's password path still answers it.
func TestCreateAnswersLegacyFirstUploadPassword(t *testing.T) {
	ctx := context.Background()
	u := newUIAHS(t, "password")
	u.set(func(u *uiaHS) { u.forceExist = true })
	c, err := Open(ctx, testOptions(t, u.testHS, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	before := u.state(t, c)
	if _, err := c.CreateRecoveryKey(ctx, ""); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("create without the password a legacy server asks for = %v, want ErrPasswordRequired", err)
	}
	u.assertUnchanged(t, c, before)
	key, err := c.CreateRecoveryKey(ctx, testXSPassword)
	if err != nil || key == "" {
		t.Fatalf("create with the password = %t, %v", key != "", err)
	}
	if auths := u.seenAuths(); len(auths) != 3 || !strings.Contains(string(auths[2]), `"m.login.password"`) {
		t.Fatalf("legacy first upload carried auth %d times", len(auths))
	}
	if ok, err := c.DeviceVerified(ctx); err != nil || !ok {
		t.Fatalf("device verified after create = %v, %v", ok, err)
	}
}

func TestResetIdentityRejectsUnsafeApprovalURL(t *testing.T) {
	for _, bad := range []string{
		"",
		"javascript:alert(document.cookie)",
		"file:///etc/approval-url-private",
		"/account/?approval-url-private",
		"https://approval-url-private:pw@auth.example.org/account/",
		"https:///approval-url-private",
	} {
		t.Run(bad, func(t *testing.T) {
			u := newUIAHS(t, "oauth")
			u.set(func(u *uiaHS) { u.urlParam = bad })
			c, _ := withIdentity(t, u)
			before := u.state(t, c)
			_, err := c.ResetCrossSigningIdentity(context.Background(), CrossSigningAuth{Approve: failApprove(t)})
			if !errors.Is(err, ErrApprovalURL) {
				t.Fatalf("reset = %v, want ErrApprovalURL", err)
			}
			if strings.Contains(err.Error(), "approval-url-private") {
				t.Fatal("the rejected URL reached the error")
			}
			u.assertUnchanged(t, c, before)
		})
	}
	t.Run("params missing", func(t *testing.T) {
		u := newUIAHS(t, "oauth")
		u.set(func(u *uiaHS) { u.params = map[string]any{} })
		c, _ := withIdentity(t, u)
		if _, err := c.ResetCrossSigningIdentity(context.Background(), CrossSigningAuth{Approve: failApprove(t)}); !errors.Is(err, ErrApprovalURL) {
			t.Fatalf("reset = %v, want ErrApprovalURL", err)
		}
	})
}

func TestResetIdentityUnstableApprovalStage(t *testing.T) {
	u := newUIAHS(t, "oauth")
	u.set(func(u *uiaHS) {
		u.flows = []mautrix.UIAFlow{{Stages: []mautrix.AuthType{"org.matrix.cross_signing_reset"}}}
		u.params = map[string]any{"org.matrix.cross_signing_reset": map[string]any{"url": testApprovalURL}}
	})
	c, oldKey := withIdentity(t, u)
	var got string
	newKey, err := c.ResetCrossSigningIdentity(context.Background(), CrossSigningAuth{
		Approve: func(_ context.Context, a CrossSigningApproval) error {
			got = a.URL
			u.approve()
			return nil
		},
	})
	if err != nil || got != testApprovalURL {
		t.Fatalf("reset through the unstable stage = %v (URL as sent %t)", err, got == testApprovalURL)
	}
	assertRestores(t, u, c, oldKey, newKey)
}

func TestResetIdentityUnsupportedStages(t *testing.T) {
	u := newUIAHS(t, "oauth")
	u.set(func(u *uiaHS) {
		u.flows = []mautrix.UIAFlow{
			{Stages: []mautrix.AuthType{mautrix.AuthTypeSSO}},
			{Stages: []mautrix.AuthType{mautrix.AuthTypePassword, mautrix.AuthTypeEmail}},
			{Stages: []mautrix.AuthType{"see https://approval-url-private"}},
		}
	})
	c, _ := withIdentity(t, u)
	before := u.state(t, c)
	_, err := c.ResetCrossSigningIdentity(context.Background(), CrossSigningAuth{Password: testXSPassword, Approve: failApprove(t)})
	if !errors.Is(err, ErrAuthUnsupported) {
		t.Fatalf("reset = %v, want ErrAuthUnsupported", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "m.login.sso") || !strings.Contains(msg, "m.login.password+m.login.email.identity") || strings.Contains(msg, "approval-url-private") {
		t.Fatalf("unsupported-stage error %q", msg)
	}
	u.assertUnchanged(t, c, before)
}

// A server's error text can name the approval page: Synapse returned the
// reset demand as a 501 with the URL in its message before it adopted the
// approval stage. Upload failures keep the code and the cause, not the text.
func TestResetIdentityUploadErrorsOmitServerText(t *testing.T) {
	text := "To reset your end-to-end encryption cross-signing identity, you first need to approve it at " + testApprovalURL + " and then try again."
	cases := map[string]struct {
		reply rawReply
		is    error
		want  string
	}{
		"pre-MSC4312 Synapse": {rawReply{http.StatusNotImplemented, `{"errcode":"M_UNRECOGNIZED","error":"` + text + `"}`}, mautrix.MUnrecognized, "HTTP 501 M_UNRECOGNIZED"},
		"401 without flows":   {rawReply{http.StatusUnauthorized, `{"errcode":"M_UNKNOWN_TOKEN","error":"` + text + `"}`}, mautrix.MUnknownToken, "HTTP 401 M_UNKNOWN_TOKEN"},
		"free-text errcode":   {rawReply{http.StatusForbidden, `{"errcode":"` + text + `","error":"no"}`}, nil, "HTTP 403"},
		"no JSON":             {rawReply{http.StatusBadGateway, text}, nil, "HTTP 502"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			u := newUIAHS(t, "oauth")
			c, _ := withIdentity(t, u)
			c.DefaultHTTPRetries = 0 // the 502 case, without mautrix's backoff
			before := u.state(t, c)
			u.set(func(u *uiaHS) { u.failUpload = &tc.reply })
			_, err := c.ResetCrossSigningIdentity(context.Background(), CrossSigningAuth{Password: testXSPassword, Approve: failApprove(t)})
			if err == nil {
				t.Fatal("reset succeeded against a failing upload")
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("reset error does not match %v", tc.is)
			}
			var httpErr mautrix.HTTPError
			if !errors.As(err, &httpErr) {
				t.Fatal("the HTTP cause is no longer reachable")
			}
			if msg := err.Error(); strings.Contains(msg, "approval-url-private") || !strings.HasSuffix(msg, tc.want) {
				t.Fatalf("upload error text leaked server text or lost its code (want suffix %q, URL leaked %t)", tc.want, strings.Contains(msg, "approval-url-private"))
			}
			u.assertUnchanged(t, c, before)
		})
	}
}

// After the server accepts the keys the old identity is gone; a failure
// storing the new one says so, and running the reset again repairs it.
func TestResetIdentityIncompleteAfterPublish(t *testing.T) {
	ctx := context.Background()
	u := newUIAHS(t, "oauth")
	c, oldKey := withIdentity(t, u)
	u.approve()
	u.failAccountData("m.cross_signing.self_signing", 1)
	key, err := c.ResetCrossSigningIdentity(ctx, CrossSigningAuth{Approve: failApprove(t)})
	if !errors.Is(err, ErrIdentityIncomplete) || key != "" {
		t.Fatalf("reset with a failing secret write = %q, %v; want no key and ErrIdentityIncomplete", key, err)
	}
	newKey, err := c.ResetCrossSigningIdentity(ctx, CrossSigningAuth{Approve: failApprove(t)})
	if err != nil {
		t.Fatalf("second reset: %v", err)
	}
	assertRestores(t, u, c, oldKey, newKey)
}

// Only synthetic secrets are used. Never print captured logs on failure.
func TestIdentityResetLogsOmitSecrets(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"oauth", "password"} {
		t.Run(mode, func(t *testing.T) {
			u := newUIAHS(t, mode)
			opts := testOptions(t, u.testHS, t.TempDir())
			var logs bytes.Buffer
			var mu sync.Mutex
			opts.Logger = zerolog.New(&lockedWriter{w: &logs, mu: &mu}).Level(zerolog.TraceLevel)
			c, err := Open(ctx, opts)
			if err != nil {
				t.Fatal("mock Open failed")
			}
			defer c.Close()
			oldKey, err := c.CreateRecoveryKey(ctx, "")
			if err != nil {
				t.Fatal("first identity failed")
			}
			var errs []string
			// A refused attempt first, then the one that succeeds.
			_, err = c.ResetCrossSigningIdentity(ctx, CrossSigningAuth{
				Password: "wrong-" + testXSPassword,
				Approve:  func(context.Context, CrossSigningApproval) error { return errors.New("declined") },
			})
			if err == nil {
				t.Fatal("refused reset succeeded")
			}
			errs = append(errs, err.Error())
			newKey, err := c.ResetCrossSigningIdentity(ctx, CrossSigningAuth{
				Password: testXSPassword,
				Approve: func(context.Context, CrossSigningApproval) error {
					u.approve()
					return nil
				},
			})
			if err != nil {
				t.Fatal("approved reset failed")
			}
			mu.Lock()
			data := logs.String()
			mu.Unlock()
			for _, secret := range []string{testXSPassword, "approval-url-private", oldKey, newKey} {
				if strings.Contains(data, secret) || strings.Contains(strings.Join(errs, "\n"), secret) {
					t.Fatal("a password, approval URL or recovery key reached a log or an error")
				}
			}
			if !strings.Contains(data, "cross-signing upload auth") && !strings.Contains(data, "cross-signing reset approval") {
				t.Fatal("the safe auth diagnostics were lost")
			}
		})
	}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
