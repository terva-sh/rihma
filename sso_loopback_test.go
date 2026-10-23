package rihma

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
)

const ssoTestHomeserver = "https://matrix.example.org"

// ssoTestCaps is a discovered homeserver offering classic SSO and token login.
func ssoTestCaps() LoginCapabilities {
	return LoginCapabilities{SSO: true, Token: true, server: ssoTestHomeserver}
}

type ssoSessions struct {
	sess *Session
	err  error
}

func (s ssoSessions) Load(context.Context) (*Session, error) { return s.sess, s.err }
func (ssoSessions) Save(context.Context, *Session) error     { return nil }
func (ssoSessions) Clear(context.Context) error              { return nil }

// ssoCancellingSessions cancels the caller's context during Load and then
// fails with an error of its own, as a store interrupted mid-read might.
type ssoCancellingSessions struct{ cancel context.CancelFunc }

func (s ssoCancellingSessions) Load(context.Context) (*Session, error) {
	s.cancel()
	return nil, errors.New("synthetic interrupted read")
}
func (ssoCancellingSessions) Save(context.Context, *Session) error { return nil }
func (ssoCancellingSessions) Clear(context.Context) error          { return nil }

// ssoCallbackURL extracts the loopback callback from the homeserver's SSO
// redirect URL, as the homeserver would.
func ssoCallbackURL(t *testing.T, browser string) *url.URL {
	t.Helper()
	u, err := url.Parse(browser)
	if err != nil {
		t.Fatal("browser URL unparseable")
	}
	cb, err := url.Parse(u.Query().Get("redirectUrl"))
	if err != nil || cb.Scheme != "http" {
		t.Fatal("callback unparseable")
	}
	return cb
}

// ssoRaw sends one raw HTTP/1.1 request to the listener and reads the reply.
func ssoRaw(t *testing.T, authority, request string) (*http.Response, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", authority, 5*time.Second)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func ssoGet(t *testing.T, authority, target string) (*http.Response, string) {
	return ssoRaw(t, authority, "GET "+target+" HTTP/1.1\r\nHost: "+authority+"\r\nConnection: close\r\n\r\n")
}

// ssoSizedRequest builds a GET for target whose request line and header
// fields, through the blank line that ends them, are exactly size bytes.
func ssoSizedRequest(t *testing.T, authority, target string, size int) string {
	t.Helper()
	head := "GET " + target + " HTTP/1.1\r\nHost: " + authority + "\r\nConnection: close\r\nX-Pad: "
	pad := size - len(head) - len("\r\n\r\n")
	if pad < 1 {
		t.Fatal("sized request too small for its target")
	}
	req := head + strings.Repeat("h", pad) + "\r\n\r\n"
	if len(req) != size {
		t.Fatal("sized request miscounted")
	}
	return req
}

// ssoBoundary runs one attempt that first sends over, which must be refused
// with status and leave the attempt pending, then at, which must be
// accepted. It returns the accepted token.
func ssoBoundary(t *testing.T, over func(a, p string) string, status int, at func(a, p string) string) string {
	t.Helper()
	login, err := ssoTestCaps().ReceiveSSOLogin(context.Background(), SSOLoopback{
		Timeout:  time.Minute,
		Sessions: ssoSessions{},
		Launch: func(_ context.Context, browser string) error {
			cb := ssoCallbackURL(t, browser)
			resp, _ := ssoRaw(t, cb.Host, over(cb.Host, cb.Path))
			if resp.StatusCode != status {
				t.Fatalf("over the limit answered %d, want %d", resp.StatusCode, status)
			}
			resp, body := ssoRaw(t, cb.Host, at(cb.Host, cb.Path))
			ssoCheckPage(t, resp, body, http.StatusOK, ssoPageAccepted)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("at the limit not accepted: %v", err)
	}
	tok, ok := login.take()
	if !ok {
		t.Fatal("accepted token lost")
	}
	return tok
}

// ssoCheckPage asserts the fixed page contract: status, static text, no
// caching or referrer, and no echo of anything secret.
func ssoCheckPage(t *testing.T, resp *http.Response, body string, status int, page string, secrets ...string) {
	t.Helper()
	if resp.StatusCode != status || body != page {
		t.Fatalf("callback answered %d %q, want %d %q", resp.StatusCode, body, status, page)
	}
	h := resp.Header
	if h.Get("Content-Type") != "text/plain; charset=utf-8" || h.Get("Cache-Control") != "no-store" ||
		h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("callback page headers incomplete: %v", h)
	}
	for _, s := range secrets {
		if s != "" && (strings.Contains(body, s) || strings.Contains(fmt.Sprint(h), s)) {
			t.Fatal("callback page echoed a secret")
		}
	}
}

// ssoListenerGoroutines counts goroutines that belong to a loopback
// listener: its Serve goroutine and its connection handlers.
func ssoListenerGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	count := 0
	for _, g := range bytes.Split(buf, []byte("\n\n")) {
		if bytes.Contains(g, []byte("rihma.LoginCapabilities.ReceiveSSOLogin")) ||
			bytes.Contains(g, []byte("rihma.(*ssoCallback)")) ||
			bytes.Contains(g, []byte("net/http.(*conn).serve")) {
			count++
		}
	}
	return count
}

// ssoNoLeak fails unless listener goroutines return to the baseline. The
// Serve goroutine is joined before ReceiveSSOLogin returns; connection
// goroutines may take a moment to unwind after their connection closed.
func ssoNoLeak(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for ssoListenerGoroutines() > baseline {
		if time.Now().After(deadline) {
			t.Fatalf("loopback listener leaked goroutines: %d > %d", ssoListenerGoroutines(), baseline)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ssoAssertClosed checks that the attempt's listener no longer answers. The
// OS may already have given the port to another listener, from this
// process or another test binary, so a connection alone is not a failure:
// only an answer from this attempt's route is, and that route answers
// nothing but 404 from any other listener.
func ssoAssertClosed(t *testing.T, cb *url.URL) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", cb.Host, time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "GET "+cb.Path+"?loginToken=synthetic-probe HTTP/1.1\r\nHost: "+cb.Host+"\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("listener still serving the attempt after ReceiveSSOLogin returned: %d", resp.StatusCode)
	}
}

// TestSSOLoopbackEndToEnd drives the whole flow against a fake homeserver
// whose SSO redirect returns to the loopback callback, with a scripted
// browser that follows redirects, then exchanges the token through Open.
func TestSSOLoopbackEndToEnd(t *testing.T) {
	baseline := ssoListenerGoroutines()
	h := newTestHS(t)
	const token = "synthetic-loopback-sso-token"
	var exchanges, redirects atomic.Int32
	var callback atomic.Pointer[url.URL]
	inner := h.ms.Server.Config.Handler
	h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/_matrix/client/v3/login":
			w.Write([]byte(`{"flows":[{"type":"m.login.sso"},{"type":"m.login.token"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/_matrix/client/v3/login/sso/redirect":
			redirects.Add(1)
			cb, err := url.Parse(r.URL.Query().Get("redirectUrl"))
			if err != nil || cb.Scheme != "http" || cb.Hostname() != "127.0.0.1" || cb.Port() == "" || cb.Port() == "0" ||
				!strings.HasPrefix(cb.Path, ssoCallbackPrefix) || len(cb.Path) < len(ssoCallbackPrefix)+43 || cb.RawQuery != "" {
				t.Error("SSO redirect named an unexpected callback")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			callback.Store(cb)
			q := cb.Query()
			q.Set("loginToken", token)
			cb2 := *cb
			cb2.RawQuery = q.Encode()
			http.Redirect(w, r, cb2.String(), http.StatusFound)
		case r.Method == http.MethodPost && r.URL.Path == "/_matrix/client/v3/login":
			exchanges.Add(1)
			var login mautrix.ReqLogin
			if json.NewDecoder(r.Body).Decode(&login) != nil || login.Type != mautrix.AuthTypeToken || login.Token != token {
				t.Error("token exchange carried the wrong login")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			login.Identifier = mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: testUser.String()}
			body, _ := json.Marshal(login)
			r.Body = io.NopCloser(bytes.NewReader(body))
			inner.ServeHTTP(w, r)
		default:
			inner.ServeHTTP(w, r)
		}
	})
	ctx := context.Background()
	caps, err := DiscoverLoginFlows(ctx, h.ms.Server.URL)
	if err != nil {
		t.Fatal("discovery failed")
	}
	opts := testOptions(t, h, t.TempDir())
	opts.Login = nil
	var logs bytes.Buffer
	opts.Logger = zerolog.New(&logs).Level(zerolog.TraceLevel)
	var stdlog bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&stdlog)
	defer log.SetOutput(prev)

	browser := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 10 * time.Second}
	var page string
	var pageHeader http.Header
	var launches atomic.Int32
	login, err := caps.ReceiveSSOLogin(ctx, SSOLoopback{
		Timeout:  time.Minute,
		Sessions: opts.Sessions,
		Launch: func(ctx context.Context, target string) error {
			launches.Add(1)
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			resp, err := browser.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			page, pageHeader = string(b), resp.Header
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("callback answered %d", resp.StatusCode)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("loopback SSO failed: %v", err)
	}
	cb := callback.Load()
	if page != ssoPageAccepted || pageHeader.Get("Cache-Control") != "no-store" || pageHeader.Get("Referrer-Policy") != "no-referrer" || redirects.Load() != 1 || launches.Load() != 1 {
		t.Fatal("browser did not see the static success page")
	}
	ssoAssertClosed(t, cb)
	nonce := strings.TrimPrefix(cb.Path, ssoCallbackPrefix)

	opts.SSOLogin = login
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatalf("Open with SSOLogin failed: %v", err)
	}
	device := c.DeviceID
	c.Close()
	sess, err := opts.Sessions.Load(ctx)
	if err != nil || sess == nil || sess.UserID != testUser || sess.DeviceID != device || exchanges.Load() != 1 {
		t.Fatal("SSO login did not persist its session")
	}

	// The stored session now wins, and a new attempt refuses to start
	// without asking for a browser.
	if c, err := Open(ctx, opts); err != nil || c.DeviceID != device || exchanges.Load() != 1 {
		t.Fatal("stored session replaced or lost")
	} else {
		c.Close()
	}
	if _, err := caps.ReceiveSSOLogin(ctx, SSOLoopback{Sessions: opts.Sessions, Launch: func(context.Context, string) error {
		t.Error("browser launched while a session is stored")
		return nil
	}}); !errors.Is(err, ErrSessionStored) {
		t.Fatal("loopback attempt started over a stored session")
	}

	// The token was taken once; a fresh store cannot reuse it.
	fresh := testOptions(t, h, t.TempDir())
	fresh.Login, fresh.SSOLogin = nil, login
	if c, err := Open(ctx, fresh); !errors.Is(err, ErrSSOLogin) {
		if c != nil {
			c.Close()
		}
		t.Fatal("SSOLogin reused")
	}
	if exchanges.Load() != 1 {
		t.Fatal("reused SSOLogin reached the homeserver")
	}

	for _, secret := range []string{token, nonce, sess.AccessToken} {
		if bytes.Contains(logs.Bytes(), []byte(secret)) || bytes.Contains(stdlog.Bytes(), []byte(secret)) {
			t.Fatal("SSO secret reached a log")
		}
	}
	browser.CloseIdleConnections()
	h.ms.Server.Close()
	ssoNoLeak(t, baseline)
}

// TestSSOLoopbackRejections sends every malformed callback shape and checks
// that each is refused with a static page while the attempt stays pending,
// then that one valid callback ends it and a duplicate is refused.
func TestSSOLoopbackRejections(t *testing.T) {
	baseline := ssoListenerGoroutines()
	var stdlog bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&stdlog)
	defer log.SetOutput(prev)
	const token = "synthetic-valid-token"
	var cb *url.URL
	login, err := ssoTestCaps().ReceiveSSOLogin(context.Background(), SSOLoopback{
		Timeout:  time.Minute,
		Sessions: ssoSessions{},
		Launch: func(_ context.Context, browser string) error {
			cb = ssoCallbackURL(t, browser)
			a, p := cb.Host, cb.Path
			nonce := strings.TrimPrefix(p, ssoCallbackPrefix)
			other := "AAAA" + nonce[4:]
			if other == nonce {
				other = "BBBB" + nonce[4:]
			}
			secrets := []string{nonce, "synthetic-secret"}
			notFound := []string{
				"/",
				ssoCallbackPrefix,
				ssoCallbackPrefix + other + "?loginToken=synthetic-secret",
				p + "/?loginToken=synthetic-secret",
				p + "x?loginToken=synthetic-secret",
				p[:len(p)-1] + "?loginToken=synthetic-secret",
				ssoCallbackPrefix + "%" + fmt.Sprintf("%02X", nonce[0]) + nonce[1:] + "?loginToken=synthetic-secret",
				strings.ToUpper(ssoCallbackPrefix) + nonce + "?loginToken=synthetic-secret",
			}
			for _, target := range notFound {
				resp, body := ssoGet(t, a, target)
				ssoCheckPage(t, resp, body, http.StatusNotFound, ssoPageNotFound, secrets...)
			}
			// Another Host (DNS rebinding, or the other loopback name) and
			// no Host at all.
			for _, host := range []string{"localhost:" + cb.Port(), "attacker.example", "127.0.0.1", "[::1]:" + cb.Port()} {
				resp, body := ssoRaw(t, a, "GET "+p+"?loginToken=synthetic-secret HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
				ssoCheckPage(t, resp, body, http.StatusNotFound, ssoPageNotFound, secrets...)
			}
			resp, body := ssoRaw(t, a, "GET "+p+"?loginToken=synthetic-secret HTTP/1.0\r\n\r\n")
			ssoCheckPage(t, resp, body, http.StatusNotFound, ssoPageNotFound, secrets...)
			// Absolute-form request naming another authority.
			resp, body = ssoRaw(t, a, "GET http://attacker.example"+p+"?loginToken=synthetic-secret HTTP/1.1\r\nHost: "+a+"\r\nConnection: close\r\n\r\n")
			ssoCheckPage(t, resp, body, http.StatusNotFound, ssoPageNotFound, secrets...)

			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions, http.MethodHead, "PATCH"} {
				resp, body := ssoRaw(t, a, method+" "+p+"?loginToken=synthetic-secret HTTP/1.1\r\nHost: "+a+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				if method == http.MethodHead {
					if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodGet || body != "" {
						t.Fatal("HEAD callback accepted")
					}
					continue
				}
				ssoCheckPage(t, resp, body, http.StatusMethodNotAllowed, ssoPageMethod, secrets...)
				if resp.Header.Get("Allow") != http.MethodGet {
					t.Fatal("405 without Allow: GET")
				}
			}
			// A body, sized or chunked.
			resp, body = ssoRaw(t, a, "GET "+p+"?loginToken=synthetic-secret HTTP/1.1\r\nHost: "+a+"\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
			ssoCheckPage(t, resp, body, http.StatusBadRequest, ssoPageInvalid, secrets...)
			resp, body = ssoRaw(t, a, "GET "+p+"?loginToken=synthetic-secret HTTP/1.1\r\nHost: "+a+"\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
			ssoCheckPage(t, resp, body, http.StatusBadRequest, ssoPageInvalid, secrets...)

			invalid := []string{
				p,
				p + "?",
				p + "?state=unrelated",
				p + "?loginToken=",
				p + "?loginToken",
				p + "?loginToken=synthetic-secret&loginToken=synthetic-secret",
				p + "?loginToken=synthetic-secret&loginToken=",
				p + "?loginToken=%zz",
				p + "?loginToken=synthetic-secret;x=1",
				p + "?loginToken=" + strings.Repeat("s", ssoMaxToken+1),
			}
			for _, target := range invalid {
				resp, body := ssoGet(t, a, target)
				ssoCheckPage(t, resp, body, http.StatusBadRequest, ssoPageInvalid, secrets...)
			}
			resp, body = ssoGet(t, a, p+"?loginToken=synthetic-secret&pad="+strings.Repeat("p", ssoMaxQuery))
			ssoCheckPage(t, resp, body, http.StatusRequestURITooLong, ssoPageTooLong, secrets...)
			// Oversized headers are refused by net/http before the handler.
			resp, _ = ssoRaw(t, a, ssoSizedRequest(t, a, p+"?loginToken=synthetic-secret", ssoMaxHeaderBytes+1))
			if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
				t.Fatalf("oversized header answered %d", resp.StatusCode)
			}

			// Every refusal above left the attempt pending.
			resp, body = ssoGet(t, a, p+"?loginToken="+token+"&unrelated=ignored")
			ssoCheckPage(t, resp, body, http.StatusOK, ssoPageAccepted, token, nonce)
			// A duplicate or a different token after acceptance is refused.
			for _, q := range []string{"?loginToken=" + token, "?loginToken=synthetic-secret", "?error=access_denied"} {
				resp, body := ssoGet(t, a, p+q)
				ssoCheckPage(t, resp, body, http.StatusGone, ssoPageGone, token, nonce)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("valid callback not accepted: %v", err)
	}
	if got, ok := login.take(); !ok || got != token || login.s.homeserver != ssoTestHomeserver {
		t.Fatal("accepted the wrong token or homeserver")
	}
	ssoAssertClosed(t, cb)
	if stdlog.Len() != 0 {
		t.Fatal("listener wrote to the standard logger")
	}
	ssoNoLeak(t, baseline)
}

// TestSSOLoopbackHomeserverError covers a homeserver that returns to the
// callback with an error instead of a token.
func TestSSOLoopbackHomeserverError(t *testing.T) {
	baseline := ssoListenerGoroutines()
	var cb *url.URL
	_, err := ssoTestCaps().ReceiveSSOLogin(context.Background(), SSOLoopback{
		Timeout:  time.Minute,
		Sessions: ssoSessions{},
		Launch: func(_ context.Context, browser string) error {
			cb = ssoCallbackURL(t, browser)
			resp, body := ssoGet(t, cb.Host, cb.Path+"?error=access_denied&error_description=synthetic-remote-secret")
			ssoCheckPage(t, resp, body, http.StatusForbidden, ssoPageDenied, "synthetic-remote-secret", "access_denied")
			resp, body = ssoGet(t, cb.Host, cb.Path+"?loginToken=synthetic-late-token")
			ssoCheckPage(t, resp, body, http.StatusGone, ssoPageGone, "synthetic-late-token")
			return nil
		},
	})
	if !errors.Is(err, ErrSSODenied) || err.Error() != ErrSSODenied.Error() {
		t.Fatalf("homeserver error returned %v", err)
	}
	ssoAssertClosed(t, cb)
	ssoNoLeak(t, baseline)
}

// TestSSOLoopbackRacingCallbacks fires many valid callbacks at once:
// exactly one is accepted, and it is the one returned.
func TestSSOLoopbackRacingCallbacks(t *testing.T) {
	baseline := ssoListenerGoroutines()
	const racers = 32
	var mu sync.Mutex
	statuses := map[int]int{}
	accepted := ""
	login, err := ssoTestCaps().ReceiveSSOLogin(context.Background(), SSOLoopback{
		Timeout:  time.Minute,
		Sessions: ssoSessions{},
		Launch: func(_ context.Context, browser string) error {
			cb := ssoCallbackURL(t, browser)
			client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 10 * time.Second}
			defer client.CloseIdleConnections()
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range racers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					tok := fmt.Sprintf("synthetic-racer-%02d", i)
					resp, err := client.Get("http://" + cb.Host + cb.Path + "?loginToken=" + tok)
					if err != nil {
						t.Errorf("racer request failed: %v", err)
						return
					}
					b, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					body := string(b)
					mu.Lock()
					defer mu.Unlock()
					statuses[resp.StatusCode]++
					if resp.StatusCode == http.StatusOK {
						accepted = tok
					}
					if strings.Contains(body, tok) {
						t.Error("racer page echoed its token")
					}
				}()
			}
			close(start)
			wg.Wait()
			return nil
		},
	})
	if err != nil {
		t.Fatalf("racing callbacks: %v", err)
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusGone] != racers-1 {
		t.Fatalf("racing callbacks answered %v", statuses)
	}
	if got, ok := login.take(); !ok || got != accepted {
		t.Fatal("returned token is not the accepted callback's")
	}
	ssoNoLeak(t, baseline)
}

// TestSSOLoopbackTimeoutCancelAndLaunchFailure covers every way an attempt
// ends without a token; each closes the listener before returning.
func TestSSOLoopbackTimeoutCancelAndLaunchFailure(t *testing.T) {
	baseline := ssoListenerGoroutines()
	caps := ssoTestCaps()

	t.Run("timeout", func(t *testing.T) {
		var cb *url.URL
		var launchCtx context.Context
		start := time.Now()
		_, err := caps.ReceiveSSOLogin(context.Background(), SSOLoopback{
			Timeout:  100 * time.Millisecond,
			Sessions: ssoSessions{},
			Launch: func(ctx context.Context, browser string) error {
				cb, launchCtx = ssoCallbackURL(t, browser), ctx
				resp, body := ssoGet(t, cb.Host, cb.Path)
				ssoCheckPage(t, resp, body, http.StatusBadRequest, ssoPageInvalid)
				return nil
			},
		})
		if !errors.Is(err, ErrSSOTimeout) || time.Since(start) > 5*time.Second {
			t.Fatalf("timeout returned %v", err)
		}
		if launchCtx.Err() == nil || !errors.Is(context.Cause(launchCtx), ErrSSOTimeout) {
			t.Fatal("launch context outlived the attempt")
		}
		ssoAssertClosed(t, cb)
	})

	t.Run("callback accepted as the attempt times out", func(t *testing.T) {
		// The result and the deadline are both ready when the wait starts;
		// the person was told sign-in completed, so the token must win.
		for range 16 {
			login, err := caps.ReceiveSSOLogin(context.Background(), SSOLoopback{
				Timeout:  50 * time.Millisecond,
				Sessions: ssoSessions{},
				Launch: func(ctx context.Context, browser string) error {
					cb := ssoCallbackURL(t, browser)
					resp, body := ssoGet(t, cb.Host, cb.Path+"?loginToken=synthetic-late")
					ssoCheckPage(t, resp, body, http.StatusOK, ssoPageAccepted)
					<-ctx.Done()
					return nil
				},
			})
			if err != nil {
				t.Fatalf("accepted callback lost to the timeout: %v", err)
			}
			if tok, ok := login.take(); !ok || tok != "synthetic-late" {
				t.Fatal("accepted token lost")
			}
		}
	})

	t.Run("caller cancels while Launch waits on its context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var cb *url.URL
		_, err := caps.ReceiveSSOLogin(ctx, SSOLoopback{
			Timeout:  time.Minute,
			Sessions: ssoSessions{},
			Launch: func(lctx context.Context, browser string) error {
				cb = ssoCallbackURL(t, browser)
				cancel()
				<-lctx.Done()
				return fmt.Errorf("launcher stopped: %w", lctx.Err())
			},
		})
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrSSOBrowser) {
			t.Fatalf("cancelled launch returned %v", err)
		}
		ssoAssertClosed(t, cb)
	})

	t.Run("attempt times out while Launch waits on its context", func(t *testing.T) {
		_, err := caps.ReceiveSSOLogin(context.Background(), SSOLoopback{
			Timeout:  50 * time.Millisecond,
			Sessions: ssoSessions{},
			Launch: func(lctx context.Context, _ string) error {
				<-lctx.Done()
				return context.Cause(lctx)
			},
		})
		if !errors.Is(err, ErrSSOTimeout) || errors.Is(err, ErrSSOBrowser) {
			t.Fatalf("timed-out launch returned %v", err)
		}
	})

	t.Run("caller cancels after a callback is accepted", func(t *testing.T) {
		// Deterministic: the result is buffered and the caller's context
		// is done before the wait starts. Whichever select branch runs, the
		// caller's cancellation wins and the token is dropped.
		for range 16 {
			ctx, cancel := context.WithCancel(context.Background())
			login, err := caps.ReceiveSSOLogin(ctx, SSOLoopback{
				Timeout:  time.Minute,
				Sessions: ssoSessions{},
				Launch: func(_ context.Context, browser string) error {
					cb := ssoCallbackURL(t, browser)
					resp, body := ssoGet(t, cb.Host, cb.Path+"?loginToken=synthetic-dropped")
					ssoCheckPage(t, resp, body, http.StatusOK, ssoPageAccepted)
					cancel()
					return nil
				},
			})
			if !errors.Is(err, context.Canceled) || login != nil {
				t.Fatalf("cancelled attempt returned %v, %v", login, err)
			}
		}
	})

	t.Run("caller cancels after the homeserver error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		_, err := caps.ReceiveSSOLogin(ctx, SSOLoopback{
			Timeout:  time.Minute,
			Sessions: ssoSessions{},
			Launch: func(_ context.Context, browser string) error {
				cb := ssoCallbackURL(t, browser)
				ssoGet(t, cb.Host, cb.Path+"?error=access_denied")
				cancel()
				return nil
			},
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled denied attempt returned %v", err)
		}
	})

	t.Run("caller cancels during the session check", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		_, err := caps.ReceiveSSOLogin(ctx, SSOLoopback{
			Sessions: ssoCancellingSessions{cancel: cancel},
			Launch: func(context.Context, string) error {
				t.Error("launched after cancellation")
				return nil
			},
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled session check returned %v", err)
		}
	})

	t.Run("cancel while waiting", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var cb *url.URL
		done := make(chan error, 1)
		launched := make(chan struct{})
		go func() {
			_, err := caps.ReceiveSSOLogin(ctx, SSOLoopback{
				Timeout:  time.Minute,
				Sessions: ssoSessions{},
				Launch: func(_ context.Context, browser string) error {
					cb = ssoCallbackURL(t, browser)
					close(launched)
					return nil
				},
			})
			done <- err
		}()
		<-launched
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cancellation did not end the attempt")
		}
		ssoAssertClosed(t, cb)
	})

	t.Run("cancel before start", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := caps.ReceiveSSOLogin(ctx, SSOLoopback{Sessions: ssoSessions{}, Launch: func(context.Context, string) error {
			t.Error("launched after cancellation")
			return nil
		}})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-cancelled attempt returned %v", err)
		}
	})

	t.Run("caller deadline shorter than timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := caps.ReceiveSSOLogin(ctx, SSOLoopback{Timeout: time.Minute, Sessions: ssoSessions{}, Launch: func(context.Context, string) error { return nil }})
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrSSOTimeout) {
			t.Fatalf("caller deadline returned %v", err)
		}
	})

	t.Run("launch failure", func(t *testing.T) {
		var cb *url.URL
		cause := errors.New("synthetic launcher failure")
		_, err := caps.ReceiveSSOLogin(context.Background(), SSOLoopback{
			Timeout:  time.Minute,
			Sessions: ssoSessions{},
			Launch: func(_ context.Context, browser string) error {
				cb = ssoCallbackURL(t, browser)
				return fmt.Errorf("open %s: %w", browser, cause)
			},
		})
		if !errors.Is(err, ErrSSOBrowser) || !errors.Is(err, cause) || err.Error() != ErrSSOBrowser.Error() {
			t.Fatalf("launch failure returned %q", err)
		}
		ssoAssertClosed(t, cb)
	})

	t.Run("callback accepted inside a failing launch", func(t *testing.T) {
		_, err := caps.ReceiveSSOLogin(context.Background(), SSOLoopback{
			Timeout:  time.Minute,
			Sessions: ssoSessions{},
			Launch: func(_ context.Context, browser string) error {
				cb := ssoCallbackURL(t, browser)
				ssoGet(t, cb.Host, cb.Path+"?loginToken=synthetic-token")
				return errors.New("synthetic launcher failure")
			},
		})
		if !errors.Is(err, ErrSSOBrowser) {
			t.Fatalf("failed launch returned %v", err)
		}
	})

	ssoNoLeak(t, baseline)
}

// TestSSOLoopbackSlowClientShutdown holds a half-sent request open when the
// attempt ends, which Shutdown cannot drain gracefully, and checks the
// call still returns within the shutdown bound with nothing left running.
func TestSSOLoopbackSlowClientShutdown(t *testing.T) {
	baseline := ssoListenerGoroutines()
	var conn net.Conn
	start := time.Now()
	_, err := ssoTestCaps().ReceiveSSOLogin(context.Background(), SSOLoopback{
		Timeout:  200 * time.Millisecond,
		Sessions: ssoSessions{},
		Launch: func(_ context.Context, browser string) error {
			cb := ssoCallbackURL(t, browser)
			var err error
			conn, err = net.Dial("tcp", cb.Host)
			if err != nil {
				return err
			}
			_, err = io.WriteString(conn, "GET "+cb.Path+"?loginToken=synthetic-slow HTTP/1.1\r\nHost: "+cb.Host+"\r\n")
			return err
		},
	})
	if !errors.Is(err, ErrSSOTimeout) {
		t.Fatalf("slow client attempt returned %v", err)
	}
	if time.Since(start) > ssoShutdownTimeout+5*time.Second {
		t.Fatal("shutdown not bounded")
	}
	conn.Close()
	ssoNoLeak(t, baseline)
}

func TestSSOLoopbackConfiguration(t *testing.T) {
	ctx := context.Background()
	launch := func(context.Context, string) error {
		t.Error("browser launched for a refused attempt")
		return nil
	}
	for _, caps := range []LoginCapabilities{
		{},
		{SSO: true, server: ssoTestHomeserver},
		{Token: true, server: ssoTestHomeserver},
		{SSO: true, Token: true},
	} {
		if _, err := caps.ReceiveSSOLogin(ctx, SSOLoopback{Sessions: ssoSessions{}, Launch: launch}); !errors.Is(err, ErrSSOUnsupported) {
			t.Fatalf("unsupported capabilities returned %v", err)
		}
	}
	for _, lb := range []SSOLoopback{
		{Address: "localhost", Sessions: ssoSessions{}, Launch: launch},
		{Address: "0.0.0.0", Sessions: ssoSessions{}, Launch: launch},
		{Address: "::", Sessions: ssoSessions{}, Launch: launch},
		{Address: "192.0.2.1", Sessions: ssoSessions{}, Launch: launch},
		{Address: "127.0.0.2", Sessions: ssoSessions{}, Launch: launch},
		{Address: "127.0.0.1:8080", Sessions: ssoSessions{}, Launch: launch},
		{Address: "[::1]", Sessions: ssoSessions{}, Launch: launch},
		{Launch: launch},
		{Sessions: ssoSessions{}},
		{Timeout: -time.Second, Sessions: ssoSessions{}, Launch: launch},
	} {
		if _, err := ssoTestCaps().ReceiveSSOLogin(ctx, lb); !errors.Is(err, ErrSSOLoopback) {
			t.Fatalf("configuration %+v returned %v", lb.Address, err)
		}
	}
	stored := &Session{UserID: testUser, DeviceID: "SYNTHETIC", AccessToken: "synthetic-access-token"}
	if _, err := ssoTestCaps().ReceiveSSOLogin(ctx, SSOLoopback{Sessions: ssoSessions{sess: stored}, Launch: launch}); !errors.Is(err, ErrSessionStored) {
		t.Fatalf("stored session returned %v", err)
	}
	loadErr := errors.New("synthetic store failure")
	if _, err := ssoTestCaps().ReceiveSSOLogin(ctx, SSOLoopback{Sessions: ssoSessions{err: loadErr}, Launch: launch}); !errors.Is(err, loadErr) {
		t.Fatalf("store failure returned %v", err)
	}
}

func TestSSOLoopbackIPv6(t *testing.T) {
	if ln, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback")
	} else {
		ln.Close()
	}
	login, err := ssoTestCaps().ReceiveSSOLogin(context.Background(), SSOLoopback{
		Address:  "::1",
		Timeout:  time.Minute,
		Sessions: ssoSessions{},
		Launch: func(_ context.Context, browser string) error {
			cb := ssoCallbackURL(t, browser)
			if cb.Hostname() != "::1" || !strings.HasPrefix(cb.Host, "[::1]:") {
				t.Fatal("IPv6 callback not bracketed")
			}
			resp, body := ssoGet(t, cb.Host, cb.Path+"?loginToken=synthetic-v6")
			ssoCheckPage(t, resp, body, http.StatusOK, ssoPageAccepted, "synthetic-v6")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("IPv6 loopback: %v", err)
	}
	if tok, ok := login.take(); !ok || tok != "synthetic-v6" {
		t.Fatal("IPv6 token lost")
	}
}

// ssoAssertRedacted formats v with every verb, marshals it to JSON and logs
// it through zerolog, and fails if any secret appears in plain, quoted or
// hex form. A JSON marshal error is acceptable: nothing is written.
func ssoAssertRedacted(t *testing.T, name string, v any, secrets ...string) {
	t.Helper()
	var forms []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		forms = append(forms, fmt.Sprintf(verb, v))
	}
	if b, err := json.Marshal(v); err == nil {
		forms = append(forms, string(b))
	}
	var logs bytes.Buffer
	zl := zerolog.New(&logs)
	zl.Info().Interface("v", v).Msgf("%v", v)
	forms = append(forms, logs.String())
	for _, form := range forms {
		for _, secret := range secrets {
			for _, enc := range []string{secret, fmt.Sprintf("%x", secret), fmt.Sprintf("%X", secret), url.QueryEscape(secret)} {
				if strings.Contains(form, enc) {
					t.Fatalf("%s leaked a secret: %q", name, form)
				}
			}
		}
	}
}

// TestLoginValuesRedacted covers every value in this package that holds a
// login token, an authorization code or verifier, a URL nonce or state, or
// an access token, by pointer and by value, alone and inside Options.
func TestLoginValuesRedacted(t *testing.T) {
	const (
		token    = "synthetic-format-token"
		code     = "synthetic-format-code"
		verifier = "synthetic-format-verifier"
		state    = "synthetic-format-state"
		access   = "synthetic-format-access"
		refresh  = "synthetic-format-refresh"
		password = "synthetic-format-password"
	)
	sso := &SSOLogin{s: &ssoLoginState{homeserver: ssoTestHomeserver, token: ptr(token)}}
	ssoAssertRedacted(t, "*SSOLogin", sso, token)
	ssoAssertRedacted(t, "SSOLogin", *sso, token)
	oauth := &OAuthLogin{p: &oauthLoginState{grant: &oauthGrant{code: code, verifier: verifier}}}
	ssoAssertRedacted(t, "*OAuthLogin", oauth, code, verifier)
	ssoAssertRedacted(t, "OAuthLogin", *oauth, code, verifier)
	authz := &OAuthAuthorization{
		URL: "https://auth.example.org/authorize?state=" + state,
		p:   &oauthAttempt{secrets: &oauthAttemptSecrets{state: state, verifier: verifier}},
	}
	ssoAssertRedacted(t, "*OAuthAuthorization", authz, state, verifier)
	ssoAssertRedacted(t, "OAuthAuthorization", *authz, state, verifier)
	opts := Options{
		Homeserver: ssoTestHomeserver,
		Login:      &mautrix.ReqLogin{Type: mautrix.AuthTypeToken, Token: token, Password: password},
		OAuthLogin: oauth,
		SSOLogin:   sso,
	}
	ssoAssertRedacted(t, "Options", opts, token, code, verifier, password)
	ssoAssertRedacted(t, "*Options", &opts, token, code, verifier, password)
	sess := &Session{UserID: testUser, DeviceID: "SYNTHETIC", AccessToken: access, PickleKey: []byte("synthetic-pickle"),
		BackupKey: []byte("synthetic-backup"), OAuth: &OAuthSession{Issuer: "https://auth.example.org/", RefreshToken: refresh}}
	for _, v := range []any{sess, *sess, sess.OAuth, *sess.OAuth} {
		var forms []string
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			forms = append(forms, fmt.Sprintf(verb, v))
		}
		for _, f := range forms {
			for _, secret := range []string{access, refresh, "synthetic-pickle", "synthetic-backup", fmt.Sprintf("%x", access)} {
				if strings.Contains(f, secret) {
					t.Fatalf("session formatting leaked a secret: %q", f)
				}
			}
		}
	}
	// JSON is the session's storage format and must keep its secrets.
	if b, _ := json.Marshal(sess); !bytes.Contains(b, []byte(access)) || !bytes.Contains(b, []byte(refresh)) {
		t.Fatal("session JSON lost its stored secrets")
	}
	c := &Client{Client: &mautrix.Client{UserID: testUser, DeviceID: "SYNTHETIC", AccessToken: access}, session: sess}
	ssoAssertRedacted(t, "*Client", c, access, refresh, "synthetic-pickle", "synthetic-backup")

	// In an unexported field fmt cannot call Format: it prints the fields
	// by reflection, and dereferences one pointer when a verb such as %s
	// does not suit it. Values whose secrets are private keep them behind a
	// further pointer, so they survive that, as does a *Client held by
	// another struct, rihma's or the application's. Exported secret fields
	// (Session's, OAuthAuthorization.URL, mautrix.ReqLogin's) cannot be
	// protected there; their documentation says so.
	ssoAssertRedacted(t, "*SASController", newSASController(c), access, refresh, "synthetic-pickle", "synthetic-backup")
	type holder struct {
		client *Client
		sso    *SSOLogin
		ssoVal SSOLogin
		oauth  *OAuthLogin
		oauthV OAuthLogin
	}
	h := holder{c, sso, *sso, oauth, *oauth}
	ssoAssertRedacted(t, "holder", h, token, code, verifier, access, refresh, "synthetic-pickle", "synthetic-backup")
	ssoAssertRedacted(t, "*holder", &h, token, code, verifier, access, refresh, "synthetic-pickle", "synthetic-backup")
	type authzHolder struct {
		authz  *OAuthAuthorization
		authzV OAuthAuthorization
	}
	ssoAssertRedacted(t, "authzHolder", authzHolder{authz, *authz}, verifier)
}

// TestOpenDropsLoginOptions checks that a Client does not keep the login
// options it was opened with, so neither the password nor a token outlives
// Open in its copy of Options.
func TestOpenDropsLoginOptions(t *testing.T) {
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c.Close()
	if c.opts.Login != nil || c.opts.OAuthLogin != nil || c.opts.SSOLogin != nil {
		t.Fatal("Client kept its login options")
	}
	if opts.Login == nil {
		t.Fatal("Open cleared the caller's Options")
	}
}

// TestSSOLoginBound checks that Open refuses an SSOLogin for another
// homeserver before any request, and that it is exclusive with the other
// login options.
func TestSSOLoginBound(t *testing.T) {
	const token = "synthetic-format-token"
	l := &SSOLogin{s: &ssoLoginState{homeserver: ssoTestHomeserver, token: ptr(token)}}

	h := newTestHS(t)
	var logins atomic.Int32
	inner := h.ms.Server.Config.Handler
	h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_matrix/client/v3/login" {
			logins.Add(1)
		}
		inner.ServeHTTP(w, r)
	})
	opts := testOptions(t, h, t.TempDir())
	opts.Login, opts.SSOLogin = nil, l
	if c, err := Open(context.Background(), opts); !errors.Is(err, ErrSSOLogin) || strings.Contains(err.Error(), token) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("SSOLogin for another homeserver returned %v", err)
	}
	if logins.Load() != 0 || l.s.used {
		t.Fatal("misbound SSOLogin reached a homeserver or was consumed")
	}
	for _, o := range []Options{
		{Login: &mautrix.ReqLogin{}, SSOLogin: l},
		{OAuthLogin: &OAuthLogin{}, SSOLogin: l},
	} {
		o.Homeserver, o.StateDir, o.Sessions = h.ms.Server.URL, t.TempDir(), ssoSessions{}
		if _, err := Open(context.Background(), o); err == nil || !strings.Contains(err.Error(), "exclusive") {
			t.Fatal("SSOLogin combined with another login option")
		}
	}
	// Trailing slashes and the discovered base path compare equal.
	tenant := &SSOLogin{s: &ssoLoginState{homeserver: "https://matrix.example.org/tenant"}}
	if !tenant.boundTo("https://matrix.example.org/tenant/") || tenant.boundTo("https://matrix.example.org") || tenant.boundTo("https://other.example.org/tenant") {
		t.Fatal("homeserver binding compared incorrectly")
	}
	if (&SSOLogin{}).boundTo(ssoTestHomeserver) || (*SSOLogin)(nil).boundTo(ssoTestHomeserver) {
		t.Fatal("unbound SSOLogin accepted")
	}
	if _, ok := (&SSOLogin{s: &ssoLoginState{homeserver: ssoTestHomeserver}}).take(); ok {
		t.Fatal("empty SSOLogin taken")
	}
	if _, ok := (&SSOLogin{}).take(); ok {
		t.Fatal("zero SSOLogin taken")
	}
	// A copy shares the single use.
	shared := SSOLogin{s: &ssoLoginState{homeserver: ssoTestHomeserver, token: ptr(token)}}
	copied := shared
	if _, ok := shared.take(); !ok {
		t.Fatal("SSOLogin not taken")
	}
	if _, ok := copied.take(); ok {
		t.Fatal("copied SSOLogin taken twice")
	}
}

func ptr[T any](v T) *T { return &v }

// TestSSOLoopbackLimitBoundaries checks each documented limit exactly: a
// request one byte over is refused without consuming the attempt, and one
// at the limit is accepted.
func TestSSOLoopbackLimitBoundaries(t *testing.T) {
	baseline := ssoListenerGoroutines()
	get := func(a, target string) string {
		return "GET " + target + " HTTP/1.1\r\nHost: " + a + "\r\nConnection: close\r\n\r\n"
	}

	t.Run("headers", func(t *testing.T) {
		tok := ssoBoundary(t,
			func(a, p string) string {
				return ssoSizedRequest(t, a, p+"?loginToken=synthetic-over", ssoMaxHeaderBytes+1)
			},
			http.StatusRequestHeaderFieldsTooLarge,
			func(a, p string) string {
				return ssoSizedRequest(t, a, p+"?loginToken=synthetic-at", ssoMaxHeaderBytes)
			})
		if tok != "synthetic-at" {
			t.Fatal("header boundary accepted the wrong request")
		}
	})

	t.Run("query", func(t *testing.T) {
		query := func(tok string, size int) string {
			q := "loginToken=" + tok + "&pad="
			return q + strings.Repeat("q", size-len(q))
		}
		tok := ssoBoundary(t,
			func(a, p string) string { return get(a, p+"?"+query("synthetic-over", ssoMaxQuery+1)) },
			http.StatusRequestURITooLong,
			func(a, p string) string { return get(a, p+"?"+query("synthetic-at", ssoMaxQuery)) })
		if tok != "synthetic-at" {
			t.Fatal("query boundary accepted the wrong request")
		}
	})

	t.Run("token", func(t *testing.T) {
		at := strings.Repeat("a", ssoMaxToken)
		tok := ssoBoundary(t,
			func(a, p string) string { return get(a, p+"?loginToken="+strings.Repeat("o", ssoMaxToken+1)) },
			http.StatusBadRequest,
			func(a, p string) string { return get(a, p+"?loginToken="+at) })
		if tok != at {
			t.Fatal("token boundary accepted the wrong request")
		}
		// The limit is on the decoded token: an escape counts once. These
		// raw queries stay under ssoMaxQuery.
		escaped := strings.Repeat("%7E", 1000) + strings.Repeat("a", ssoMaxToken-1000)
		tok = ssoBoundary(t,
			func(a, p string) string { return get(a, p+"?loginToken="+escaped+"a") },
			http.StatusBadRequest,
			func(a, p string) string { return get(a, p+"?loginToken="+escaped) })
		if tok != strings.Repeat("~", 1000)+strings.Repeat("a", ssoMaxToken-1000) {
			t.Fatal("escaped token boundary accepted the wrong request")
		}
	})

	t.Run("body", func(t *testing.T) {
		with := func(framing, body string) func(a, p string) string {
			return func(a, p string) string {
				return "GET " + p + "?loginToken=synthetic-body HTTP/1.1\r\nHost: " + a + "\r\n" + framing + "Connection: close\r\n\r\n" + body
			}
		}
		for _, over := range []func(a, p string) string{
			with("Content-Length: 1\r\n", "x"),
			with("Transfer-Encoding: chunked\r\n", "0\r\n\r\n"),
		} {
			if tok := ssoBoundary(t, over, http.StatusBadRequest, with("Content-Length: 0\r\n", "")); tok != "synthetic-body" {
				t.Fatal("body boundary accepted the wrong request")
			}
		}
	})
	ssoNoLeak(t, baseline)
}

// TestSSOHeaderSizeIsALowerBound checks the handler's own header check: it
// never counts more than was sent, whatever line ends and spacing the
// client used, and it refuses a request over the limit that reaches the
// handler, without ending the attempt.
func TestSSOHeaderSizeIsALowerBound(t *testing.T) {
	for _, wire := range []string{
		"GET /rihma/sso/n?loginToken=x HTTP/1.1\r\nHost: 127.0.0.1:1\r\nX-A: b\r\nX-A: c\r\n\r\n",
		"GET /rihma/sso/n?loginToken=x HTTP/1.1\nHost:127.0.0.1:1\nX-A:b\n\n",
		"GET /rihma/sso/n HTTP/1.0\n\n",
		"GET http://127.0.0.1:1/rihma/sso/n?loginToken=x HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n",
		"GET http://127.0.0.1:1/rihma/sso/n?loginToken=x HTTP/1.0\n\n",
		"GET /rihma/sso/n HTTP/1.1\r\nHost: 127.0.0.1:1\r\nTransfer-Encoding: chunked\r\n\r\n",
	} {
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(wire)))
		if err != nil {
			t.Fatalf("fixture %q: %v", wire, err)
		}
		head := wire[:strings.Index(wire, "\n\n")+2]
		if i := strings.Index(wire, "\r\n\r\n"); i >= 0 {
			head = wire[:i+4]
		}
		if got := ssoHeaderSize(r); got > len(head) {
			t.Fatalf("header size %d exceeds the %d bytes sent for %q", got, len(head), wire)
		}
	}
	cb := &ssoCallback{authority: "127.0.0.1:1", path: ssoCallbackPrefix + "n", result: make(chan ssoResult, 1)}
	wire := ssoSizedRequest(t, cb.authority, cb.path+"?loginToken=synthetic-large", ssoMaxHeaderBytes+64)
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(wire)))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	cb.ServeHTTP(w, r)
	if w.Code != http.StatusRequestHeaderFieldsTooLarge || w.Body.String() != ssoPageTooLong || cb.done || len(cb.result) != 0 {
		t.Fatalf("oversized request reaching the handler answered %d and ended=%v", w.Code, cb.done)
	}
}
