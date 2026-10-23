package rihma

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A loopback callback owned by rihma for one classic SSO attempt. The
// application still opens the browser; rihma listens for the homeserver's
// redirect back, checks it against the attempt, and hands Open the token.

var (
	// ErrSSOLoopback reports an unusable SSOLoopback configuration or a
	// listener that could not be started.
	ErrSSOLoopback = errors.New("rihma: SSO loopback callback unavailable")
	// ErrSessionStored means the session store already holds a session, so
	// a browser sign-in would not be used. Open restores the stored one.
	ErrSessionStored = errors.New("rihma: a session is already stored")
	// ErrSSOBrowser reports that the application's Launch function failed.
	// The returned error also matches the launcher's own error.
	ErrSSOBrowser = errors.New("rihma: browser launch failed")
	// ErrSSOTimeout means no callback arrived before SSOLoopback.Timeout.
	ErrSSOTimeout = errors.New("rihma: SSO sign-in timed out")
	// ErrSSODenied means the homeserver returned to the callback with an
	// error instead of a login token. The attempt is finished.
	ErrSSODenied = errors.New("rihma: SSO sign-in was not completed")
	// ErrSSOLogin reports an SSOLogin that Open cannot use: one received from
	// another homeserver, or one already used.
	ErrSSOLogin = errors.New("rihma: unusable SSO login")
)

const (
	ssoLoopbackTimeout = 5 * time.Minute
	ssoShutdownTimeout = 2 * time.Second
	ssoRequestTimeout  = 10 * time.Second
	// ssoMaxHeaderBytes bounds the request line and header fields as sent,
	// through the blank line that ends them. net/http reads up to
	// MaxHeaderBytes plus a fixed 4096 bytes of bufio slack before it
	// answers 431, so MaxHeaderBytes is set that much lower; the boundary
	// tests pin the sum. ServeHTTP checks again with ssoHeaderSize.
	ssoMaxHeaderBytes = 16 << 10
	ssoHTTPHeaderSlop = 4096
	// ssoMaxQuery bounds the raw query; ssoMaxToken the decoded token.
	ssoMaxQuery       = 4 << 10
	ssoMaxToken       = 2 << 10
	ssoCallbackPrefix = "/rihma/sso/"
)

// SSOLoopback configures ReceiveSSOLogin.
type SSOLoopback struct {
	// Address is the loopback IP to listen on: "127.0.0.1" (the default when
	// empty) or "::1". The port is assigned by the operating system. The
	// name localhost is refused, because it can resolve to the other address
	// family, where another process may hold the same port.
	Address string
	// Timeout bounds the whole attempt, from listening to the callback. Zero
	// means five minutes.
	Timeout time.Duration
	// Sessions is the store the login will be saved to. Required.
	// ReceiveSSOLogin refuses to start while it holds a session.
	Sessions SessionStore
	// Launch opens url in the user's browser. Required. The listener is
	// already accepting when it is called. It must return once the browser
	// has been asked to open the page, not wait for the sign-in; ctx ends
	// with the attempt. url carries the attempt's nonce: do not log it.
	Launch func(ctx context.Context, url string) error
}

// SSOLogin is a login token received at a loopback callback, ready for
// Open in Options.SSOLogin. It is bound to the homeserver that issued it and
// is single-use, whether the exchange succeeds or fails; copies share that
// use. It formats as a fixed placeholder, by pointer or by value, and
// marshals to an empty JSON object. Do not retain it.
type SSOLogin struct {
	// The state sits behind a pointer, so a copy of the value does not copy
	// its lock, and the token sits behind another, so fmt reaches neither:
	// in an unexported field it dereferences at most one pointer.
	s *ssoLoginState
}

type ssoLoginState struct {
	mu         sync.Mutex
	used       bool
	homeserver string
	token      *string
}

// Format prints a placeholder for every verb, so the token cannot reach a
// log through fmt.
func (SSOLogin) Format(f fmt.State, _ rune) { io.WriteString(f, "rihma.SSOLogin{redacted}") }

// take marks the login used and returns its token for one exchange.
func (l *SSOLogin) take() (string, bool) {
	if l == nil || l.s == nil {
		return "", false
	}
	l.s.mu.Lock()
	defer l.s.mu.Unlock()
	if l.s.used || l.s.token == nil || *l.s.token == "" {
		return "", false
	}
	l.s.used = true
	token := *l.s.token
	l.s.token = nil
	return token, true
}

func (l *SSOLogin) boundTo(homeserver string) bool {
	base, ok := normalHomeserver(homeserver)
	return ok && l != nil && l.s != nil && l.s.homeserver != "" && l.s.homeserver == base
}

// ReceiveSSOLogin runs one browser SSO attempt with a callback that rihma
// owns. It listens on a loopback address with an OS-assigned port, asks the
// application to open the homeserver's SSO page through lb.Launch, and
// accepts one GET to the attempt's unguessable callback path carrying
// exactly one nonempty loginToken. Requests with another host, path,
// method, body or token shape are refused without ending the attempt;
// requests after it ends are refused as used or expired. The listener is
// closed and its server stopped before ReceiveSSOLogin returns; a client
// holding a request open is cut off after a short grace period. Nothing is
// logged.
//
// It returns ErrSSOUnsupported when the homeserver lacks classic SSO or
// token login, ErrSessionStored when lb.Sessions holds a session,
// ErrSSOBrowser when Launch fails, ErrSSODenied when the homeserver returns
// an error instead of a token, and ErrSSOTimeout after lb.Timeout. When the
// caller's context ends first, it returns that context's error, even if a
// callback was accepted or Launch failed; an accepted token is then dropped
// without being exchanged.
func (l LoginCapabilities) ReceiveSSOLogin(ctx context.Context, lb SSOLoopback) (*SSOLogin, error) {
	if l.server == "" || !l.SSO || !l.Token {
		return nil, ErrSSOUnsupported
	}
	home, ok := normalHomeserver(l.server)
	if !ok {
		return nil, ErrSSOUnsupported
	}
	host := lb.Address
	switch host {
	case "":
		host = "127.0.0.1"
	case "127.0.0.1", "::1":
	default:
		return nil, ErrSSOLoopback
	}
	if lb.Sessions == nil || lb.Launch == nil || lb.Timeout < 0 {
		return nil, ErrSSOLoopback
	}
	timeout := lb.Timeout
	if timeout == 0 {
		timeout = ssoLoopbackTimeout
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sess, err := lb.Sessions.Load(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if sess != nil {
		return nil, ErrSessionStored
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSSOLoopback, err)
	}
	cb := &ssoCallback{
		authority: net.JoinHostPort(host, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)),
		path:      ssoCallbackPrefix + randomURLToken(),
		result:    make(chan ssoResult, 1),
	}
	browser, err := l.SSORedirectURL("http://" + cb.authority + cb.path)
	if err != nil {
		ln.Close()
		return nil, err
	}
	srv := &http.Server{
		Handler:           cb,
		ReadHeaderTimeout: ssoRequestTimeout,
		ReadTimeout:       ssoRequestTimeout,
		WriteTimeout:      ssoRequestTimeout,
		MaxHeaderBytes:    ssoMaxHeaderBytes - ssoHTTPHeaderSlop,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	srv.SetKeepAlivesEnabled(false)
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(ln)
	}()
	defer func() {
		cb.finish()
		stop, cancel := context.WithTimeout(context.Background(), ssoShutdownTimeout)
		defer cancel()
		if srv.Shutdown(stop) != nil {
			srv.Close()
		}
		<-served
	}()

	attempt, cancel := context.WithTimeoutCause(ctx, timeout, ErrSSOTimeout)
	defer cancel()
	// Every way out below classifies the ending the same way: the caller's
	// cancellation first, then the attempt's own timeout, then what
	// happened at the callback or the launcher.
	if err := lb.Launch(attempt, browser); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempt.Err() != nil {
			return nil, ErrSSOTimeout
		}
		return nil, &ssoLaunchError{cause: err}
	}
	var r ssoResult
	select {
	case r = <-cb.result:
	case <-attempt.Done():
		if !cb.finish() {
			// A callback was accepted as the attempt ended; its page told
			// the person sign-in completed, so keep it unless the caller
			// itself gave up.
			r = <-cb.result
		}
	}
	if err := ctx.Err(); err != nil {
		// The caller gave up, even if a token arrived first. The token is
		// dropped here: no SSOLogin is made, nothing in rihma keeps it, and
		// it is never exchanged, so the homeserver lets it expire.
		return nil, err
	}
	if r.err != nil {
		return nil, r.err
	}
	if r.token == "" {
		return nil, ErrSSOTimeout
	}
	return &SSOLogin{s: &ssoLoginState{homeserver: home, token: &r.token}}, nil
}

type ssoResult struct {
	token string
	err   error
}

// ssoCallback serves the attempt's one route. done is set by the first
// callback that ends the attempt, or by finish; result receives at most
// one value.
type ssoCallback struct {
	authority string
	path      string
	result    chan ssoResult

	mu   sync.Mutex
	done bool
}

// finish ends the attempt and reports whether it was still pending.
func (c *ssoCallback) finish() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	pending := !c.done
	c.done = true
	return pending
}

// The pages the browser can show. They are fixed text: nothing from the
// request is echoed.
const (
	ssoPageAccepted = "Sign-in complete. You can close this window and return to the application.\n"
	ssoPageDenied   = "Sign-in did not complete. Return to the application to try again.\n"
	ssoPageInvalid  = "This sign-in response is not valid. Return to the application to try again.\n"
	ssoPageGone     = "This sign-in link has expired or was already used. Return to the application to try again.\n"
	ssoPageNotFound = "Not found.\n"
	ssoPageMethod   = "Method not allowed.\n"
	ssoPageTooLong  = "Request too long.\n"
)

func (c *ssoCallback) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	if ssoHeaderSize(r) > ssoMaxHeaderBytes {
		ssoPage(w, http.StatusRequestHeaderFieldsTooLarge, ssoPageTooLong)
		return
	}
	if r.Host != c.authority || subtle.ConstantTimeCompare([]byte(r.URL.EscapedPath()), []byte(c.path)) != 1 {
		ssoPage(w, http.StatusNotFound, ssoPageNotFound)
		return
	}
	if r.Method != http.MethodGet {
		h.Set("Allow", http.MethodGet)
		ssoPage(w, http.StatusMethodNotAllowed, ssoPageMethod)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		ssoPage(w, http.StatusBadRequest, ssoPageInvalid)
		return
	}
	if len(r.URL.RawQuery) > ssoMaxQuery {
		ssoPage(w, http.StatusRequestURITooLong, ssoPageTooLong)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		ssoPage(w, http.StatusBadRequest, ssoPageInvalid)
		return
	}
	status, page := c.accept(q)
	ssoPage(w, status, page)
}

// accept decides a well-addressed callback. Only the first callback that
// carries an error or a usable token ends the attempt.
func (c *ssoCallback) accept(q url.Values) (int, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return http.StatusGone, ssoPageGone
	}
	if q.Has("error") {
		c.done = true
		c.result <- ssoResult{err: ErrSSODenied}
		return http.StatusForbidden, ssoPageDenied
	}
	token := q["loginToken"]
	if len(token) != 1 || token[0] == "" || len(token[0]) > ssoMaxToken {
		return http.StatusBadRequest, ssoPageInvalid
	}
	c.done = true
	c.result <- ssoResult{token: token[0]}
	return http.StatusOK, ssoPageAccepted
}

// ssoHeaderSize is the least number of bytes the request line and header
// fields can have taken on the wire: one byte for each separator and line
// end, and the Host line only when the request target did not carry the
// host. It never exceeds what was sent, so it cannot refuse a request the
// transport admitted under the limit; it stops a larger one should the
// transport's allowance ever grow.
func ssoHeaderSize(r *http.Request) int {
	n := len(r.Method) + 1 + len(r.RequestURI) + 1 + len(r.Proto) + 1
	if strings.HasPrefix(r.RequestURI, "/") && r.Host != "" {
		n += len("Host:") + len(r.Host) + 1
	}
	for name, values := range r.Header {
		for _, v := range values {
			n += len(name) + 1 + len(v) + 1
		}
	}
	return n + 1
}

func ssoPage(w http.ResponseWriter, status int, page string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(page)))
	w.WriteHeader(status)
	io.WriteString(w, page)
}

// ssoLaunchError matches ErrSSOBrowser and the launcher's error, but its
// message is fixed, so a launcher error that quotes the URL does not carry
// the nonce further.
type ssoLaunchError struct{ cause error }

func (e *ssoLaunchError) Error() string   { return ErrSSOBrowser.Error() }
func (e *ssoLaunchError) Unwrap() []error { return []error{ErrSSOBrowser, e.cause} }
