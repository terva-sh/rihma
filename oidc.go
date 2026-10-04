package rihma

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exsync"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/oauth"
)

// Delegated OAuth 2.0 login (the Matrix OAuth API, as served by the Matrix
// Authentication Service). mautrix provides the token requests and refreshes
// tokens before each request; rihma validates metadata, generates the attempt
// secrets, checks the callback, and owns session persistence.

var (
	// ErrOAuthUnsupported means the homeserver does not offer the OAuth API;
	// use classic login instead.
	ErrOAuthUnsupported = errors.New("rihma: homeserver does not offer OAuth login")
	// ErrOAuthDiscovery reports unreachable or unusable OAuth metadata. It
	// carries no remote reason text.
	ErrOAuthDiscovery = errors.New("rihma: OAuth metadata discovery failed")
	// ErrOAuthClient reports client metadata or a redirect URI that rihma will
	// not register.
	ErrOAuthClient = errors.New("rihma: invalid OAuth client metadata or redirect URI")
	// ErrOAuthRegistration reports a refused or unusable client registration.
	ErrOAuthRegistration = errors.New("rihma: OAuth client registration failed")
	// ErrOAuthCallback reports a callback that does not belong to the pending
	// attempt, or an attempt that has already been completed.
	ErrOAuthCallback = errors.New("rihma: invalid OAuth callback")
	// ErrOAuthDenied reports an authorization error response, such as the
	// user declining consent. The attempt is finished.
	ErrOAuthDenied = errors.New("rihma: OAuth authorization was refused")
	// ErrOAuthLogin reports a failed or unusable code exchange in Open.
	ErrOAuthLogin = errors.New("rihma: OAuth login failed")
	// ErrOAuthRevoke reports a failed revocation in Logout. The session and
	// state directory are kept, so Logout can be retried.
	ErrOAuthRevoke = errors.New("rihma: OAuth revocation failed")
	// ErrOAuthSessionEnded means the issuer refused to refresh the session:
	// it was revoked, expired or replaced. Sign in again. Errors matching it
	// also match mautrix.MUnknownToken.
	ErrOAuthSessionEnded = errors.New("rihma: OAuth session ended; sign in again")
)

const (
	oauthStableScope   = "urn:matrix:client:"
	oauthUnstableScope = "urn:matrix:org.matrix.msc2967.client:"
	// oauthCleanupTimeout bounds best-effort revocation after a failed login.
	oauthCleanupTimeout = 10 * time.Second
)

// OAuthServer is a homeserver's validated OAuth metadata.
type OAuthServer struct {
	// Issuer identifies the authorization server.
	Issuer string
	// AccountManagementURI is the issuer's account management page, or "".
	AccountManagementURI string

	homeserver  string
	meta        oauth.ServerMetadata
	issRequired bool
	scopePrefix string
}

type oauthMetadata struct {
	oauth.ServerMetadata
	ScopesSupported       []string `json:"scopes_supported"`
	IssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

// DiscoverOAuth fetches the homeserver's authorization metadata without
// authentication, trying the stable endpoint and then the MSC2965 unstable
// one. It opens no store and creates no device. A homeserver without the
// OAuth API returns ErrOAuthUnsupported. Unreachable or invalid metadata
// returns ErrOAuthDiscovery. Cancellation returns the caller's context error.
func DiscoverOAuth(ctx context.Context, homeserver string) (*OAuthServer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	base, ok := normalHomeserver(homeserver)
	if !ok {
		return nil, ErrOAuthDiscovery
	}
	cli, err := mautrix.NewClient(base, "", "")
	if err != nil {
		return nil, ErrOAuthDiscovery
	}
	cli.Log = zerolog.Nop()
	var meta *oauthMetadata
	for _, path := range [][]any{{"v1", "auth_metadata"}, {"unstable", "org.matrix.msc2965", "auth_metadata"}} {
		meta = nil
		_, err = cli.MakeRequest(ctx, http.MethodGet, cli.BuildClientURL(path...), nil, &meta)
		if err == nil || !oauthNotOffered(err) {
			break
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if oauthNotOffered(err) {
			return nil, ErrOAuthUnsupported
		}
		return nil, ErrOAuthDiscovery
	}
	if !meta.valid() {
		return nil, ErrOAuthDiscovery
	}
	s := &OAuthServer{
		Issuer:      meta.Issuer,
		homeserver:  base,
		meta:        meta.ServerMetadata,
		issRequired: meta.IssParameterSupported,
		scopePrefix: oauthStableScope,
	}
	if u, err := url.Parse(meta.AccountManagementURI); err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil {
		s.AccountManagementURI = u.String()
	}
	if !slices.Contains(meta.ScopesSupported, oauthStableScope+"api:*") && slices.Contains(meta.ScopesSupported, oauthUnstableScope+"api:*") {
		s.scopePrefix = oauthUnstableScope
	}
	s.meta.Unrecognized = nil
	return s, nil
}

func oauthNotOffered(err error) bool {
	var httpErr mautrix.HTTPError
	return errors.Is(err, mautrix.MUnrecognized) || errors.As(err, &httpErr) && httpErr.IsStatus(http.StatusNotFound)
}

func (m *oauthMetadata) valid() bool {
	if m == nil {
		return false
	}
	issuer, err := url.Parse(m.Issuer)
	if err != nil || !safeSSOURL(issuer) || issuer.RawQuery != "" {
		return false
	}
	for _, endpoint := range []string{m.AuthorizationEndpoint, m.TokenEndpoint, m.RegistrationEndpoint, m.RevocationEndpoint} {
		if u, err := url.Parse(endpoint); err != nil || !safeSSOURL(u) {
			return false
		}
	}
	return slices.Contains(m.ResponseTypesSupported, oauth.ResponseTypeCode) &&
		slices.Contains(m.ResponseModesSupported, oauth.ResponseModeQuery) &&
		slices.Contains(m.GrantTypesSupported, oauth.GrantTypeAuthorizationCode) &&
		slices.Contains(m.GrantTypesSupported, oauth.GrantTypeRefreshToken) &&
		slices.Contains(m.CodeChallengeMethodsSupported, oauth.CodeChallengeMethodS256)
}

// normalHomeserver accepts an HTTPS (or loopback HTTP fixture) base URL and
// returns it without a trailing slash, so equal servers compare equal.
func normalHomeserver(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || !safeSSOURL(u) || u.RawQuery != "" || u.ForceQuery {
		return "", false
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), true
}

// OAuthClientMetadata describes the application in its client registration.
// The issuer shows it on the consent page.
type OAuthClientMetadata struct {
	// ClientName is the application's display name.
	ClientName string
	// ClientURI is the application's HTTPS home page. Required.
	ClientURI string
	// LogoURI, PolicyURI and TOSURI are optional HTTPS pages on ClientURI's
	// host or a subdomain of it.
	LogoURI   string
	PolicyURI string
	TOSURI    string
}

// OAuthAuthorization is one pending browser authorization. It holds the
// attempt's state and PKCE verifier in memory only; it cannot be resumed
// after a restart. Drop it to cancel.
type OAuthAuthorization struct {
	// URL is the authorization page to open in the user's browser. It carries
	// the attempt's state: treat it as transient and do not log it.
	URL string

	server   *OAuthServer
	clientID string
	redirect *url.URL
	state    string
	verifier string
	deviceID id.DeviceID

	mu   sync.Mutex
	done bool
}

// BeginLogin registers a native public client for one attempt, as MSC2966
// requires at the start of each authorization flow, and prepares the browser
// URL. redirectURI is the caller-owned callback: loopback HTTP on 127.0.0.1,
// [::1] or localhost with an explicit port (registered without the port), or
// a private-use scheme naming ClientURI's host in reverse-DNS order, such as
// com.example.app:/callback. Queries, fragments and user info are refused.
// The request asks for full client API access and a new device whose ID rihma
// generates. Cancellation returns the caller's context error.
func (s *OAuthServer) BeginLogin(ctx context.Context, client OAuthClientMetadata, redirectURI string) (*OAuthAuthorization, error) {
	if s == nil || s.homeserver == "" {
		return nil, ErrOAuthUnsupported
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	redirect, registered, ok := nativeRedirect(client, redirectURI)
	if !ok {
		return nil, ErrOAuthClient
	}
	cli, err := mautrix.NewClient(s.homeserver, "", "")
	if err != nil {
		return nil, ErrOAuthRegistration
	}
	cli.Log = zerolog.Nop()
	meta := s.meta
	cli.OAuthSetServerMetadata(&meta)
	reg, err := cli.OAuthRegisterClient(ctx, &oauth.ClientMetadata{
		ApplicationType:         oauth.ApplicationTypeNative,
		ClientName:              client.ClientName,
		ClientURI:               client.ClientURI,
		LogoURI:                 client.LogoURI,
		PolicyURI:               client.PolicyURI,
		TOSURI:                  client.TOSURI,
		GrantTypes:              []oauth.GrantType{oauth.GrantTypeAuthorizationCode, oauth.GrantTypeRefreshToken},
		RedirectURIs:            []string{registered},
		ResponseTypes:           []oauth.ResponseType{oauth.ResponseTypeCode},
		TokenEndpointAuthMethod: oauth.AuthMethodNone,
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrOAuthRegistration
	}
	if reg == nil || reg.ClientID == "" || reg.TokenEndpointAuthMethod != "" && reg.TokenEndpointAuthMethod != oauth.AuthMethodNone {
		return nil, ErrOAuthRegistration
	}
	a := &OAuthAuthorization{
		server:   s,
		clientID: reg.ClientID,
		redirect: redirect,
		state:    randomURLToken(),
		verifier: randomURLToken(),
		deviceID: id.DeviceID(strings.TrimRight(base32.StdEncoding.EncodeToString(randomBytes(10)), "=")),
	}
	challenge := sha256.Sum256([]byte(a.verifier))
	authURL, err := url.Parse(s.meta.AuthorizationEndpoint)
	if err != nil {
		return nil, ErrOAuthDiscovery
	}
	q := authURL.Query()
	q.Set("response_type", string(oauth.ResponseTypeCode))
	q.Set("client_id", a.clientID)
	q.Set("redirect_uri", redirect.String())
	q.Set("scope", s.scopePrefix+"api:* "+s.scopePrefix+"device:"+string(a.deviceID))
	q.Set("state", a.state)
	q.Set("response_mode", string(oauth.ResponseModeQuery))
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", string(oauth.CodeChallengeMethodS256))
	authURL.RawQuery = q.Encode()
	a.URL = authURL.String()
	return a, nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("rihma: crypto/rand: %v", err))
	}
	return b
}

func randomURLToken() string { return base64.RawURLEncoding.EncodeToString(randomBytes(32)) }

// nativeRedirect applies MSC2966's native-client rules. It returns the URI
// used in the authorization request and the one registered for it.
func nativeRedirect(client OAuthClientMetadata, redirectURI string) (*url.URL, string, bool) {
	home, err := url.Parse(client.ClientURI)
	if err != nil || home.Scheme != "https" || home.Hostname() == "" || home.User != nil || home.Fragment != "" {
		return nil, "", false
	}
	host := strings.ToLower(home.Hostname())
	for _, page := range []string{client.LogoURI, client.PolicyURI, client.TOSURI} {
		if page == "" {
			continue
		}
		u, err := url.Parse(page)
		if err != nil || u.Scheme != "https" || u.User != nil {
			return nil, "", false
		}
		if h := strings.ToLower(u.Hostname()); h != host && !strings.HasSuffix(h, "."+host) {
			return nil, "", false
		}
	}
	u, err := url.Parse(redirectURI)
	if err != nil || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(redirectURI, "#") {
		return nil, "", false
	}
	switch {
	case u.Scheme == "http":
		switch u.Hostname() {
		case "127.0.0.1", "::1", "localhost":
		default:
			return nil, "", false
		}
		if !safeSSOURL(u) { // requires an explicit, valid port
			return nil, "", false
		}
		registered := *u
		registered.Host = u.Hostname()
		if strings.Contains(registered.Host, ":") {
			registered.Host = "[" + registered.Host + "]"
		}
		return u, registered.String(), true
	case u.Scheme == reverseDNS(host) && strings.Contains(u.Scheme, ".") && u.Host == "" && strings.HasPrefix(u.Path, "/"):
		return u, u.String(), true
	}
	return nil, "", false
}

func reverseDNS(host string) string {
	labels := strings.Split(host, ".")
	slices.Reverse(labels)
	return strings.Join(labels, ".")
}

var oauthErrorCode = regexp.MustCompile(`^[a-z_]{1,64}$`)

// Accept validates the browser's return to the redirect URI: the full
// callback URL, including its query. The callback must match the redirect's
// scheme, host, port and path, carry this attempt's state and, when the
// issuer includes or promises it (RFC 9207), its issuer. A callback that
// fails those checks returns ErrOAuthCallback and leaves the attempt pending,
// so a stray request does not end it. An authorization error response returns
// ErrOAuthDenied, naming only a well-formed OAuth error code. A successful
// Accept finishes the attempt; pass the result to Open in Options.OAuthLogin.
func (a *OAuthAuthorization) Accept(callback string) (*OAuthLogin, error) {
	if a == nil || a.server == nil {
		return nil, ErrOAuthCallback
	}
	u, err := url.Parse(callback)
	if err != nil || u.User != nil || u.Opaque != "" || u.Fragment != "" ||
		u.Scheme != a.redirect.Scheme || u.Host != a.redirect.Host || u.EscapedPath() != a.redirect.EscapedPath() {
		return nil, ErrOAuthCallback
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, ErrOAuthCallback
	}
	state := q["state"]
	if len(state) != 1 || subtle.ConstantTimeCompare([]byte(state[0]), []byte(a.state)) != 1 {
		return nil, ErrOAuthCallback
	}
	iss := q["iss"]
	if len(iss) > 1 || len(iss) == 1 && iss[0] != a.server.Issuer || len(iss) == 0 && a.server.issRequired {
		return nil, ErrOAuthCallback
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.done {
		return nil, ErrOAuthCallback
	}
	if q.Has("error") {
		a.done = true
		if code := q.Get("error"); oauthErrorCode.MatchString(code) {
			return nil, fmt.Errorf("%w: %s", ErrOAuthDenied, code)
		}
		return nil, ErrOAuthDenied
	}
	code := q["code"]
	if len(code) != 1 || code[0] == "" {
		return nil, ErrOAuthCallback
	}
	a.done = true
	return &OAuthLogin{grant: oauthGrant{
		server:      a.server,
		clientID:    a.clientID,
		redirectURI: a.redirect.String(),
		code:        code[0],
		verifier:    a.verifier,
		deviceID:    a.deviceID,
	}}, nil
}

// OAuthLogin is an accepted authorization response, ready for Open. It holds
// the authorization code and PKCE verifier: do not log or retain it. It is
// single-use, whether the exchange succeeds or fails.
type OAuthLogin struct {
	mu    sync.Mutex
	used  bool
	grant oauthGrant
}

type oauthGrant struct {
	server      *OAuthServer
	clientID    string
	redirectURI string
	code        string
	verifier    string
	deviceID    id.DeviceID
}

// take marks the login used and returns its values for one exchange.
func (l *OAuthLogin) take() (oauthGrant, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used || l.grant.server == nil {
		return oauthGrant{}, false
	}
	l.used = true
	g := l.grant
	l.grant.code, l.grant.verifier = "", ""
	return g, true
}

func (l *OAuthLogin) boundTo(homeserver string) bool {
	base, ok := normalHomeserver(homeserver)
	return ok && l.grant.server != nil && l.grant.server.homeserver == base
}

// loginOAuth exchanges the code, confirms the account and device, and saves
// the session before returning. Tokens issued to a login that then fails are
// revoked, best effort.
func (c *Client) loginOAuth(ctx context.Context, login *OAuthLogin, pickleKey []byte) error {
	l, ok := login.take()
	if !ok {
		return fmt.Errorf("%w: authorization already used", ErrOAuthLogin)
	}
	meta := l.server.meta
	c.Client.OAuthSetServerMetadata(&meta)
	c.boundUnknownTokenRetry()
	start := time.Now()
	resp, err := c.Client.OAuthExchangeToken(ctx, oauth.ExchangeTokenParams{
		CodeVerifier: l.verifier,
		RedirectURI:  l.redirectURI,
		Code:         l.code,
		ClientID:     l.clientID,
	})
	if err != nil {
		// A cancelled exchange may still have been redeemed, creating a
		// device whose tokens never arrived; there is nothing here to revoke.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: %s", ErrOAuthLogin, oauthFailure(err))
	}
	if resp == nil {
		return fmt.Errorf("%w: empty token response", ErrOAuthLogin)
	}
	expiry := start.Add(resp.ExpiresIn.Duration)
	c.Client.OAuthSetTokens(l.clientID, resp.RefreshToken, resp.AccessToken, expiry)
	if resp.AccessToken == "" || resp.RefreshToken == "" || !strings.EqualFold(resp.TokenType, "Bearer") || resp.ExpiresIn.Duration <= 0 {
		c.abandonOAuth(ctx)
		return fmt.Errorf("%w: unusable token response", ErrOAuthLogin)
	}
	c.sessionMu.Lock()
	c.session = Session{AccessToken: resp.AccessToken, PickleKey: pickleKey, OAuth: &OAuthSession{
		Issuer:             l.server.Issuer,
		ClientID:           l.clientID,
		TokenEndpoint:      l.server.meta.TokenEndpoint,
		RevocationEndpoint: l.server.meta.RevocationEndpoint,
		RefreshToken:       resp.RefreshToken,
		ExpiresAt:          expiry,
	}}
	c.sessionMu.Unlock()
	who, err := c.Whoami(ctx)
	if err != nil || who == nil || who.UserID == "" || who.DeviceID != l.deviceID {
		c.abandonOAuth(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return fmt.Errorf("%w: account lookup: %s", ErrOAuthLogin, oauthFailure(err))
		}
		return fmt.Errorf("%w: homeserver did not confirm the requested device", ErrOAuthLogin)
	}
	c.UserID, c.DeviceID = who.UserID, who.DeviceID
	err = c.writeSession(ctx, true, func(s *Session) error {
		s.UserID, s.DeviceID = who.UserID, who.DeviceID
		return nil
	})
	if err != nil {
		// Without a saved session the new device is unreachable; end it.
		c.abandonOAuth(ctx)
		return err
	}
	return nil
}

// oauthFailure names an HTTP status and OAuth or Matrix error code without
// any remote description text.
func oauthFailure(err error) string {
	var httpErr mautrix.HTTPError
	if errors.As(err, &httpErr) && httpErr.Response != nil {
		if httpErr.RespError != nil && oauthErrorCode.MatchString(strings.ToLower(httpErr.RespError.ErrCode)) {
			return fmt.Sprintf("HTTP %d %s", httpErr.Response.StatusCode, httpErr.RespError.ErrCode)
		}
		return fmt.Sprintf("HTTP %d", httpErr.Response.StatusCode)
	}
	return "request failed"
}

// oauthRevokeError reduces a revocation failure to its status and error code,
// keeping only the caller's cancellation as a wrapped cause. The issuer's
// description text never reaches the caller.
func oauthRevokeError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w: %w", ErrOAuthRevoke, ctx.Err())
	}
	return fmt.Errorf("%w: %s", ErrOAuthRevoke, oauthFailure(err))
}

// abandonOAuth revokes the client's tokens after a failed login, even when
// the login was cancelled, within a bounded time.
func (c *Client) abandonOAuth(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), oauthCleanupTimeout)
	defer cancel()
	_ = c.Client.OAuthRevokeToken(ctx)
}

// restoreOAuth installs a stored OAuth session without network access. The
// token and revocation endpoints are the ones validated at login.
func (c *Client) restoreOAuth() error {
	o := c.session.OAuth
	for _, endpoint := range []string{o.Issuer, o.TokenEndpoint, o.RevocationEndpoint} {
		if u, err := url.Parse(endpoint); err != nil || !safeSSOURL(u) {
			return errors.New("rihma: stored OAuth session is incomplete")
		}
	}
	if o.ClientID == "" || o.RefreshToken == "" || c.session.AccessToken == "" {
		return errors.New("rihma: stored OAuth session is incomplete")
	}
	c.Client.OAuthSetServerMetadata(&oauth.ServerMetadata{Issuer: o.Issuer, TokenEndpoint: o.TokenEndpoint, RevocationEndpoint: o.RevocationEndpoint})
	c.Client.OAuthSetTokens(o.ClientID, o.RefreshToken, c.session.AccessToken, o.ExpiresAt)
	c.boundUnknownTokenRetry()
	return nil
}

// boundUnknownTokenRetry works around mautrix v0.31.0 retrying
// M_UNKNOWN_TOKEN without limit once a client holds a refresh token. Without
// a request retry trigger it compares the rejected token with "", so every
// rejection looks stale and is retried with growing backoff until the access
// token expires. With an idle trigger it compares the token actually sent: a
// rejected current token fails at once and an expired one is refreshed once.
// The trigger is never notified, so no request is interrupted.
func (c *Client) boundUnknownTokenRetry() {
	if c.Client.RequestRetryTrigger == nil {
		c.Client.RequestRetryTrigger = exsync.NewEvent()
	}
}

// saveRefreshedTokens is mautrix's SaveNewToken hook. mautrix uses a rotated
// token pair only after this returns nil, so a crash cannot strand the stored
// session behind a refresh token the issuer has already replaced. The save
// ignores the triggering request's cancellation: once issued, the new pair
// must be kept.
func (c *Client) saveRefreshedTokens(ctx context.Context, refreshToken, accessToken string, expiry time.Time) error {
	return c.writeSession(context.WithoutCancel(ctx), false, func(s *Session) error {
		if s.OAuth == nil {
			return errors.New("rihma: token refresh on a session without OAuth")
		}
		s.AccessToken = accessToken
		s.OAuth.RefreshToken, s.OAuth.ExpiresAt = refreshToken, expiry
		return nil
	})
}

// oauthRefreshRefused reports whether err is a token refresh the issuer
// refused. MSC2964 treats a 4xx refresh response as a logged-out session;
// rate limits and timeouts stay retryable.
func oauthRefreshRefused(err error) bool {
	if !errors.Is(err, mautrix.ErrFailedToRefreshToken) {
		return false
	}
	var httpErr mautrix.HTTPError
	if !errors.As(err, &httpErr) || httpErr.Response == nil {
		return false
	}
	switch httpErr.Response.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return true
	}
	return false
}

// classifySessionEnd turns a refused refresh into ErrOAuthSessionEnded and
// returns any other error unchanged.
func classifySessionEnd(err error) error {
	if oauthRefreshRefused(err) && !errors.Is(err, ErrOAuthSessionEnded) {
		return &oauthSessionEnded{cause: err}
	}
	return err
}

type oauthSessionEnded struct{ cause error }

func (e *oauthSessionEnded) Error() string { return ErrOAuthSessionEnded.Error() }
func (e *oauthSessionEnded) Unwrap() error { return e.cause }

// Is lets callers that already stop on mautrix.MUnknownToken treat a refused
// refresh the same way.
func (e *oauthSessionEnded) Is(target error) bool {
	return target == ErrOAuthSessionEnded || errors.Is(mautrix.MUnknownToken, target)
}
