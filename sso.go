package rihma

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strconv"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
)

var (
	ErrLoginDiscovery = errors.New("rihma: login flow discovery failed")
	ErrSSOUnsupported = errors.New("rihma: classic SSO token login is unavailable")
	ErrSSOCallback    = errors.New("rihma: invalid SSO callback URL")
)

// LoginCapabilities describes classic Matrix login flows, independently of an
// account runtime. It does not describe delegated OAuth/OIDC authentication.
type LoginCapabilities struct {
	Password bool
	SSO      bool
	Token    bool
	server   string
}

// DiscoverLoginFlows queries an HTTPS homeserver (or an HTTP loopback fixture)
// without opening stores, logging in, or creating a device. Server errors are
// reduced to ErrLoginDiscovery; cancellation retains the caller's context error.
func DiscoverLoginFlows(ctx context.Context, homeserver string) (LoginCapabilities, error) {
	if err := ctx.Err(); err != nil {
		return LoginCapabilities{}, err
	}
	u, err := url.Parse(homeserver)
	if err != nil || !safeSSOURL(u) || u.RawQuery != "" {
		return LoginCapabilities{}, ErrLoginDiscovery
	}
	cli, err := mautrix.NewClient(u.String(), "", "")
	if err != nil {
		return LoginCapabilities{}, ErrLoginDiscovery
	}
	cli.Log = zerolog.Nop()
	flows, err := cli.GetLoginFlows(ctx)
	if err != nil || flows == nil {
		if ctx.Err() != nil {
			return LoginCapabilities{}, ctx.Err()
		}
		return LoginCapabilities{}, ErrLoginDiscovery
	}
	return LoginCapabilities{
		Password: flows.HasFlow(mautrix.AuthTypePassword),
		SSO:      flows.HasFlow(mautrix.AuthTypeSSO),
		Token:    flows.HasFlow(mautrix.AuthTypeToken),
		server:   u.String(),
	}, nil
}

// SSORedirectURL builds the browser URL for a caller-owned callback. It makes no
// request and supports classic m.login.sso/m.login.token only. The callback must
// use HTTPS or loopback HTTP with an explicit port, without userinfo or fragments.
// The caller must bind the callback to its pending attempt and protect query data.
// Browser launch, callback listening and nonce/state validation belong to the caller.
func (l LoginCapabilities) SSORedirectURL(callback string) (string, error) {
	if l.server == "" || !l.SSO || !l.Token {
		return "", ErrSSOUnsupported
	}
	u, err := url.Parse(callback)
	if err != nil || !safeSSOURL(u) {
		return "", ErrSSOCallback
	}
	callbackQuery, err := url.ParseQuery(u.RawQuery)
	if err != nil || callbackQuery.Has("loginToken") {
		return "", ErrSSOCallback
	}
	cli, err := mautrix.NewClient(l.server, "", "")
	if err != nil {
		return "", ErrSSOUnsupported
	}
	redirect, err := url.Parse(cli.BuildClientURL("v3", "login", "sso", "redirect"))
	if err != nil {
		return "", ErrSSOUnsupported
	}
	query := redirect.Query()
	query.Set("redirectUrl", u.String())
	redirect.RawQuery = query.Encode()
	return redirect.String(), nil
}

func safeSSOURL(u *url.URL) bool {
	if u == nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" || u.Port() == "" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()
}
