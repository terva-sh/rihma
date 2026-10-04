package rihma

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/ssss"
)

// A server accepts an account's first cross-signing identity without
// user-interactive auth (Matrix v1.11). Replacing an existing identity
// needs either the account password or, on a server whose accounts an
// OAuth 2.0 server manages, the person's approval on that server's
// account page (the m.oauth stage of Matrix v1.17; MSC4312's unstable
// name is org.matrix.cross_signing_reset).

// Approval stages, stable name first. Both carry the same params.
var approvalStages = []mautrix.AuthType{mautrix.AuthTypeOAuth, "org.matrix.cross_signing_reset"}

var (
	// ErrPasswordRequired is returned when the server asks for the account
	// password and the CrossSigningAuth has none. Nothing was changed: ask
	// for the password and call again.
	ErrPasswordRequired = errors.New("rihma: the server asks for the account password to change the cross-signing identity")

	// ErrApprovalRequired is returned when the server asks for approval on
	// its account management page and the CrossSigningAuth has no Approve.
	// Nothing was changed.
	ErrApprovalRequired = errors.New("rihma: the server asks for approval on its account page to replace the cross-signing identity")

	// ErrAuthUnsupported is returned when the server offers only
	// user-interactive auth stages rihma cannot answer. Nothing was changed.
	ErrAuthUnsupported = errors.New("rihma: the server asks for authentication rihma cannot answer")

	// ErrApprovalURL is returned when the server's approval page is not an
	// absolute http(s) URL without credentials. Approve is not called, and
	// nothing was changed.
	ErrApprovalURL = errors.New("rihma: the server's approval page is not an http(s) URL")

	// ErrIdentityIncomplete is returned when the server accepted the new
	// cross-signing keys but storing them in secret storage, or signing
	// this device with them, failed. Any old identity is gone and no
	// recovery key was returned: run ResetCrossSigningIdentity again.
	ErrIdentityIncomplete = errors.New("rihma: the server accepted the new cross-signing identity, but its setup did not finish")
)

// CrossSigningAuth answers the user-interactive auth a server asks for
// before it lets the account replace its cross-signing identity. Leave a
// field empty when the account cannot use it.
type CrossSigningAuth struct {
	// Password answers the m.login.password stage. It is sent only when
	// the server asks for it.
	Password string

	// Approve handles a server that sends the person to its account
	// management page to approve the reset. It shows or opens
	// approval.URL, waits until the person says they have approved, and
	// returns nil; rihma then retries the upload at once. If the server
	// has not seen the approval, Approve is called again with the next
	// Attempt. Return an error to abandon the reset, and return when ctx
	// is done. Approve owns the pacing: block on the person, or sleep
	// before returning to poll. The reset's error wraps Approve's error
	// for errors.Is and errors.As but does not repeat its text, which
	// may hold the URL.
	Approve func(ctx context.Context, approval CrossSigningApproval) error
}

// CrossSigningApproval is one request for the person's approval of a
// cross-signing identity reset.
type CrossSigningApproval struct {
	// URL is the server's account management page for the approval. Show
	// or open it for the person; do not log it.
	URL string
	// Attempt counts requests in this reset from 1. Above 1, the server
	// had not seen an approval when rihma last retried.
	Attempt int
}

// ResetCrossSigningIdentity replaces the account's cross-signing identity
// and secret storage with new ones, signs this device with the new
// identity, and returns the new recovery key. The key is secret: show it
// to the person once and never log it.
//
// This is destructive. Every device and user that verified the old
// identity stops trusting the account until they verify it again, and
// the old recovery key stops working. Call it only when the person has
// asked for a reset, typically because the recovery key is lost. On an
// account with no identity it creates one, as CreateRecoveryKey does.
//
// The server asks for auth before replacing an identity; auth answers it.
// Until the server accepts the new keys nothing is written, so
// ErrPasswordRequired, ErrApprovalRequired, ErrAuthUnsupported,
// ErrApprovalURL, a rejected password (mautrix.MForbidden), an error from
// Approve, and cancellation while Approve runs leave the old identity
// and its recovery key as they were. A failure after the server accepted
// the keys is ErrIdentityIncomplete. Cancellation during the final upload
// can leave the outcome unknown; run the reset again to settle it.
//
// The account's key backup is left alone. Its key stays in secret storage
// under the old recovery key, which the new one cannot read.
func (c *Client) ResetCrossSigningIdentity(ctx context.Context, auth CrossSigningAuth) (string, error) {
	return c.bootstrapIdentity(ctx, auth, true)
}

// bootstrapIdentity creates (replace false) or replaces the account's
// cross-signing identity. The server is told about the new keys before
// anything is written to secret storage, so a refusal there costs
// nothing: writing the secrets first would overwrite the old identity's.
func (c *Client) bootstrapIdentity(ctx context.Context, auth CrossSigningAuth, replace bool) (string, error) {
	if err := c.Connect(ctx); err != nil {
		return "", err
	}
	if !replace {
		exists, err := c.HasCrossSigningIdentity(ctx)
		if err != nil {
			return "", err
		}
		if exists {
			return "", ErrIdentityExists
		}
	}
	mach := c.OlmMachine()
	keys, err := mach.GenerateCrossSigningKeys()
	if err != nil {
		return "", fmt.Errorf("rihma: generate cross-signing keys: %w", err)
	}
	storageKey, err := ssss.NewKey("")
	if err != nil {
		return "", fmt.Errorf("rihma: generate secret storage key: %w", err)
	}
	if err := c.publishCrossSigning(ctx, keys, auth, replace); err != nil {
		return "", err
	}
	if err := c.storeIdentity(ctx, storageKey, keys); err != nil {
		return "", fmt.Errorf("%w: %w", ErrIdentityIncomplete, err)
	}
	if err := c.signSelf(ctx); err != nil {
		return "", fmt.Errorf("%w: %w", ErrIdentityIncomplete, err)
	}
	return storageKey.RecoveryKey(), nil
}

// storeIdentity makes key the account's default secret storage key and
// stores the cross-signing private keys under it, as other clients
// expect to find them.
func (c *Client) storeIdentity(ctx context.Context, key *ssss.Key, keys *crypto.CrossSigningKeysCache) error {
	mach := c.OlmMachine()
	if err := mach.SSSS.SetKeyData(ctx, key.ID, key.Metadata); err != nil {
		return fmt.Errorf("store secret storage key: %w", err)
	}
	if err := mach.UploadCrossSigningKeysToSSSS(ctx, key, keys); err != nil {
		return fmt.Errorf("store cross-signing keys: %w", err)
	}
	if err := mach.SSSS.SetDefaultKeyID(ctx, key.ID); err != nil {
		return fmt.Errorf("set default secret storage key: %w", err)
	}
	return nil
}

// publishCrossSigning uploads the public keys, answering the server's
// user-interactive auth. mautrix retries a 401 once and discards the
// retry's response, so an approval the server has not yet seen is
// handled by publishing again: the fresh request draws a fresh challenge.
func (c *Client) publishCrossSigning(ctx context.Context, keys *crypto.CrossSigningKeysCache, auth CrossSigningAuth, replace bool) error {
	mach := c.OlmMachine()
	for attempt := 1; ; attempt++ {
		var stop error
		approved := false
		err := mach.PublishCrossSigningKeys(ctx, keys, func(uia *mautrix.RespUserInteractive) any {
			answer, approval, err := c.answerUIA(ctx, uia, auth, replace, attempt)
			if err != nil {
				stop = err
				return nil
			}
			approved = approval
			return answer
		})
		switch {
		case err == nil:
			return nil
		case stop != nil:
			return stop
		case ctx.Err() != nil:
			return fmt.Errorf("rihma: upload cross-signing keys: %w", ctx.Err())
		case approved && isStatus(err, http.StatusUnauthorized):
			c.opts.Logger.Debug().Int("attempt", attempt).Msg("the server has not seen the cross-signing reset approval yet")
			continue
		}
		return &uploadError{cause: err}
	}
}

// uploadError reports a failed cross-signing upload by HTTP status and
// Matrix error code, not by the server's error text: Synapse put the
// approval URL there before it adopted the approval stage. The cause
// stays available to errors.Is and errors.As (mautrix.MForbidden for a
// rejected password).
type uploadError struct{ cause error }

func (e *uploadError) Error() string {
	var httpErr mautrix.HTTPError
	if !errors.As(e.cause, &httpErr) || httpErr.Response == nil {
		// No response: a local or transport failure the server did not word.
		return "rihma: upload cross-signing keys: " + e.cause.Error()
	}
	msg := fmt.Sprintf("rihma: upload cross-signing keys: HTTP %d", httpErr.Response.StatusCode)
	if httpErr.RespError != nil && isProtocolName(httpErr.RespError.ErrCode) {
		msg += " " + httpErr.RespError.ErrCode
	}
	return msg
}

func (e *uploadError) Unwrap() error { return e.cause }

// answerUIA picks the auth for one challenge. A nil answer with a nil
// error lets the original 401 stand, for a response that is not
// user-interactive auth at all (such as M_UNKNOWN_TOKEN).
func (c *Client) answerUIA(ctx context.Context, uia *mautrix.RespUserInteractive, auth CrossSigningAuth, replace bool, attempt int) (answer any, approval bool, err error) {
	if len(uia.Flows) == 0 {
		return nil, false, nil
	}
	if !replace {
		// A current server asks for auth only to replace a master key, so
		// a challenge here means another device created an identity after
		// the first check. A server from before Matrix v1.11 asks for any
		// first upload too. Ask the server again rather than guess, so
		// create never answers a replacement.
		exists, err := c.HasCrossSigningIdentity(ctx)
		if err != nil {
			return nil, false, err
		}
		if exists {
			return nil, false, ErrIdentityExists
		}
	}
	log := c.opts.Logger
	if uia.HasSingleStageFlow(mautrix.AuthTypePassword) && auth.Password != "" {
		log.Debug().Msg("answering cross-signing upload auth with the account password")
		return &mautrix.ReqUIAuthLogin{
			BaseAuthData: mautrix.BaseAuthData{Type: mautrix.AuthTypePassword, Session: uia.Session},
			User:         c.UserID.String(),
			Password:     auth.Password,
		}, false, nil
	}
	for _, stage := range approvalStages {
		if !uia.HasSingleStageFlow(stage) {
			continue
		}
		if !replace {
			// This stage exists only to approve replacing a master key.
			return nil, false, ErrIdentityExists
		}
		if auth.Approve == nil {
			return nil, false, ErrApprovalRequired
		}
		page, err := approvalURL(uia.Params[stage])
		if err != nil {
			return nil, false, err
		}
		log.Debug().Str("stage", string(stage)).Int("attempt", attempt).Msg("asking for cross-signing reset approval on the account page")
		if err := auth.Approve(ctx, CrossSigningApproval{URL: page, Attempt: attempt}); err != nil {
			return nil, false, &approvalError{cause: err}
		}
		if err := ctx.Err(); err != nil {
			return nil, false, fmt.Errorf("rihma: cross-signing reset approval: %w", err)
		}
		// Matrix v1.17: after approval, the auth dict carries only the session.
		return &approvalAuth{Session: uia.Session}, true, nil
	}
	if uia.HasSingleStageFlow(mautrix.AuthTypePassword) {
		return nil, false, ErrPasswordRequired
	}
	return nil, false, fmt.Errorf("%w (offered: %s)", ErrAuthUnsupported, flowNames(uia.Flows))
}

type approvalAuth struct {
	Session string `json:"session,omitempty"`
}

// approvalError carries the error Approve returned. Approve holds the
// approval URL, and an error from opening or polling it can repeat it,
// so the cause is kept for errors.Is and errors.As but its text is not.
type approvalError struct{ cause error }

func (e *approvalError) Error() string {
	return "rihma: cross-signing reset approval abandoned by the application"
}

func (e *approvalError) Unwrap() error { return e.cause }

// approvalURL reads the url param of an approval stage. The page is
// opened for a person, so anything but an absolute http(s) URL without
// userinfo is refused. Its text never goes into the error.
func approvalURL(params any) (string, error) {
	fields, _ := params.(map[string]any)
	raw, _ := fields["url"].(string)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return "", ErrApprovalURL
	}
	return raw, nil
}

// flowNames lists the offered flows, stages joined by "+", for errors.
// Stage names are protocol identifiers; one that does not look like one
// is the server's free text and is replaced rather than repeated.
// isProtocolName is that test, for stage names and error codes alike.
func flowNames(flows []mautrix.UIAFlow) string {
	names := make([]string, 0, len(flows))
	for _, f := range flows {
		stages := make([]string, len(f.Stages))
		for i, s := range f.Stages {
			stages[i] = "(unnamed)"
			if isProtocolName(string(s)) {
				stages[i] = string(s)
			}
		}
		names = append(names, strings.Join(stages, "+"))
	}
	return strings.Join(names, ", ")
}

func isProtocolName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func isStatus(err error, code int) bool {
	var httpErr mautrix.HTTPError
	return errors.As(err, &httpErr) && httpErr.IsStatus(code)
}
