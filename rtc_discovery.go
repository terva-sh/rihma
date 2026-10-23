package rihma

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
)

var (
	// ErrRTCUnsupported reports that the server advertises none of the accepted
	// discovery dialects, or does not recognize the advertised endpoint.
	ErrRTCUnsupported = errors.New("rihma: MatrixRTC transport discovery dialect unsupported")
	// ErrRTCProtocol reports a discovery response that does not conform to the
	// negotiated dialect, including one written in the other dialect's schema.
	ErrRTCProtocol = errors.New("rihma: invalid MatrixRTC transport discovery response")
)

// RTCTransportDialect names a transport discovery wire contract, not merely a
// feature flag. See docs/matrixrtc.md for the proposal revisions each pins.
type RTCTransportDialect string

const (
	// RTCTransportsStable is MSC4143/MSC4195 as merged: `org.matrix.msc4143.stable`
	// in /versions, GET /_matrix/client/v1/rtc/transports, a required
	// `transports` list and `m.livekit` with a required WebSocket `url`.
	RTCTransportsStable RTCTransportDialect = "msc4143-stable"
	// RTCTransportsUnstable is the reference implementation's unstable schema,
	// which pinned mautrix-go decodes: `org.matrix.msc4143` in /versions, the
	// unstable endpoint, an `rtc_transports` list (absent when none are
	// configured) and `livekit` with `url` and/or legacy `livekit_service_url`.
	RTCTransportsUnstable RTCTransportDialect = "msc4143-unstable"
)

// RTCTransports is the result of one discovery. An empty Transports list is a
// genuine answer from the server, not a decoding failure.
type RTCTransports struct {
	Dialect    RTCTransportDialect
	Transports []RTCTransport // in the homeserver's order of preference
}

// RTCTransport is one advertised transport. Raw is a detached copy of the
// complete wire object, so unknown transports and fields survive. LiveKit is
// set only for a LiveKit transport the negotiated dialect defines.
type RTCTransport struct {
	Type    string
	Raw     json.RawMessage
	LiveKit *RTCLiveKitTransport
}

// RTCLiveKitTransport holds validated LiveKit endpoint metadata. rihma never
// contacts these URLs and never sends a homeserver credential to them.
type RTCLiveKitTransport struct {
	// URL is the SFU's absolute wss:// URL. It is empty only for a legacy
	// unstable `livekit` transport that gives ServiceURL alone.
	URL string
	// ServiceURL is the legacy unstable `livekit_service_url`, an absolute
	// https:// URL of a separate authorization service. Stable never sets it.
	ServiceURL string
}

const (
	rtcMaxResponse   = 64 << 10
	rtcMaxTransports = 64
	rtcMaxURL        = 2048
)

// DiscoverRTCTransports asks the homeserver which MatrixRTC transports it
// offers. accept lists the dialects the caller understands, most preferred
// first; with none it is stable, then unstable. Each call fetches /versions and
// uses the first accepted dialect it advertises. The embedded client's
// SpecVersions is neither read nor written, so concurrent calls do not race on
// it. The response is decoded only in that dialect and never reinterpreted.
//
// Errors:
//   - ErrRTCUnsupported: an unknown dialect, or no accepted dialect in
//     /versions (no discovery request is made), or a discovery endpoint
//     answering 404 or M_UNRECOGNIZED (wrapped with that HTTPError).
//   - ErrRTCProtocol: a successful /versions or discovery response that is
//     oversized, not JSON of the expected shape, or in the other dialect. Both
//     are parsed by exact key and JSON kind, so a null the protocol does not
//     allow fails here rather than reading as empty, false or "". No
//     HTTPError is wrapped, since its Request carries the access token.
//   - The context's error once ctx is done.
//   - Otherwise mautrix's error unchanged: an HTTPError for any other HTTP
//     status (including a /versions 404, which means a wrong homeserver URL
//     rather than no MatrixRTC) or a transport failure, and
//     mautrix.ErrFailedToRefreshToken when an OAuth refresh fails.
//
// It is safe to call concurrently with Sync. /versions and the discovery
// request are each sent once, whatever the client's retry settings or a retry
// count on ctx; mautrix's single re-send after refreshing a rejected, stale
// OAuth access token is the only exception. Neither request is logged, even by
// a logger carried on ctx. An OAuth refresh it triggers is mautrix's own
// request and logs as the client is configured, without its body.
func (c *Client) DiscoverRTCTransports(ctx context.Context, accept ...RTCTransportDialect) (*RTCTransports, error) {
	if len(accept) == 0 {
		accept = []RTCTransportDialect{RTCTransportsStable, RTCTransportsUnstable}
	}
	for _, dialect := range accept {
		if dialect != RTCTransportsStable && dialect != RTCTransportsUnstable {
			return nil, ErrRTCUnsupported
		}
	}
	// mautrix prefers a logger on the request context over FullRequest.Logger;
	// a disabled one there makes it fall back to the no-op logger below.
	quiet := zerolog.Nop()
	requestCtx := quiet.WithContext(ctx)
	once := mautrix.FullRequest{MaxAttempts: 1, Logger: &quiet, ResponseSizeLimit: rtcMaxResponse}
	capabilities, err := c.getVersions(requestCtx, once)
	switch {
	case err == nil:
	case ctx.Err() != nil:
		return nil, ctx.Err()
	// Protocol errors drop mautrix's HTTPError: its Request carries the
	// Authorization header, and the body is the server's, not the caller's.
	case oversizedSuccess(err):
		return nil, fmt.Errorf("%w: /versions response exceeds %d bytes", ErrRTCProtocol, rtcMaxResponse)
	default:
		// Includes a /versions 404: that is a wrong homeserver URL or not a
		// Matrix server, not a server without MatrixRTC.
		return nil, err
	}
	flags, ok := rtcAdvertised(capabilities)
	if !ok {
		return nil, fmt.Errorf("%w: /versions response is not a JSON object of the expected shape", ErrRTCProtocol)
	}
	var dialect RTCTransportDialect
	for _, candidate := range accept {
		if flags[rtcFlag(candidate)] {
			dialect = candidate
			break
		}
	}
	if dialect == "" {
		return nil, ErrRTCUnsupported
	}
	path := mautrix.ClientURLPath{"v1", "rtc", "transports"}
	if dialect == RTCTransportsUnstable {
		path = mautrix.ClientURLPath{"unstable", "org.matrix.msc4143", "rtc", "transports"}
	}
	once.Method, once.URL = http.MethodGet, c.BuildURL(path)
	raw, err := c.MakeFullRequest(requestCtx, once)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var refusal mautrix.HTTPError
	switch {
	case err == nil:
	case oversizedSuccess(err):
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrRTCProtocol, rtcMaxResponse)
	case errors.Is(err, mautrix.MUnrecognized) || errors.As(err, &refusal) && refusal.IsStatus(http.StatusNotFound):
		return nil, fmt.Errorf("%w: %w", ErrRTCUnsupported, err)
	default:
		return nil, err
	}
	return decodeRTCTransports(dialect, raw)
}

// rtcFlag names only the /versions flag. No released spec version includes
// MatrixRTC, so none is inferred, whatever a later SDK's feature table says.
func rtcFlag(dialect RTCTransportDialect) string {
	if dialect == RTCTransportsStable {
		return "org.matrix.msc4143.stable"
	}
	return "org.matrix.msc4143"
}

// rtcAdvertised parses /versions strictly, by exact key, rather than through
// mautrix's struct, whose decoding reads null as false and matches keys
// case-insensitively. `versions` is required: an array of strings.
// `unstable_features` is optional, but when present it must be an object whose
// values are all JSON booleans. A null for either, or within either, is
// malformed rather than absent or false.
func rtcAdvertised(raw []byte) (map[string]bool, bool) {
	body, ok := rtcObject(raw)
	if !ok {
		return nil, false
	}
	list, present := body["versions"]
	var versions []json.RawMessage
	if !present || rtcKind(list) != '[' || json.Unmarshal(list, &versions) != nil {
		return nil, false
	}
	for _, version := range versions {
		if _, ok := rtcString(version); !ok {
			return nil, false
		}
	}
	flags := make(map[string]bool)
	features, present := body["unstable_features"]
	if !present {
		return flags, true
	}
	values, ok := rtcObject(features)
	if !ok {
		return nil, false
	}
	for name, value := range values {
		switch string(bytes.TrimSpace(value)) {
		case "true":
			flags[name] = true
		case "false":
		default:
			return nil, false
		}
	}
	return flags, true
}

// rtcKind is the first byte of a JSON value: '{', '[', '"', 't', 'f', 'n' or a
// digit or '-'. It lets a caller refuse null before Go decodes it to a zero.
func rtcKind(raw json.RawMessage) byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return 0
	}
	return trimmed[0]
}

// rtcObject decodes a JSON object by exact key; null and other kinds fail.
func rtcObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if rtcKind(raw) != '{' || json.Unmarshal(raw, &fields) != nil {
		return nil, false
	}
	return fields, true
}

// rtcString decodes a JSON string; null and other kinds fail.
func rtcString(raw json.RawMessage) (string, bool) {
	var text string
	if rtcKind(raw) != '"' || json.Unmarshal(raw, &text) != nil {
		return "", false
	}
	return text, true
}

func decodeRTCTransports(dialect RTCTransportDialect, raw []byte) (*RTCTransports, error) {
	if len(raw) > rtcMaxResponse {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrRTCProtocol, rtcMaxResponse)
	}
	body, ok := rtcObject(raw)
	if !ok {
		return nil, fmt.Errorf("%w: response is not a JSON object", ErrRTCProtocol)
	}
	key, other := "transports", "rtc_transports"
	if dialect == RTCTransportsUnstable {
		key, other = other, key
	}
	list, present := body[key]
	if _, mismatch := body[other]; mismatch {
		return nil, fmt.Errorf("%w: response carries %q, which %s does not define", ErrRTCProtocol, other, dialect)
	}
	result := &RTCTransports{Dialect: dialect, Transports: []RTCTransport{}}
	if !present {
		if dialect == RTCTransportsUnstable {
			// The reference homeserver answers {} when nothing is configured.
			return result, nil
		}
		return nil, fmt.Errorf("%w: required %q is missing", ErrRTCProtocol, key)
	}
	var items []json.RawMessage
	if rtcKind(list) != '[' || json.Unmarshal(list, &items) != nil {
		return nil, fmt.Errorf("%w: %q is not an array", ErrRTCProtocol, key)
	}
	if len(items) > rtcMaxTransports {
		return nil, fmt.Errorf("%w: more than %d transports", ErrRTCProtocol, rtcMaxTransports)
	}
	for i, item := range items {
		transport, err := decodeRTCTransport(dialect, item)
		if err != nil {
			return nil, fmt.Errorf("%w: transport %d: %s", ErrRTCProtocol, i, err)
		}
		result.Transports = append(result.Transports, *transport)
	}
	return result, nil
}

func decodeRTCTransport(dialect RTCTransportDialect, item json.RawMessage) (*RTCTransport, error) {
	fields, ok := rtcObject(item)
	if !ok {
		return nil, errors.New("not an object")
	}
	kind, ok := rtcString(fields["type"])
	if !ok || !rtcIdentifier(kind) {
		return nil, errors.New("type is missing or not a namespaced identifier")
	}
	transport := &RTCTransport{Type: kind, Raw: append(json.RawMessage(nil), item...)}
	stableKind := kind == "m.livekit"
	legacyKind := dialect == RTCTransportsUnstable && kind == "livekit"
	if !stableKind && !legacyKind {
		return transport, nil
	}
	sfu, err := rtcEndpoint(fields, "url", "wss")
	if err != nil {
		return nil, err
	}
	live := &RTCLiveKitTransport{URL: sfu}
	if dialect == RTCTransportsUnstable {
		if live.ServiceURL, err = rtcEndpoint(fields, "livekit_service_url", "https"); err != nil {
			return nil, err
		}
	}
	if live.URL == "" && (stableKind || live.ServiceURL == "") {
		return nil, errors.New("LiveKit transport has no usable url")
	}
	transport.LiveKit = live
	return transport, nil
}

// rtcIdentifier applies the Matrix common namespaced identifier grammar.
func rtcIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 255 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("-_~.", r)) {
			return false
		}
	}
	return true
}

// rtcEndpoint returns the named field as an absolute URL with the given scheme
// and a host, without credentials or a fragment, or "" when it is absent.
// The error names only the field, never its value.
func rtcEndpoint(fields map[string]json.RawMessage, name, scheme string) (string, error) {
	value, present := fields[name]
	if !present {
		return "", nil
	}
	// Present but null is not absent: it fails here rather than reading as "".
	text, ok := rtcString(value)
	if !ok {
		return "", fmt.Errorf("%s is not a string", name)
	}
	parsed, err := url.Parse(text)
	if err != nil || len(text) > rtcMaxURL || parsed.Scheme != scheme || parsed.Opaque != "" || parsed.Hostname() == "" ||
		parsed.User != nil || strings.ContainsAny(text, "#\\ \t\r\n") {
		return "", fmt.Errorf("%s is not an absolute %s:// URL", name, scheme)
	}
	return text, nil
}
