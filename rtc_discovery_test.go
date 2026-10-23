package rihma

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
)

const (
	rtcStablePath   = "/_matrix/client/v1/rtc/transports"
	rtcUnstablePath = "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports"
)

var (
	rtcStableFlag   = map[string]bool{"org.matrix.msc4143.stable": true}
	rtcUnstableFlag = map[string]bool{"org.matrix.msc4143": true}
)

type rtcFixture struct {
	client             *Client
	versions, requests atomic.Int32
	path               atomic.Value
	// versionsFailures makes that many /versions requests answer 502 first.
	versionsFailures atomic.Int32
	// versionsRespond, when set, answers /versions instead of the flags.
	versionsRespond atomic.Pointer[func(http.ResponseWriter, *http.Request)]
}

// newRTCFixture serves /versions with flags and every other request with
// respond, recording the discovery path. Only local fixtures are contacted.
func newRTCFixture(t *testing.T, flags map[string]bool, respond func(w http.ResponseWriter, r *http.Request)) *rtcFixture {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal("fixture setup failed")
	}
	token := hex.EncodeToString(secret)
	f := &rtcFixture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_matrix/client/versions" {
			f.versions.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if f.versionsFailures.Add(-1) >= 0 {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"fixture outage"}`))
				return
			}
			if respond := f.versionsRespond.Load(); respond != nil {
				(*respond)(w, r)
				return
			}
			if flags == nil {
				flags = map[string]bool{} // a nil map would encode as null, which is malformed
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"versions": []string{"v1.19"}, "unstable_features": flags})
			return
		}
		f.requests.Add(1)
		f.path.Store(r.URL.Path)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		respond(w, r)
	}))
	t.Cleanup(server.Close)
	cli, err := mautrix.NewClient(server.URL, "", token)
	if err != nil {
		t.Fatal("client preparation failed")
	}
	cli.Log = zerolog.Nop()
	f.client = &Client{Client: cli}
	return f
}

func rtcBody(body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func rtcContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// Each dialect answers in its own schema, so a wrong choice cannot pass.
func rtcDialectBodies(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case rtcStablePath:
		rtcBody(`{"transports":[{"type":"m.livekit","url":"wss://sfu.example.org"}]}`)(w, r)
	case rtcUnstablePath:
		rtcBody(`{"rtc_transports":[{"type":"livekit","livekit_service_url":"https://rtc.example.org"}]}`)(w, r)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func TestRTCDiscoveryNegotiation(t *testing.T) {
	both := map[string]bool{"org.matrix.msc4143": true, "org.matrix.msc4143.stable": true}
	for _, tc := range []struct {
		name   string
		flags  map[string]bool
		accept []RTCTransportDialect
		want   RTCTransportDialect // "" means unsupported without a request
	}{
		{"unadvertised", nil, nil, ""},
		{"stable", rtcStableFlag, nil, RTCTransportsStable},
		{"unstable", rtcUnstableFlag, nil, RTCTransportsUnstable},
		{"both-prefers-stable", both, nil, RTCTransportsStable},
		{"caller-prefers-unstable", both, []RTCTransportDialect{RTCTransportsUnstable, RTCTransportsStable}, RTCTransportsUnstable},
		{"caller-accepts-only-unstable", rtcStableFlag, []RTCTransportDialect{RTCTransportsUnstable}, ""},
		{"caller-accepts-only-stable", rtcUnstableFlag, []RTCTransportDialect{RTCTransportsStable}, ""},
		{"unknown-dialect", both, []RTCTransportDialect{"org.example.dialect"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRTCFixture(t, tc.flags, rtcDialectBodies)
			result, err := f.client.DiscoverRTCTransports(rtcContext(t), tc.accept...)
			if tc.want == "" {
				if !errors.Is(err, ErrRTCUnsupported) || result != nil || f.requests.Load() != 0 {
					t.Fatal("unsupported dialect issued a discovery request")
				}
				return
			}
			if err != nil || result == nil || result.Dialect != tc.want || len(result.Transports) != 1 || f.requests.Load() != 1 || f.versions.Load() != 1 {
				t.Fatalf("negotiation failed: %v", err)
			}
			live := result.Transports[0].LiveKit
			if tc.want == RTCTransportsStable && (f.path.Load() != rtcStablePath || result.Transports[0].Type != "m.livekit" || live == nil || live.URL != "wss://sfu.example.org" || live.ServiceURL != "") {
				t.Fatal("stable transport metadata changed")
			}
			if tc.want == RTCTransportsUnstable && (f.path.Load() != rtcUnstablePath || result.Transports[0].Type != "livekit" || live == nil || live.URL != "" || live.ServiceURL != "https://rtc.example.org") {
				t.Fatal("unstable transport metadata changed")
			}
		})
	}
}

// Concurrent discoveries on a cold client each fetch /versions into their own
// value. The embedded client's unsynchronized SpecVersions stays untouched, so
// there is no shared read/initialize to race on.
func TestRTCDiscoveryConcurrentColdCache(t *testing.T) {
	const callers = 32
	f := newRTCFixture(t, map[string]bool{"org.matrix.msc4143": true, "org.matrix.msc4143.stable": true}, rtcDialectBodies)
	ctx := rtcContext(t)
	start := make(chan struct{})
	errs := make(chan error, callers)
	for i := range callers {
		accept := []RTCTransportDialect{RTCTransportsStable, RTCTransportsUnstable}
		if i%2 == 1 {
			accept = []RTCTransportDialect{RTCTransportsUnstable}
		}
		go func() {
			<-start
			result, err := f.client.DiscoverRTCTransports(ctx, accept...)
			if err == nil && (result.Dialect != accept[0] || len(result.Transports) != 1) {
				err = errors.New("wrong dialect negotiated")
			}
			errs <- err
		}()
	}
	close(start)
	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent discovery failed: %v", err)
		}
	}
	if f.client.SpecVersions != nil || f.versions.Load() != callers || f.requests.Load() != callers {
		t.Fatal("discovery touched the shared versions cache")
	}
}

// rtcWrite answers with status and body, declaring the length or streaming it.
func rtcWrite(status int, body string, declared bool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if declared {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
		w.WriteHeader(status)
		for i := 0; i < len(body); i += 4096 {
			_, _ = w.Write([]byte(body[i:min(i+4096, len(body))]))
			if !declared {
				w.(http.Flusher).Flush()
			}
		}
	}
}

// The /versions response follows the same error contract as discovery: a bad
// successful response is a protocol error, an HTTP refusal stays an HTTPError,
// and no discovery request follows either.
func TestRTCDiscoveryCapabilityResponses(t *testing.T) {
	const marker = "fixture-marker"
	oversized := `{"unstable_features":{"org.matrix.msc4143.stable":true},"org.example.padding":"` + strings.Repeat("x", rtcMaxResponse) + `"}`
	hugeError := `{"errcode":"M_UNKNOWN","error":"` + marker + strings.Repeat("x", mautrix.ErrorResponseSizeLimit) + `"}`
	for _, tc := range []struct {
		name    string
		respond func(http.ResponseWriter, *http.Request)
		want    error // ErrRTCProtocol, ErrRTCUnsupported, or nil for an HTTPError with status
		status  int
	}{
		{"not-json", rtcWrite(200, marker, false), ErrRTCProtocol, 0},
		{"empty", rtcWrite(200, ``, false), ErrRTCProtocol, 0},
		{"null", rtcWrite(200, `null`, false), ErrRTCProtocol, 0},
		{"array", rtcWrite(200, `[]`, false), ErrRTCProtocol, 0},
		{"string", rtcWrite(200, `"`+marker+`"`, false), ErrRTCProtocol, 0},
		{"trailing-data", rtcWrite(200, `{"versions":["v1.19"],"unstable_features":{"org.matrix.msc4143.stable":true}} `+marker, false), ErrRTCProtocol, 0},
		// versions is required: an array of strings. null is not absent.
		{"versions-missing", rtcWrite(200, `{"unstable_features":{"org.matrix.msc4143.stable":true}}`, false), ErrRTCProtocol, 0},
		{"versions-null", rtcWrite(200, `{"versions":null,"unstable_features":{"org.matrix.msc4143.stable":true}}`, false), ErrRTCProtocol, 0},
		{"versions-object", rtcWrite(200, `{"versions":{},"unstable_features":{"org.matrix.msc4143.stable":true}}`, false), ErrRTCProtocol, 0},
		{"versions-string", rtcWrite(200, `{"versions":"v1.19","unstable_features":{"org.matrix.msc4143.stable":true}}`, false), ErrRTCProtocol, 0},
		{"version-null", rtcWrite(200, `{"versions":["v1.19",null],"unstable_features":{"org.matrix.msc4143.stable":true}}`, false), ErrRTCProtocol, 0},
		{"version-number", rtcWrite(200, `{"versions":[1.19],"unstable_features":{"org.matrix.msc4143.stable":true}}`, false), ErrRTCProtocol, 0},
		// unstable_features is optional; when present, an object of booleans.
		{"features-null", rtcWrite(200, `{"versions":["v1.19"],"unstable_features":null}`, false), ErrRTCProtocol, 0},
		{"features-array", rtcWrite(200, `{"versions":["v1.19"],"unstable_features":["org.matrix.msc4143.stable"]}`, false), ErrRTCProtocol, 0},
		{"features-string", rtcWrite(200, `{"versions":["v1.19"],"unstable_features":"`+marker+`"}`, false), ErrRTCProtocol, 0},
		{"flag-null", rtcWrite(200, `{"versions":["v1.19"],"unstable_features":{"org.matrix.msc4143.stable":null}}`, false), ErrRTCProtocol, 0},
		{"flag-string", rtcWrite(200, `{"versions":["v1.19"],"unstable_features":{"org.matrix.msc4143.stable":"`+marker+`"}}`, false), ErrRTCProtocol, 0},
		{"flag-number", rtcWrite(200, `{"versions":["v1.19"],"unstable_features":{"org.matrix.msc4143.stable":1}}`, false), ErrRTCProtocol, 0},
		// A malformed flag fails even when it is not one discovery looks at.
		{"other-flag-null", rtcWrite(200, `{"versions":["v1.19"],"unstable_features":{"org.matrix.msc4143.stable":true,"org.example.flag":null}}`, false), ErrRTCProtocol, 0},
		{"versions-only", rtcWrite(200, `{"versions":["v1.19"]}`, false), ErrRTCUnsupported, 0},
		{"no-features", rtcWrite(200, `{"versions":["v1.19"],"unstable_features":{}}`, false), ErrRTCUnsupported, 0},
		{"flag-false", rtcWrite(200, `{"versions":["v1.19"],"unstable_features":{"org.matrix.msc4143.stable":false}}`, false), ErrRTCUnsupported, 0},
		// Keys match exactly; mautrix's struct decoding would accept this one.
		{"features-key-case", rtcWrite(200, `{"versions":["v1.19"],"UNSTABLE_FEATURES":{"org.matrix.msc4143.stable":true}}`, false), ErrRTCUnsupported, 0},
		{"declared-oversize", rtcWrite(200, oversized, true), ErrRTCProtocol, 0},
		{"streamed-oversize", rtcWrite(200, oversized, false), ErrRTCProtocol, 0},
		{"empty-object", rtcWrite(200, `{}`, false), ErrRTCProtocol, 0},
		{"not-found", rtcWrite(404, `{"errcode":"M_UNRECOGNIZED","error":"`+marker+`"}`, false), nil, 404},
		{"not-found-plain", rtcWrite(404, marker, false), nil, 404},
		{"oversized-error-body", rtcWrite(500, hugeError, false), nil, 500},
		{"declared-oversized-error-body", rtcWrite(500, hugeError, true), nil, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRTCFixture(t, rtcStableFlag, rtcDialectBodies)
			f.versionsRespond.Store(&tc.respond)
			result, err := f.client.DiscoverRTCTransports(rtcContext(t))
			if result != nil || err == nil || f.versions.Load() != 1 || f.requests.Load() != 0 {
				t.Fatalf("capability failure was not refused before discovery: %v", err)
			}
			var refusal mautrix.HTTPError
			if tc.want != nil {
				if !errors.Is(err, tc.want) || errors.As(err, &refusal) || strings.Contains(err.Error(), marker) {
					t.Fatalf("capability response misclassified: %v", err)
				}
				return
			}
			if !errors.As(err, &refusal) || !refusal.IsStatus(tc.status) || errors.Is(err, ErrRTCProtocol) || errors.Is(err, ErrRTCUnsupported) {
				t.Fatalf("capability refusal not preserved: %v", err)
			}
		})
	}
}

// Sliding Sync passes the same helper a zero request. A malformed /versions is
// not retried there and ends as ErrSlidingUnsupported, as it did through
// Client.Versions.
func TestFetchVersionsMalformedKeepsSlidingOutcome(t *testing.T) {
	f := newRTCFixture(t, rtcStableFlag, rtcDialectBodies)
	respond := rtcWrite(200, `null`, false)
	f.versionsRespond.Store(&respond)
	_, err := f.client.fetchVersions(rtcContext(t), mautrix.FullRequest{})
	if _, retry := startupRetryDelay(err, 1); !errors.Is(err, errVersionsMalformed) || retry {
		t.Fatalf("malformed versions classified differently: %v", err)
	}
}

// rtcRetryingClient makes every default request retry quickly, by client
// setting and by a retry count on the context.
func rtcRetryingClient(t *testing.T, f *rtcFixture) context.Context {
	f.client.DefaultHTTPRetries = 3
	f.client.DefaultHTTPBackoff = time.Millisecond
	return mautrix.WithMaxRetries(rtcContext(t), 3)
}

// Discovery makes each of its requests once, even when the client or the
// context asks for retries and the failure is one mautrix would retry.
func TestRTCDiscoverySingleAttempt(t *testing.T) {
	t.Run("versions", func(t *testing.T) {
		f := newRTCFixture(t, rtcStableFlag, rtcDialectBodies)
		f.versionsFailures.Store(1 << 20)
		result, err := f.client.DiscoverRTCTransports(rtcRetryingClient(t, f))
		var refusal mautrix.HTTPError
		if result != nil || !errors.As(err, &refusal) || !refusal.IsStatus(http.StatusBadGateway) || f.versions.Load() != 1 || f.requests.Load() != 0 {
			t.Fatalf("capability request was retried or misreported: %d attempts, %v", f.versions.Load(), err)
		}
	})
	t.Run("transports", func(t *testing.T) {
		f := newRTCFixture(t, rtcStableFlag, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		result, err := f.client.DiscoverRTCTransports(rtcRetryingClient(t, f))
		var refusal mautrix.HTTPError
		if result != nil || !errors.As(err, &refusal) || !refusal.IsStatus(http.StatusServiceUnavailable) || f.versions.Load() != 1 || f.requests.Load() != 1 {
			t.Fatalf("discovery request was retried or misreported: %d attempts, %v", f.requests.Load(), err)
		}
	})
}

// Neither the client's logger nor a logger carried on the context records
// discovery, on success or failure. Client.Versions on the same setup does log,
// so the capture would see a leak.
func TestRTCDiscoveryLogsNothing(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(strconv.FormatBool(fail), func(t *testing.T) {
			f := newRTCFixture(t, rtcStableFlag, rtcDialectBodies)
			var clientLog, contextLog bytes.Buffer
			f.client.Log = zerolog.New(&clientLog).Level(zerolog.TraceLevel)
			ctx := zerolog.New(&contextLog).Level(zerolog.TraceLevel).WithContext(rtcContext(t))
			if fail {
				f.versionsFailures.Store(1)
			}
			if _, err := f.client.DiscoverRTCTransports(ctx); (err != nil) != fail {
				t.Fatalf("unexpected discovery outcome: %v", err)
			}
			if clientLog.Len() != 0 || contextLog.Len() != 0 {
				t.Fatal("discovery was logged")
			}
			if _, err := f.client.Versions(ctx); err != nil || contextLog.Len() == 0 {
				t.Fatal("log capture is not effective")
			}
		})
	}
}

// Sliding Sync's capability fetch passes a zero request, which keeps what
// Client.Versions did: the client's retries and its logger.
func TestFetchVersionsZeroRequestKeepsClientDefaults(t *testing.T) {
	f := newRTCFixture(t, rtcStableFlag, rtcDialectBodies)
	var clientLog bytes.Buffer
	f.client.Log = zerolog.New(&clientLog).Level(zerolog.DebugLevel)
	f.client.DefaultHTTPRetries = 2
	f.client.DefaultHTTPBackoff = time.Millisecond
	f.versionsFailures.Store(2)
	versions, err := f.client.fetchVersions(rtcContext(t), mautrix.FullRequest{})
	if err != nil || !versions.UnstableFeatures[rtcFlag(RTCTransportsStable)] || f.versions.Load() != 3 || clientLog.Len() == 0 || f.client.SpecVersions != nil {
		t.Fatalf("zero request changed the client defaults: %d attempts, %v", f.versions.Load(), err)
	}
}

// A cached SpecVersions, however stale, is neither consulted nor replaced.
func TestRTCDiscoveryIgnoresSharedVersions(t *testing.T) {
	f := newRTCFixture(t, rtcUnstableFlag, rtcDialectBodies)
	stale := &mautrix.RespVersions{UnstableFeatures: map[string]bool{"org.matrix.msc4143.stable": true}}
	f.client.SpecVersions = stale
	result, err := f.client.DiscoverRTCTransports(rtcContext(t))
	if err != nil || result.Dialect != RTCTransportsUnstable || f.client.SpecVersions != stale || len(stale.UnstableFeatures) != 1 || f.versions.Load() != 1 {
		t.Fatalf("discovery used or changed the shared versions cache: %v", err)
	}
}

func TestRTCDiscoverySchemas(t *testing.T) {
	future := `{"type":"org.example.future","endpoint":{"region":"eu"},"url":7}`
	extended := `{"type":"m.livekit","url":"wss://sfu.example.org/rtc","org.example.weight":3}`
	legacyInStable := `{"type":"livekit","livekit_service_url":"https://rtc.example.org"}`
	unknownNull := `{"type":"org.example.future","endpoint":null,"url":null}`
	stableServiceNull := `{"type":"m.livekit","url":"wss://sfu.example.org","livekit_service_url":null}`
	for _, tc := range []struct {
		name    string
		dialect RTCTransportDialect
		body    string
		want    []string // raw transports; nil means ErrRTCProtocol
	}{
		{"stable-empty", RTCTransportsStable, `{"transports":[]}`, []string{}},
		{"stable-requires-list", RTCTransportsStable, `{}`, nil},
		{"stable-null-list", RTCTransportsStable, `{"transports":null}`, nil},
		{"stable-object-list", RTCTransportsStable, `{"transports":{}}`, nil},
		// The pinned SDK decodes these as an empty result; both directions are refused.
		{"stable-endpoint-unstable-schema", RTCTransportsStable, `{"rtc_transports":[{"type":"livekit","livekit_service_url":"https://rtc.example.org"}]}`, nil},
		{"unstable-endpoint-stable-schema", RTCTransportsUnstable, `{"transports":[{"type":"m.livekit","url":"wss://sfu.example.org"}]}`, nil},
		{"stable-both-lists", RTCTransportsStable, `{"transports":[],"rtc_transports":[]}`, nil},
		{"unstable-both-lists", RTCTransportsUnstable, `{"transports":[],"rtc_transports":[]}`, nil},
		{"unstable-unconfigured", RTCTransportsUnstable, `{}`, []string{}},
		{"unstable-empty", RTCTransportsUnstable, `{"rtc_transports":[]}`, []string{}},
		{"unstable-null-list", RTCTransportsUnstable, `{"rtc_transports":null}`, nil},
		{"null-body", RTCTransportsStable, `null`, nil},
		{"array-body", RTCTransportsStable, `[]`, nil},
		{"not-json", RTCTransportsStable, `{"transports":[`, nil},
		{"empty-body", RTCTransportsStable, ``, nil},
		{"transport-not-object", RTCTransportsStable, `{"transports":[1]}`, nil},
		{"transport-null", RTCTransportsStable, `{"transports":[null]}`, nil},
		{"type-missing", RTCTransportsStable, `{"transports":[{"url":"wss://sfu.example.org"}]}`, nil},
		{"type-not-string", RTCTransportsStable, `{"transports":[{"type":7}]}`, nil},
		{"type-null", RTCTransportsStable, `{"transports":[{"type":null}]}`, nil},
		{"type-array", RTCTransportsStable, `{"transports":[{"type":["m.livekit"]}]}`, nil},
		{"stable-other-list-null", RTCTransportsStable, `{"transports":[],"rtc_transports":null}`, nil},
		{"unstable-other-list-null", RTCTransportsUnstable, `{"transports":null}`, nil},
		{"stable-url-array", RTCTransportsStable, `{"transports":[{"type":"m.livekit","url":["wss://sfu.example.org"]}]}`, nil},
		{"stable-url-object", RTCTransportsStable, `{"transports":[{"type":"m.livekit","url":{}}]}`, nil},
		// A null endpoint is present, not absent, so it cannot fall back to the other one.
		{"unstable-url-null", RTCTransportsUnstable, `{"rtc_transports":[{"type":"livekit","url":null,"livekit_service_url":"https://rtc.example.org"}]}`, nil},
		{"unstable-service-null", RTCTransportsUnstable, `{"rtc_transports":[{"type":"livekit","url":"wss://sfu.example.org","livekit_service_url":null}]}`, nil},
		{"unstable-service-number", RTCTransportsUnstable, `{"rtc_transports":[{"type":"livekit","url":"wss://sfu.example.org","livekit_service_url":7}]}`, nil},
		{"unstable-m-livekit-url-null", RTCTransportsUnstable, `{"rtc_transports":[{"type":"m.livekit","url":null}]}`, nil},
		// Fields a dialect does not define are opaque and kept raw, null included.
		{"unknown-null-fields", RTCTransportsStable, `{"transports":[` + unknownNull + `]}`, []string{unknownNull}},
		{"stable-undefined-service-null", RTCTransportsStable, `{"transports":[` + stableServiceNull + `]}`, []string{stableServiceNull}},
		{"type-empty", RTCTransportsStable, `{"transports":[{"type":""}]}`, nil},
		{"type-uppercase", RTCTransportsStable, `{"transports":[{"type":"M.LiveKit","url":"wss://sfu.example.org"}]}`, nil},
		{"type-space", RTCTransportsStable, `{"transports":[{"type":"org.example future"}]}`, nil},
		{"type-overlong", RTCTransportsStable, `{"transports":[{"type":"org.` + strings.Repeat("x", 252) + `"}]}`, nil},
		{"unknown-transport", RTCTransportsStable, `{"transports":[` + future + `]}`, []string{future}},
		{"unknown-fields", RTCTransportsStable, `{"transports":[` + extended + `]}`, []string{extended}},
		{"legacy-type-is-unknown-in-stable", RTCTransportsStable, `{"transports":[` + legacyInStable + `]}`, []string{legacyInStable}},
		{"unknown-top-level", RTCTransportsStable, `{"transports":[` + future + `],"org.example.hint":true}`, []string{future}},
		{"ordered", RTCTransportsUnstable, `{"rtc_transports":[` + future + `,` + extended + `]}`, []string{future, extended}},
		{"stable-url-missing", RTCTransportsStable, `{"transports":[{"type":"m.livekit"}]}`, nil},
		{"stable-url-null", RTCTransportsStable, `{"transports":[{"type":"m.livekit","url":null}]}`, nil},
		{"stable-url-number", RTCTransportsStable, `{"transports":[{"type":"m.livekit","url":7}]}`, nil},
		{"stable-service-only", RTCTransportsStable, `{"transports":[{"type":"m.livekit","livekit_service_url":"https://rtc.example.org"}]}`, nil},
		{"unstable-neither-url", RTCTransportsUnstable, `{"rtc_transports":[{"type":"livekit"}]}`, nil},
		{"unstable-m-livekit-service-only", RTCTransportsUnstable, `{"rtc_transports":[{"type":"m.livekit","livekit_service_url":"https://rtc.example.org"}]}`, nil},
		{"unstable-service-http", RTCTransportsUnstable, `{"rtc_transports":[{"type":"livekit","livekit_service_url":"http://rtc.example.org"}]}`, nil},
		{"unstable-service-relative", RTCTransportsUnstable, `{"rtc_transports":[{"type":"livekit","livekit_service_url":"/livekit/jwt"}]}`, nil},
		{"unstable-service-bad-with-good-url", RTCTransportsUnstable, `{"rtc_transports":[{"type":"livekit","url":"wss://sfu.example.org","livekit_service_url":"ftp://rtc.example.org"}]}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := rtcStableFlag
			if tc.dialect == RTCTransportsUnstable {
				flags = rtcUnstableFlag
			}
			f := newRTCFixture(t, flags, rtcBody(tc.body))
			result, err := f.client.DiscoverRTCTransports(rtcContext(t), tc.dialect)
			if tc.want == nil {
				if !errors.Is(err, ErrRTCProtocol) || result != nil {
					t.Fatalf("malformed response accepted: %v", err)
				}
				return
			}
			if err != nil || result == nil || result.Dialect != tc.dialect || len(result.Transports) != len(tc.want) {
				t.Fatalf("discovery failed: %v", err)
			}
			for i, raw := range tc.want {
				if string(result.Transports[i].Raw) != raw {
					t.Fatal("raw transport not preserved")
				}
			}
		})
	}
}

func TestRTCDiscoveryEndpointMetadata(t *testing.T) {
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"wss://sfu.example.org", true},
		{"wss://sfu.example.org:7880/livekit/sfu?region=eu", true},
		{"wss://[2001:db8::1]:443", true},
		{"https://sfu.example.org", false},
		{"ws://sfu.example.org", false},
		{"http://sfu.example.org", false},
		{"/livekit/sfu", false},
		{"sfu.example.org", false},
		{"//sfu.example.org", false},
		{"wss:///livekit", false},
		{"wss:sfu.example.org", false},
		{"wss://user:pass@sfu.example.org", false},
		{"wss://sfu.example.org/#frag", false},
		{"wss://sfu.example.org\\path", false},
		{"wss://sfu example.org", false},
		{"wss://sfu.example.org/" + strings.Repeat("x", rtcMaxURL), false},
		{"", false},
	} {
		t.Run(tc.url, func(t *testing.T) {
			item, _ := json.Marshal(map[string]string{"type": "m.livekit", "url": tc.url})
			f := newRTCFixture(t, rtcStableFlag, rtcBody(`{"transports":[`+string(item)+`]}`))
			result, err := f.client.DiscoverRTCTransports(rtcContext(t))
			if !tc.ok {
				if !errors.Is(err, ErrRTCProtocol) || result != nil {
					t.Fatal("malformed endpoint accepted")
				}
				if strings.Contains(err.Error(), tc.url) && tc.url != "" {
					t.Fatal("error repeats the endpoint value")
				}
				return
			}
			if err != nil || result.Transports[0].LiveKit == nil || result.Transports[0].LiveKit.URL != tc.url {
				t.Fatalf("valid endpoint refused: %v", err)
			}
		})
	}
}

func TestRTCDiscoveryBounds(t *testing.T) {
	many := strings.TrimSuffix(strings.Repeat(`{"type":"org.example.future"},`, rtcMaxTransports+1), ",")
	limit := strings.TrimSuffix(strings.Repeat(`{"type":"org.example.future"},`, rtcMaxTransports), ",")
	padding := `{"transports":[],"org.example.padding":"` + strings.Repeat("x", rtcMaxResponse) + `"}`
	for _, tc := range []struct {
		name    string
		respond func(http.ResponseWriter, *http.Request)
		count   int // -1 means ErrRTCProtocol
	}{
		{"transport-limit", rtcBody(`{"transports":[` + limit + `]}`), rtcMaxTransports},
		{"too-many-transports", rtcBody(`{"transports":[` + many + `]}`), -1},
		{"declared-oversize", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(padding)))
			rtcBody(padding)(w, r)
		}, -1},
		{"streamed-oversize", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			for i := 0; i < len(padding); i += 4096 {
				_, _ = w.Write([]byte(padding[i:min(i+4096, len(padding))]))
				w.(http.Flusher).Flush()
			}
		}, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRTCFixture(t, rtcStableFlag, tc.respond)
			result, err := f.client.DiscoverRTCTransports(rtcContext(t))
			if tc.count < 0 {
				if !errors.Is(err, ErrRTCProtocol) || result != nil {
					t.Fatalf("bound not enforced: %v", err)
				}
				return
			}
			if err != nil || len(result.Transports) != tc.count {
				t.Fatalf("discovery within bounds failed: %v", err)
			}
		})
	}
}

func TestRTCDiscoveryMatrixErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body  string
		status      int
		unsupported bool
		want        error
	}{
		{"forbidden", `{"errcode":"M_FORBIDDEN","error":"fixture refusal"}`, 403, false, mautrix.MForbidden},
		{"unrecognized", `{"errcode":"M_UNRECOGNIZED","error":"fixture refusal"}`, 404, true, mautrix.MUnrecognized},
		{"unrecognized-method", `{"errcode":"M_UNRECOGNIZED","error":"fixture refusal"}`, 405, true, mautrix.MUnrecognized},
		{"not-found-without-errcode", `not json`, 404, true, nil},
		{"rate-limited", `{"errcode":"M_LIMIT_EXCEEDED","error":"fixture refusal"}`, 429, false, mautrix.MLimitExceeded},
		// An error body over mautrix's error limit keeps its status: it is
		// not an oversized discovery response.
		{"not-found-oversized-body", strings.Repeat("x", mautrix.ErrorResponseSizeLimit+1), 404, true, nil},
		{"forbidden-oversized-body", strings.Repeat("x", mautrix.ErrorResponseSizeLimit+1), 403, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRTCFixture(t, rtcStableFlag, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			result, err := f.client.DiscoverRTCTransports(rtcContext(t))
			var refusal mautrix.HTTPError
			if result != nil || !errors.As(err, &refusal) || !refusal.IsStatus(tc.status) || errors.Is(err, ErrRTCUnsupported) != tc.unsupported || errors.Is(err, ErrRTCProtocol) || f.requests.Load() != 1 {
				t.Fatalf("Matrix refusal not preserved: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatal("Matrix error code not preserved")
			}
		})
	}
}

// Discovered endpoints are metadata only: no request reaches them.
func TestRTCDiscoveryNeverContactsDiscoveredURLs(t *testing.T) {
	var contacted atomic.Int32
	sfu := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { contacted.Add(1) }))
	defer sfu.Close()
	host := strings.TrimPrefix(sfu.URL, "https://")
	body, _ := json.Marshal(map[string]any{"rtc_transports": []map[string]string{{"type": "livekit", "url": "wss://" + host, "livekit_service_url": sfu.URL}}})
	f := newRTCFixture(t, rtcUnstableFlag, rtcBody(string(body)))
	result, err := f.client.DiscoverRTCTransports(rtcContext(t))
	if err != nil || len(result.Transports) != 1 || result.Transports[0].LiveKit == nil || result.Transports[0].LiveKit.ServiceURL != sfu.URL {
		t.Fatalf("discovery failed: %v", err)
	}
	if contacted.Load() != 0 {
		t.Fatal("a discovered URL was contacted")
	}
}

func TestRTCDiscoveryCancellation(t *testing.T) {
	entered, shutdown := make(chan struct{}), make(chan struct{})
	f := newRTCFixture(t, rtcStableFlag, func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
		case <-shutdown:
		}
	})
	defer close(shutdown)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := f.client.DiscoverRTCTransports(ctx); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not arrive")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrRTCProtocol) || errors.Is(err, ErrRTCUnsupported) {
			t.Fatal("cancellation not preserved")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not stop")
	}
}

func TestRTCDiscoveryCancelledBeforeVersions(t *testing.T) {
	f := newRTCFixture(t, rtcStableFlag, rtcDialectBodies)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.client.DiscoverRTCTransports(ctx); !errors.Is(err, context.Canceled) || f.requests.Load() != 0 {
		t.Fatal("cancellation not preserved")
	}
}

// The pinned SDK still decodes the merged schema as an empty result. This is
// why rihma owns discovery; a dependency upgrade that changes it is noticed.
func TestRTCDiscoveryPinnedSDKSchema(t *testing.T) {
	f := newRTCFixture(t, rtcStableFlag, rtcDialectBodies)
	ctx := rtcContext(t)
	if _, err := f.client.Versions(ctx); err != nil {
		t.Fatal("capability discovery failed")
	}
	result, err := f.client.Client.RTCTransports(ctx)
	if err != nil || result == nil || len(result.RTCTransports) != 0 || f.path.Load() != rtcStablePath {
		t.Fatal("pinned SDK discovery characterization changed; revisit docs/matrixrtc.md")
	}
}
