package rihma

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"
)

// Only synthetic payloads are used. Never print captured logs on failure.
func TestRequestLogsOmitPayloads(t *testing.T) {
	for _, level := range []zerolog.Level{zerolog.DebugLevel, zerolog.TraceLevel} {
		t.Run(level.String(), func(t *testing.T) {
			h := newTestHS(t)
			opts := testOptions(t, h, t.TempDir())
			const password = "synthetic-login-password-private"
			const message = "synthetic-message-private"
			opts.Login.Password = password
			var logs bytes.Buffer
			opts.Logger = zerolog.New(&logs).Level(level)
			var mu sync.Mutex
			var bodies []string
			attempts := 0
			h.ms.Router.HandleFunc("PUT /_matrix/client/v3/rooms/{roomID}/send/{eventType}/{txnID}", func(w http.ResponseWriter, r *http.Request) {
				var payload struct {
					Body string `json:"body"`
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error("request body was not valid JSON")
					w.WriteHeader(400)
					return
				}
				mu.Lock()
				bodies = append(bodies, payload.Body)
				attempts++
				n := attempts
				mu.Unlock()
				if n == 1 {
					w.WriteHeader(502)
					w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"synthetic failure"}`))
					return
				}
				w.Write([]byte(`{"event_id":"$sent"}`))
			})
			ctx := context.Background()
			c, err := Open(ctx, opts)
			if err != nil {
				t.Fatal("mock Open failed")
			}
			defer c.Close()
			// mautrix's own request retry is independent of the library sync loop.
			c.DefaultHTTPRetries = 1
			c.DefaultHTTPBackoff = 1
			if _, err := c.SendText(ctx, id.RoomID("!plain:localhost"), message); err != nil {
				t.Fatal("mock send failed")
			}
			mu.Lock()
			valid := len(bodies) == 2 && bodies[0] == message && bodies[1] == message
			mu.Unlock()
			if !valid {
				t.Fatal("outbound body changed or retry did not reach the server")
			}
			data := logs.Bytes()
			for _, payload := range []string{password, message} {
				if bytes.Contains(data, []byte(payload)) {
					t.Fatal("request payload reached the logger")
				}
			}
			if !bytes.Contains(data, []byte("req_id")) || !bytes.Contains(data, []byte("status_code")) || !bytes.Contains(data, []byte("response_length")) {
				t.Fatal("safe request metadata was lost")
			}
		})
	}
}

func TestRequestLogsIgnoreSensitiveOverride(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("test binary unavailable")
	}
	cmd := exec.Command(executable, "-test.run=^TestRequestLogsOmitPayloads$", "-test.timeout=20s")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "MAUTRIX_LOG_SENSITIVE_CONTENT=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "MAUTRIX_LOG_SENSITIVE_CONTENT=yes")
	if output, err := cmd.CombinedOutput(); err != nil {
		// Child failures contain only fixed assertions, never captured log content.
		t.Fatalf("sensitive override regression failed: %s", output)
	}
}
