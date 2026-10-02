//go:build e2e

// Package e2e is the connector's live suite: a fake terva host that
// spawns terva-rihma through run.sh, as terva does, and speaks connproto
// over its stdio, with a rihma client playing the human on the throwaway
// Synapse from `just synapse`. Scenarios follow terva-conn-matrix's
// tests/live_synapse.rs. It never touches a real account.
package e2e

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"terva.sh/terva/packages/agent/connproto"
)

func homeserver(t *testing.T) string {
	hs := os.Getenv("RIHMA_E2E_HS")
	if hs == "" {
		t.Skip("RIHMA_E2E_HS not set; run `just e2e`")
	}
	return hs
}

func tag() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func runSh(t *testing.T) string {
	p, err := filepath.Abs(filepath.Join("..", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func register(t *testing.T, ctx context.Context, hs, localpart, password string) {
	t.Helper()
	cli, err := mautrix.NewClient(hs, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.RegisterDummy(ctx, &mautrix.ReqRegister[any]{Username: localpart, Password: password, InhibitLogin: true}); err != nil {
		t.Fatalf("register %s (is `just synapse` up?): %v", localpart, err)
	}
}

// verb runs `run.sh <verb>` against home with stdin, returning combined
// output and the exit code.
func verb(t *testing.T, home, stdin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(runSh(t), args...)
	cmd.Env = append(os.Environ(), "TERVA_HOME="+home)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return string(out), code
}

// provision logs the bot in with `setup` the way an operator would, by
// piping the answers, and checks `configured` agrees. Input that stops
// after the password takes setup's defaults: a new recovery key, and no
// emoji wait. answers are any further lines, for the e2ee prompts. It
// returns setup's output.
func provision(t *testing.T, home, hs, user, password string, answers ...string) string {
	t.Helper()
	in := fmt.Sprintf("%s\n%s\n%s\n", hs, user, password)
	for _, a := range answers {
		in += a + "\n"
	}
	out, code := verb(t, home, in, "setup")
	if code != 0 {
		t.Fatalf("setup exited %d:\n%s", code, out)
	}
	if strings.Contains(out, password) {
		t.Fatal("setup echoed the password")
	}
	if out, code := verb(t, home, "", "configured"); code != 0 {
		t.Fatalf("configured exited %d after setup:\n%s", code, out)
	}
	return out
}

// host is one run of the connector under a fake terva.
type host struct {
	t      *testing.T
	home   string
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	frames chan map[string]any
	logf   *os.File

	mu      sync.Mutex
	skipped []map[string]any
	hello   map[string]any // as handshake received it
}

var runN int

func spawn(t *testing.T, home string) *host {
	t.Helper()
	runN++
	logf, err := os.Create(filepath.Join(home, fmt.Sprintf("run-%d.log", runN)))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(runSh(t), "run")
	cmd.Env = append(os.Environ(), "TERVA_HOME="+home)
	cmd.Stderr = logf
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := &host{t: t, home: home, cmd: cmd, stdin: stdin, frames: make(chan map[string]any, 256), logf: logf}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 4<<20)
		for sc.Scan() {
			var f map[string]any
			if json.Unmarshal(sc.Bytes(), &f) == nil {
				h.frames <- f
			}
		}
		close(h.frames)
	}()
	t.Cleanup(func() {
		if h.cmd.ProcessState == nil {
			h.cmd.Process.Kill()
			h.cmd.Wait()
		}
		logf.Close()
	})
	return h
}

func (h *host) write(frame any) {
	h.t.Helper()
	b, err := json.Marshal(frame)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.stdin.Write(append(b, '\n')); err != nil {
		h.t.Fatalf("write %s: %v", b, err)
	}
}

// expect waits for the next frame satisfying pred, keeping the others
// for the failure message.
func (h *host) expect(what string, timeout time.Duration, pred func(map[string]any) bool) map[string]any {
	h.t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case f, ok := <-h.frames:
			if !ok {
				h.t.Fatalf("connector exited while waiting for %s; skipped %v; log %s", what, h.skipped, h.logf.Name())
			}
			if pred(f) {
				return f
			}
			h.skipped = append(h.skipped, f)
		case <-deadline:
			h.t.Fatalf("timed out waiting for %s; skipped %v; log %s", what, h.skipped, h.logf.Name())
		}
	}
}

// drain collects every frame that arrives within d, for asserting that
// something did not happen.
func (h *host) drain(d time.Duration) []map[string]any {
	h.t.Helper()
	var got []map[string]any
	deadline := time.After(d)
	for {
		select {
		case f, ok := <-h.frames:
			if !ok {
				h.t.Fatalf("connector exited while draining; log %s", h.logf.Name())
			}
			got = append(got, f)
		case <-deadline:
			return got
		}
	}
}

func isType(typ string) func(map[string]any) bool {
	return func(f map[string]any) bool { return f["type"] == typ }
}

// handshake does hello, hello_ack at protocol 2, and connect, and
// returns the connected frame.
func (h *host) handshake() map[string]any {
	h.t.Helper()
	hello := h.expect("hello", 60*time.Second, isType("hello")) // run.sh may build first
	h.hello = hello
	if hello["name"] != "rihma" {
		h.t.Fatalf("hello name = %v, want rihma", hello["name"])
	}
	h.write(connproto.HelloAckFromHost{
		Type: "hello_ack", Protocol: 2, TervaVersion: "e2e",
		DataDir: filepath.Join(h.home, "connectors", "rihma", "data"),
		Capabilities: &connproto.Capabilities{Features: []string{
			"message_ids", "chat_kinds", "asks", "entities", "chat_membership",
			"edits_in", "deletes_in", "reactions_in", "attachment_kinds",
		}},
	})
	h.write(connproto.ConnectFromHost{Type: "connect"})
	f := h.expect("connected or connect_error", 30*time.Second, func(f map[string]any) bool {
		return f["type"] == "connected" || f["type"] == "connect_error"
	})
	if f["type"] != "connected" {
		h.t.Fatalf("connect: %v", f)
	}
	return f
}

// shutdown asks the connector to stop and requires a clean exit.
func (h *host) shutdown() {
	h.t.Helper()
	h.write(connproto.ShutdownFromHost{Type: "shutdown"})
	h.stdin.Close()
	done := make(chan error, 1)
	go func() { done <- h.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			h.t.Fatalf("connector exit: %v; log %s", err, h.logf.Name())
		}
	case <-time.After(15 * time.Second):
		h.t.Fatalf("connector did not exit after shutdown; log %s", h.logf.Name())
	}
}
