//go:build dogfood && e2e

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/rihma"
)

// TestOperatorWarnings uses the real terva CLI and its operator sink. The
// provider and connector-only fault proxy are local; no provider credential
// or real Matrix account is used. The ordinary live suite needs only Synapse,
// so this additional check opts in through RIHMA_E2E_TERVA.
func TestOperatorWarnings(t *testing.T) {
	hs, binary := os.Getenv("RIHMA_E2E_HS"), os.Getenv("RIHMA_E2E_TERVA")
	if hs == "" || binary == "" {
		t.Skip("set RIHMA_E2E_HS and RIHMA_E2E_TERVA; see testing/DOGFOOD.md")
	}
	target, err := url.Parse(hs)
	if err != nil || target.Scheme != "http" || target.Hostname() != "127.0.0.1" {
		t.Fatal("operator test requires the throwaway Synapse on HTTP loopback")
	}
	version, err := exec.Command(binary, "--version").Output()
	var major, minor, patch int
	_, parseErr := fmt.Sscanf(string(version), "terva %d.%d.%d", &major, &minor, &patch)
	if err != nil || parseErr != nil || major == 0 && (minor < 139 || minor == 139 && patch < 7) {
		t.Fatal("RIHMA_E2E_TERVA must be terva v0.139.7 or later")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()

	var failing atomic.Bool
	var failures atomic.Int32
	forward := httputil.NewSingleHostReverseProxy(target)
	forward.ErrorLog = log.New(io.Discard, "", 0)
	faults := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/sync") && failing.Load() {
			failures.Add(1)
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"fixture outage"}`))
			return
		}
		forward.ServeHTTP(w, r)
	}))
	defer faults.Close()
	var modelCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/models") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"fixture","object":"model"}]}`))
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			http.NotFound(w, r)
			return
		}
		modelCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"id\":\"fixture\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"fixture response\"},\"finish_reason\":null}]}\n\n")
		_, _ = fmt.Fprint(w, "data: {\"id\":\"fixture\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer provider.Close()

	home := t.TempDir()
	cwd := filepath.Join(home, "cwd")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TERVA_HOME", home)
	t.Setenv("TERVA_LANG", "en")
	config := map[string]any{"provider": "operator-fixture", "model": "fixture", "endpoints": map[string]any{
		"operator-fixture": map[string]any{"baseUrl": provider.URL + "/v1", "contextWindow": 32768},
	}}
	writeFixtureJSON(t, filepath.Join(home, "config.json"), config)
	manifest, err := filepath.Abs("../../connector.json")
	if err != nil {
		t.Fatal(err)
	}
	runSh, err := filepath.Abs("../../run.sh")
	if err != nil {
		t.Fatal(err)
	}
	tag := fmt.Sprintf("%x", time.Now().UnixNano())
	botLocal, ownerLocal := "warningbot-"+tag, "warningowner-"+tag
	bot := id.UserID("@" + botLocal + ":localhost")
	registration, err := mautrix.NewClient(hs, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{botLocal, ownerLocal} {
		if _, err := registration.RegisterDummy(ctx, &mautrix.ReqRegister[any]{Username: user, Password: "fixture-password", InhibitLogin: true}); err != nil {
			t.Fatal("throwaway account registration failed")
		}
	}
	setup := exec.CommandContext(ctx, runSh, "setup")
	setup.Stdin = strings.NewReader(faults.URL + "\n" + bot.String() + "\nfixture-password\n3\n")
	// Setup output can contain credentials; it is deliberately never logged.
	if _, err := setup.Output(); err != nil {
		t.Fatal("throwaway connector setup failed")
	}
	cfgPath := filepath.Join(home, "connectors", "rihma", "config.json")
	if _, err := setLimit(cfgPath, 1); err != nil {
		t.Fatal(err)
	}
	pwPath := filepath.Join(home, "owner.password")
	if err := os.WriteFile(pwPath, []byte("fixture-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(home, "humans")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	o := options{homeserver: hs, bot: bot, owner: id.UserID("@" + ownerLocal + ":localhost"), ownerPW: pwPath, stateDir: state, config: cfgPath,
		connectorLog: filepath.Join(home, "logs", "connector-rihma.log")}
	owner, err := login(ctx, o, o.owner, pwPath)
	if err != nil {
		t.Fatal("throwaway human login failed")
	}
	defer func() { cancel(); <-owner.done }()
	command := strings.Join([]string{"exec", shellArg(binary), "bot run --connector rihma --connector-manifest", shellArg(manifest),
		"--provider operator-fixture --model fixture --no-ext --no-mcp --no-tools --approval ask --cwd", shellArg(cwd)}, " ")
	d := &dogfood{o: o, owner: owner, botLog: filepath.Join(home, "operator.log"), passed: map[int]bool{}}
	d.o.launch = command
	if d.bot, err = startBot(command, d.botLog); err != nil {
		t.Fatal(err)
	}
	defer func() { d.bot.stop() }()
	if d.dm, err = owner.room(ctx, "operator warnings", true, true, bot); err != nil {
		t.Fatal(err)
	}
	if !owner.waitMember(ctx, d.dm, bot, event.MembershipJoin, 45*time.Second) {
		t.Fatal("real host did not join test DM")
	}
	if _, ok := d.ask(ctx, d.dm, owner, text("/start")); !ok {
		t.Fatal("real host did not pair test owner")
	}
	if _, ok := d.ask(ctx, d.dm, owner, text("/status")); !ok {
		t.Fatal("real host built-in round trip failed")
	}

	t.Log("real host paired; checking fresh media and UTD notices")
	diagnostic, err := markLog(o.connectorLog)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := markLog(d.botLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		output, _ := operator.read()
		logs, _ := diagnostic.read()
		// Report only kinds and counts; never copy host output or secret state.
		t.Logf("evidence counts: host media=%d UTD=%d; diagnostics media=%d UTD=%d", strings.Count(string(output), "dropped attachment."), strings.Count(string(output), "unable to decrypt"), strings.Count(string(logs), "dropping attachment"), strings.Count(string(logs), "unable to decrypt messages"))
	})
	first := time.Now()
	callsBefore := modelCalls.Load()
	var media []id.EventID
	for range 3 {
		evt, err := owner.SendMedia(ctx, d.dm, rihma.Media{Data: make([]byte, 3<<19), Name: "private-fixture-name.bin", MimeType: "application/octet-stream", MsgType: event.MsgFile, Caption: "private fixture caption"})
		if err != nil {
			t.Fatal("sending oversize test media failed")
		}
		media = append(media, evt)
	}
	for range 3 {
		// Raw encrypted content with too-short ciphertext fails immediately,
		// rather than relying on a person losing keys or a key-request timeout.
		if _, err := owner.SendMessageEvent(ctx, d.dm, event.EventEncrypted, map[string]any{
			"algorithm": id.AlgorithmMegolmV1, "ciphertext": "private-fixture-ciphertext", "session_id": "fixture", "sender_key": "fixture",
		}); err != nil {
			t.Fatal("sending undecryptable fixture failed")
		}
	}
	waitOperator(t, ctx, "first media and UTD reports", func() bool {
		return countOperator(t, operator, "dropped attachment.") == 1 && countOperator(t, operator, "unable to decrypt") == 1 && diagnosticDrops(t, diagnostic) >= 3
	})
	matched := false
	for _, evt := range media {
		dropped, warned, err := oversizeEvidence(diagnostic, operator, evt)
		if err != nil {
			t.Fatal(err)
		}
		matched = matched || dropped && warned
	}
	if !matched {
		t.Fatal("real-host media warning did not match its connector diagnostic")
	}
	if _, ok := d.ask(ctx, d.dm, owner, text("/status")); !ok {
		t.Fatal("valid traffic stopped after media/UTD failures")
	}
	if modelCalls.Load() != callsBefore {
		t.Fatal("a refused or undecryptable event started a model turn")
	}
	if countOperator(t, operator, "dropped attachment.") != 1 || countOperator(t, operator, "unable to decrypt") != 1 {
		t.Fatal("warning flood was not rate-limited")
	}
	waitOperator(t, ctx, "aggregated UTD report after one minute", func() bool { return countOperator(t, operator, "unable to decrypt") == 2 })
	if time.Since(first) < 55*time.Second {
		t.Fatal("UTD window ended too early")
	}
	output, err := operator.read()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), "unable to decrypt 2 message(s)") {
		t.Fatal("UTD report did not aggregate the pending failures")
	}
	if _, err := owner.SendMedia(ctx, d.dm, rihma.Media{Data: make([]byte, 3<<19), Name: "private-fixture-name.bin", MsgType: event.MsgFile}); err != nil {
		t.Fatal(err)
	}
	waitOperator(t, ctx, "media notice after its window", func() bool { return countOperator(t, operator, "dropped attachment.") == 2 })

	t.Log("rate limits and valid traffic passed; checking connector-only outage and recovery")
	outage, err := markLog(d.botLog)
	if err != nil {
		t.Fatal(err)
	}
	failing.Store(true)
	if _, err := owner.SendStateEvent(ctx, d.dm, event.StateRoomName, "", map[string]string{"name": "outage fixture"}); err != nil {
		t.Fatal(err)
	}
	waitOperator(t, ctx, "sync retry notice", func() bool { return countOperator(t, outage, "retrying automatically") == 1 })
	from := owner.mark()
	if _, err := owner.say(ctx, d.dm, text("/status")); err != nil {
		t.Fatal(err)
	}
	if !owner.silent(ctx, from, d.dm, 5*time.Second) {
		t.Fatal("outage did not hold the queued message")
	}
	waitOperator(t, ctx, "repeated failed sync attempts", func() bool { return failures.Load() >= 3 })
	if countOperator(t, outage, "retrying automatically") != 1 {
		t.Fatal("repeated sync failures flooded the operator")
	}
	failing.Store(false)
	if _, ok := owner.reply(ctx, from, d.dm, 45*time.Second); !ok {
		t.Fatal("queued message did not recover after outage")
	}
	if _, ok := d.ask(ctx, d.dm, owner, text("fixture model turn")); !ok {
		t.Fatal("fresh model turn did not recover after outage")
	}
	if modelCalls.Load() != callsBefore+1 {
		t.Fatal("fake model round trip count was incorrect")
	}

	assertNoticePrivacy(t, d.botLog, cfgPath)
	t.Log("outage recovery passed; running scripted dogfood row 27 against this host")
	rowOversize(ctx, d)
	if !d.passed[27] {
		t.Fatal("scripted dogfood row 27 failed against the real host")
	}
	if modelCalls.Load() != callsBefore+1 {
		t.Fatal("scripted dogfood row 27 started a model turn")
	}
	assertNoticePrivacy(t, d.botLog, cfgPath)
}

func shellArg(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func writeFixtureJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
func waitOperator(t *testing.T, ctx context.Context, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(80 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if ready() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
func countOperator(t *testing.T, m logMark, kind string) int {
	t.Helper()
	b, err := m.read()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(operatorNotice(line), kind) {
			n++
		}
	}
	return n
}
func diagnosticDrops(t *testing.T, m logMark) int {
	t.Helper()
	b, err := m.read()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), `"message":"dropping attachment"`)
}
func assertNoticePrivacy(t *testing.T, logPath, cfgPath string) {
	t.Helper()
	// The generated session file is read only to reject secret values from
	// notices. Neither it nor a matching value is printed on a failure.
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal("cannot read generated session for privacy check")
	}
	var state struct {
		Session struct {
			AccessToken string `json:"access_token"`
			PickleKey   string `json:"pickle_key"`
			BackupKey   string `json:"backup_key"`
		} `json:"session"`
	}
	if err := json.Unmarshal(cfg, &state); err != nil {
		t.Fatal("cannot parse generated session for privacy check")
	}
	output, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = operatorNotice(line)
		if line == "" {
			continue
		}
		for _, secret := range []string{state.Session.AccessToken, state.Session.PickleKey, state.Session.BackupKey, "fixture-password", "private-fixture-name.bin", "private fixture caption", "private-fixture-ciphertext"} {
			if secret != "" && strings.Contains(line, secret) {
				t.Fatal("operator notice contains private fixture data")
			}
		}
	}
}
