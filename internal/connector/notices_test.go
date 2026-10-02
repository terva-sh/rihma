package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"terva.sh/terva/packages/agent/connsdk"

	"terva.sh/rihma"
)

// Exercise the real constructor and SDK writer, stopping before Connect
// so no homeserver or account is needed. Media drops use the actual ingest
// path, with the declared size rejected before any network request.
func TestOperatorNoticesReachTheHost(t *testing.T) {
	tervaHome(t, false)
	if err := saveConfig(fileConfig{HomeserverURL: "https://hs.example", UserID: "@bot:hs", DeviceID: "DEV",
		Session: &sessionSecrets{AccessToken: "fixture-token", PickleKey: "MDEyMzQ1Njc4OWFiY2RlZg=="}, MaxAttachmentMB: 1}); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	cfg := Config()
	cfg.NewTransport = func(s connsdk.Session) (connsdk.Transport, error) {
		s.DataDir = dataDir
		built, err := NewTransport(s)
		if err != nil {
			t.Fatal(err)
		}
		tr := built.(*transport)
		var diagnostics bytes.Buffer
		tr.log = zerolog.New(&diagnostics)
		tr.notices.log = tr.log
		opts := tr.clientOptions()
		opts.OnUTD("!room:hs", 3)
		if !strings.Contains(diagnostics.String(), "unable to decrypt") {
			t.Fatal("decryption notice missing from stderr diagnostics")
		}
		opts.OnSyncRetry()
		opts.OnSyncRetry() // suppressed within the window
		tr.client = &rihma.Client{}
		evt := msgEvent(t, `{"msgtype":"m.file","body":"private caption","filename":"private-name.txt",
			"url":"mxc://hs/fixture-token","info":{"size":1048577}}`)
		if _, ok := tr.translateMedia(t.Context(), evt, false); ok {
			t.Fatal("oversize media was delivered")
		}
		tr.translateMedia(t.Context(), evt, false) // suppressed within the window
		tr.translateMedia(t.Context(), evt, true)  // same media limit for stickers
		return nil, errors.New("fixture stops before opening the client")
	}
	var out bytes.Buffer
	input := "{\"type\":\"hello_ack\",\"protocol\":2}\n{\"type\":\"connect\"}\n{\"type\":\"shutdown\"}\n"
	if err := connsdk.Serve(cfg, strings.NewReader(input), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var notices []string
	decoder := json.NewDecoder(&out)
	for {
		var frame struct{ Type, Message string }
		if err := decoder.Decode(&frame); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if frame.Type == "warn" {
			notices = append(notices, frame.Message)
		}
	}
	if len(notices) != 3 {
		t.Fatalf("notices = %v; want decryption, sync, and media", notices)
	}
	for i, want := range []string{"decrypt 3", "retrying automatically", "dropped attachment"} {
		if !strings.Contains(notices[i], want) {
			t.Errorf("notice %d = %q, want %q", i, notices[i], want)
		}
	}
	if !strings.Contains(notices[2], "1048576 bytes") {
		t.Errorf("media notice lacks configured ceiling: %q", notices[2])
	}
	for _, forbidden := range []string{"private caption", "private-name.txt", "fixture-token", "DownloadMedia"} {
		if strings.Contains(strings.Join(notices, "\n"), forbidden) {
			t.Errorf("host notices contain %q", forbidden)
		}
	}
}

func TestOperatorNoticeFloodIsBounded(t *testing.T) {
	frames := make(chan string, 200)
	n := newOperatorNotices(func(line string) { frames <- line }, zerolog.Nop())
	now := time.Unix(1700000000, 0)
	n.now = func() time.Time { return now }
	var workers sync.WaitGroup
	for range 100 {
		workers.Go(func() {
			n.syncRetry()
			n.droppedMedia("!room:hs", "$evt", "attachment", 1024)
		})
	}
	workers.Wait()
	if got := len(frames); got != 2 {
		t.Fatalf("concurrent burst produced %d notices, want one per kind", got)
	}
	now = now.Add(noticeWindow - time.Nanosecond)
	n.syncRetry()
	n.droppedMedia("!other:hs", "$other", "sticker", 1024)
	if got := len(frames); got != 2 {
		t.Fatalf("another room bypassed the media limit: %d notices", got)
	}
	now = now.Add(time.Nanosecond)
	n.syncRetry()
	n.droppedMedia("!other:hs", "$other", "sticker", 1024)
	if got := len(frames); got != 4 {
		t.Fatalf("next window produced %d total notices, want 4", got)
	}
}
