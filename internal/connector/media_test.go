package connector

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"terva.sh/rihma"
)

func TestPlanAttachment(t *testing.T) {
	info := func(mime string, dur int) *event.FileInfo { return &event.FileInfo{MimeType: mime, Duration: dur} }
	for _, tc := range []struct {
		name    string
		msg     event.MessageEventContent
		sticker bool
		want    attachmentPlan
		ok      bool
	}{
		{"image with a v1.10 caption", event.MessageEventContent{MsgType: event.MsgImage, Body: "a dot", FileName: "dot.png", Info: info("image/png", 0)}, false,
			attachmentPlan{kind: "image", name: "dot.png", caption: "a dot", mime: "image/png"}, true},
		{"filename equal to body is no caption", event.MessageEventContent{MsgType: event.MsgFile, Body: "notes.txt", FileName: "notes.txt"}, false,
			attachmentPlan{kind: "document", name: "notes.txt", mime: "text/plain"}, true},
		{"no filename: body is the name", event.MessageEventContent{MsgType: event.MsgVideo, Body: "clip.mp4", Info: info("", 1500)}, false,
			attachmentPlan{kind: "video", name: "clip.mp4", mime: "video/mp4", duration: 1500 * time.Millisecond}, true},
		{"MSC3245 voice", event.MessageEventContent{MsgType: event.MsgAudio, Body: "voice.ogg", MSC3245Voice: &event.MSC3245Voice{}, Info: info("audio/ogg", 2000)}, false,
			attachmentPlan{kind: "voice", name: "voice.ogg", mime: "audio/ogg", duration: 2 * time.Second}, true},
		{"plain audio", event.MessageEventContent{MsgType: event.MsgAudio, Body: "song.mp3"}, false,
			attachmentPlan{kind: "audio", name: "song.mp3", mime: "audio/mpeg"}, true},
		{"sticker: body is the name, no caption", event.MessageEventContent{Body: "a cat", FileName: "cat.png", Info: info("image/webp", 0)}, true,
			attachmentPlan{kind: "sticker", name: "a cat", mime: "image/webp"}, true},
		{"unknown extension", event.MessageEventContent{MsgType: event.MsgFile, Body: "blob.xyz"}, false,
			attachmentPlan{kind: "document", name: "blob.xyz", mime: "application/octet-stream"}, true},
		{"text is not media", event.MessageEventContent{MsgType: event.MsgText, Body: "hi"}, false, attachmentPlan{}, false},
		{"location is not media", event.MessageEventContent{MsgType: event.MsgLocation, Body: "here"}, false, attachmentPlan{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := planAttachment(&tc.msg, tc.sticker)
			if ok != tc.ok || (ok && got != tc.want) {
				t.Fatalf("got %+v, %v; want %+v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// The first two cases are terva-conn-matrix's pinned ones.
func TestFileName(t *testing.T) {
	for _, tc := range []struct{ evt, name, want string }{
		{"$abc/DEF:123", "../../etc/passwd", "abc_DEF_123-.._.._etc_passwd"},
		{"$ev", "", "ev-attachment"},
		{"$ev", "naïve café.png", "ev-na_ve_caf_.png"},
		{"$ev", strings.Repeat("x", 90) + ".png", "ev-" + strings.Repeat("x", 76) + ".png"},
	} {
		if got := fileName(tc.evt, tc.name); got != tc.want {
			t.Errorf("fileName(%q, %q) = %q, want %q", tc.evt, tc.name, got, tc.want)
		}
	}
}

func TestMimeAndMsgType(t *testing.T) {
	for name, want := range map[string]event.MessageType{
		"shot.PNG": event.MsgImage, "notes.txt": event.MsgFile, "a.opus": event.MsgAudio,
		"c.webm": event.MsgVideo, "noext": event.MsgFile,
	} {
		if got := msgTypeFor(guessMime(name)); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
}

func TestCeiling(t *testing.T) {
	if got := (fileConfig{}).ceiling(); got != 64<<20 {
		t.Fatalf("default ceiling = %d", got)
	}
	if got := (fileConfig{MaxAttachmentMB: 2}).ceiling(); got != 2<<20 {
		t.Fatalf("2 MB ceiling = %d", got)
	}
}

// A declared size over the limit fails before any request; the client
// here has no server at all.
func TestDownloadRefusesDeclaredSize(t *testing.T) {
	var c rihma.Client
	_, err := c.DownloadMedia(t.Context(), &event.MessageEventContent{URL: "mxc://hs/x", Info: &event.FileInfo{Size: 11}}, 10, nil)
	if !errors.Is(err, rihma.ErrTooLarge) {
		t.Fatalf("declared 11 bytes against 10 = %v", err)
	}
}

func TestThreadMediaCarriesParentContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/download/hs/attachment") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("fixture"))
	}))
	t.Cleanup(server.Close)
	client, err := mautrix.NewClient(server.URL, "@bot:hs", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"dm", "group"} {
		tr := newTestTransport()
		tr.client = &rihma.Client{Client: client}
		tr.dataDir = t.TempDir()
		tr.titles.set("!room:hs", "ops")
		direct := event.DirectChatsEventContent{}
		if kind == "dm" {
			direct["@human:hs"] = []id.RoomID{"!room:hs"}
		}
		tr.dms.set(direct)
		evt := msgEvent(t, `{"msgtype":"m.file","body":"attachment.bin","url":"mxc://hs/attachment",
			"m.relates_to":{"rel_type":"m.thread","event_id":"$root"}}`)
		m, ok := tr.translateMedia(t.Context(), evt, false)
		if !ok || m.ChatID != "!room:hs;thread=$root" || m.ParentChatID != "!room:hs" || m.ParentChatKind != kind || len(m.Attachments) != 1 {
			t.Fatalf("%s media = %+v, %v", kind, m, ok)
		}
		data, err := os.ReadFile(m.Attachments[0].Path)
		if err != nil || string(data) != "fixture" {
			t.Fatalf("attachment = %q, %v", data, err)
		}
		m, ok = tr.translateMedia(t.Context(), evt, true)
		if !ok || m.ChatKind == "thread" || m.ParentChatID != "" || m.ParentChatKind != "" {
			t.Fatalf("room-scoped sticker = %+v", m)
		}
	}
}
