//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// rawMedia is an m.file built by hand, so a test can send what a
// well-behaved client would not.
type rawMedia struct {
	name     string
	data     []byte
	declared int  // info.size; 0 sends no info
	plain    bool // an unencrypted url even in an encrypted room
	tamper   bool // flip a ciphertext byte after encrypting
}

func (h *human) sendRaw(t *testing.T, ctx context.Context, room id.RoomID, m rawMedia) id.EventID {
	t.Helper()
	content := &event.MessageEventContent{MsgType: event.MsgFile, Body: m.name}
	if m.declared > 0 {
		content.Info = &event.FileInfo{MimeType: "application/octet-stream", Size: m.declared}
	}
	data := m.data
	var ef *attachment.EncryptedFile
	if !m.plain {
		ef = attachment.NewEncryptedFile()
		data = ef.Encrypt(data)
		if m.tamper {
			data[0] ^= 0xff
		}
	}
	up, err := h.UploadMedia(ctx, mautrix.ReqUploadMedia{ContentBytes: data, ContentType: "application/octet-stream"})
	if err != nil {
		t.Fatal(err)
	}
	if ef != nil {
		content.File = &event.EncryptedFileInfo{EncryptedFile: *ef, URL: up.ContentURI.CUString()}
	} else {
		content.URL = up.ContentURI.CUString()
	}
	return h.send(t, ctx, room, content)
}

func setConfig(t *testing.T, home, key string, value any) {
	t.Helper()
	p := filepath.Join(home, "connectors", "rihma", "config.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg[key] = value
	out, _ := json.Marshal(cfg)
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAttachmentRefusals: with max_attachment_mb at 1, a file that
// declares 2 MiB, files that stream 1.5 MiB without declaring a size
// (encrypted and not), and an encrypted file whose ciphertext was
// altered are all dropped, while a small file and a sticker arrive.
// data_dir keeps only those two.
func TestAttachmentRefusals(t *testing.T) {
	hs := homeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tg := tag()
	botLocal := "capbot-" + tg
	bot := id.UserID("@" + botLocal + ":localhost")
	register(t, ctx, hs, botLocal, "bot-pw")
	home := t.TempDir()
	provision(t, home, hs, bot.String(), "bot-pw")
	setConfig(t, home, "max_attachment_mb", 1)
	hu := newHuman(t, ctx, hs, "capdrew-"+tg, "human-pw", bot)

	conn := spawn(t, home)
	conn.handshake()
	room := openEncryptedDM(t, ctx, hu, bot)

	big := make([]byte, 3<<19)
	refused := map[id.EventID]string{
		hu.sendRaw(t, ctx, room, rawMedia{name: "says-big.bin", data: []byte("tiny"), declared: 2 << 20}): "declared over the limit",
		hu.sendRaw(t, ctx, room, rawMedia{name: "big.bin", data: big}):                                    "encrypted, over the limit",
		hu.sendRaw(t, ctx, room, rawMedia{name: "big-plain.bin", data: big, plain: true}):                 "unencrypted, over the limit",
		hu.sendRaw(t, ctx, room, rawMedia{name: "tampered.bin", data: []byte("altered"), tamper: true}):   "altered ciphertext",
	}
	ok := hu.sendRaw(t, ctx, room, rawMedia{name: "fits.bin", data: []byte("fits"), declared: 4})

	up, err := hu.UploadMedia(ctx, mautrix.ReqUploadMedia{ContentBytes: tinyPNG(t), ContentType: "image/png"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hu.SendMessageEvent(ctx, room, event.EventSticker, &event.MessageEventContent{
		Body: "a wave", URL: up.ContentURI.CUString(), Info: &event.FileInfo{MimeType: "image/png", Size: len(tinyPNG(t))},
	})
	if err != nil {
		t.Fatal(err)
	}
	marker := hu.send(t, ctx, room, text("after the refusals"))

	conn.expect("the file that fits", 60*time.Second, func(f map[string]any) bool { return f["type"] == "message" && f["id"] == ok.String() })
	f := conn.expect("the sticker", 60*time.Second, func(f map[string]any) bool { return f["type"] == "message" && f["id"] == resp.EventID.String() })
	atts, _ := f["attachments"].([]any)
	if len(atts) != 1 || str(f, "text") != "" {
		t.Fatalf("sticker message = %v", f)
	}
	if a, _ := atts[0].(map[string]any); str(a, "kind") != "sticker" || str(a, "name") != "a wave" || str(a, "mime_type") != "image/png" {
		t.Fatalf("sticker = %v", a)
	}
	conn.expect("the marker", 60*time.Second, func(f map[string]any) bool { return f["type"] == "message" && f["id"] == marker.String() })
	for _, f := range conn.skipped {
		if why, bad := refused[id.EventID(str(f, "id"))]; bad {
			t.Fatalf("an attachment that should be refused (%s) was delivered: %v", why, f)
		}
	}
	entries, err := os.ReadDir(filepath.Join(home, "connectors", "rihma", "data"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("data_dir holds %v, want the file that fits and the sticker", names)
	}
	conn.shutdown()
}
