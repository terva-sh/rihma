//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connproto"

	"terva.sh/rihma"
)

// tinyPNG is a 1x1 PNG, the kind of image terva-conn-matrix's scenario
// sends.
func tinyPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func download(t *testing.T, ctx context.Context, hu *human, content *event.MessageEventContent) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := hu.DownloadMedia(ctx, content, 0, &buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// reactionKeysBy lists the annotation keys sender has on target, as the
// server's relations report them.
func reactionKeysBy(t *testing.T, ctx context.Context, hu *human, room id.RoomID, target id.EventID, sender id.UserID) []string {
	t.Helper()
	resp, err := hu.GetRelations(ctx, room, target, &mautrix.ReqGetRelations{RelationType: event.RelAnnotation, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, evt := range resp.Chunk {
		if evt.Sender != sender || evt.Type != event.EventReaction {
			continue
		}
		if evt.Content.Parsed == nil {
			_ = evt.Content.ParseRaw(evt.Type)
		}
		keys = append(keys, evt.Content.AsReaction().RelatesTo.Key)
	}
	return keys
}

func result(t *testing.T, conn *host, id string) map[string]any {
	t.Helper()
	r := conn.expect("result "+id, 30*time.Second, func(f map[string]any) bool { return f["type"] == "result" && f["id"] == id })
	if str(r, "error") != "" {
		t.Fatalf("result %s = %v", id, r)
	}
	return r
}

// messageEvents ports the events half of
// dm_message_events_and_attachments: edits, reactions, and deletes in,
// edit, react, and delete out, and removing a reaction after a restart
// with nothing in memory.
func messageEvents(t *testing.T, encrypted bool) {
	hs := homeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	tg := tag()
	botLocal := "evbot-" + tg
	bot := id.UserID("@" + botLocal + ":localhost")
	register(t, ctx, hs, botLocal, "bot-pw")
	home := t.TempDir()
	provision(t, home, hs, bot.String(), "bot-pw")
	hu := newHuman(t, ctx, hs, "evdrew-"+tg, "human-pw", bot)
	hu.plain = !encrypted

	conn := spawn(t, home)
	conn.handshake()
	var room id.RoomID
	if encrypted {
		room = openEncryptedDM(t, ctx, hu, bot)
	} else {
		resp, err := hu.CreateRoom(ctx, &mautrix.ReqCreateRoom{Preset: "trusted_private_chat", IsDirect: true, Invite: []id.UserID{bot}})
		if err != nil {
			t.Fatal(err)
		}
		room = resp.RoomID
		waitJoined(t, ctx, hu.Client, room, bot)
	}

	hello := hu.send(t, ctx, room, text("hello events"))
	conn.expect("hello", 60*time.Second, func(f map[string]any) bool { return f["type"] == "message" && f["id"] == hello.String() })
	conn.write(connproto.SendFromHost{Type: "send", ID: "ev-1", ChatID: room.String(), Text: "roger"})
	botMsg := id.EventID(str(result(t, conn, "ev-1"), "message_id"))

	// An edit in, under the original id.
	edit := text("* hello events v2")
	edit.NewContent = text("hello events v2")
	edit.RelatesTo = (&event.RelatesTo{}).SetReplace(hello)
	hu.send(t, ctx, room, edit)
	f := conn.expect("message_edited", 60*time.Second, func(f map[string]any) bool { return f["type"] == "message_edited" })
	if str(f, "id") != hello.String() || str(f, "text") != "hello events v2" || str(f, "chat_id") != room.String() {
		t.Fatalf("message_edited = %v", f)
	}

	// A reaction in, then its removal.
	react, err := hu.SendReaction(ctx, room, botMsg, "👍")
	if err != nil {
		t.Fatal(err)
	}
	f = conn.expect("reaction", 60*time.Second, func(f map[string]any) bool { return f["type"] == "reaction" && f["removed"] != true })
	if str(f, "message_id") != botMsg.String() || str(f, "key") != "👍" || str(f, "user_id") != hu.UserID.String() {
		t.Fatalf("reaction = %v", f)
	}
	if _, err := hu.RedactEvent(ctx, room, react.EventID); err != nil {
		t.Fatal(err)
	}
	f = conn.expect("reaction removed", 60*time.Second, func(f map[string]any) bool { return f["type"] == "reaction" && f["removed"] == true })
	if str(f, "message_id") != botMsg.String() || str(f, "key") != "👍" || str(f, "user_id") != hu.UserID.String() {
		t.Fatalf("reaction removal = %v", f)
	}

	// A delete in.
	doomed := hu.send(t, ctx, room, text("delete me"))
	conn.expect("delete me", 60*time.Second, func(f map[string]any) bool { return f["type"] == "message" && f["id"] == doomed.String() })
	if _, err := hu.RedactEvent(ctx, room, doomed); err != nil {
		t.Fatal(err)
	}
	f = conn.expect("message_deleted", 60*time.Second, func(f map[string]any) bool { return f["type"] == "message_deleted" })
	if str(f, "id") != doomed.String() || str(f, "chat_id") != room.String() {
		t.Fatalf("message_deleted = %v", f)
	}

	// React, edit, and delete out.
	// Three reactions, so removing the middle one after the restart must
	// match on the key, whichever order the server lists them in.
	for i, key := range []string{"✅", "👀", "❤"} {
		rid := fmt.Sprintf("ev-2.%d", i)
		conn.write(connproto.ReactFromHost{Type: "react", ID: rid, ChatID: room.String(), MessageID: hello.String(), Key: key})
		result(t, conn, rid)
	}
	conn.write(connproto.EditFromHost{Type: "edit", ID: "ev-3", ChatID: room.String(), MessageID: botMsg.String(), Text: "**fixed** roger"})
	result(t, conn, "ev-3")
	got := hu.waitSeen(t, ctx, "the bot's edit", func(s seenMsg) bool { return s.body == "* **fixed** roger" })
	if got.formattedBody != "* <strong>fixed</strong> roger" {
		t.Fatalf("edit fallback formatted_body = %q", got.formattedBody)
	}
	conn.write(connproto.DeleteFromHost{Type: "delete", ID: "ev-4", ChatID: room.String(), MessageID: botMsg.String()})
	result(t, conn, "ev-4")
	raw, err := hu.GetEvent(ctx, room, botMsg)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw.Content.VeryRaw) > 2 || raw.Unsigned.RedactedBecause == nil {
		t.Fatalf("the deleted message still has content %s", raw.Content.VeryRaw)
	}
	if keys := reactionKeysBy(t, ctx, hu, room, hello, bot); len(keys) != 3 {
		t.Fatalf("the bot's reactions on hello = %v, want three", keys)
	}

	// Attachments out: a file with a caption, then an image without.
	notes := filepath.Join(home, "notes.txt")
	shot := filepath.Join(home, "shot.png")
	if err := os.WriteFile(notes, []byte("release notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shot, tinyPNG(t), 0o600); err != nil {
		t.Fatal(err)
	}
	conn.write(connproto.SendFileFromHost{Type: "send_file", ID: "ev-5", ChatID: room.String(), Path: notes, Caption: "the notes"})
	result(t, conn, "ev-5")
	file := hu.waitSeen(t, ctx, "the bot's file", func(s seenMsg) bool { return s.content.MsgType == event.MsgFile })
	if file.body != "the notes" || file.content.FileName != "notes.txt" || (encrypted && file.content.File == nil) {
		t.Fatalf("the bot's file: body %q, filename %q, encrypted file %v", file.body, file.content.FileName, file.content.File != nil)
	}
	if got := download(t, ctx, hu, file.content); string(got) != "release notes" {
		t.Fatalf("the bot's file downloads as %q", got)
	}
	conn.write(connproto.SendImageFromHost{Type: "send_image", ID: "ev-6", ChatID: room.String(), Path: shot})
	result(t, conn, "ev-6")
	img := hu.waitSeen(t, ctx, "the bot's image", func(s seenMsg) bool { return s.content.MsgType == event.MsgImage })
	if img.body != "shot.png" || !bytes.Equal(download(t, ctx, hu, img.content), tinyPNG(t)) {
		t.Fatalf("the bot's image: body %q", img.body)
	}

	// An attachment in: byte-exact through data_dir.
	dot, err := hu.SendMedia(ctx, room, rihma.Media{Data: tinyPNG(t), Name: "dot.png", MimeType: "image/png", MsgType: event.MsgImage, Caption: "a dot"})
	if err != nil {
		t.Fatal(err)
	}
	f = conn.expect("the attachment", 60*time.Second, func(f map[string]any) bool { return f["type"] == "message" && f["id"] == dot.String() })
	atts, _ := f["attachments"].([]any)
	if len(atts) != 1 {
		t.Fatalf("attachment message = %v", f)
	}
	a, _ := atts[0].(map[string]any)
	dataDir := filepath.Join(home, "connectors", "rihma", "data")
	path := str(a, "path")
	if str(a, "kind") != "image" || str(a, "name") != "dot.png" || str(a, "caption") != "a dot" || str(a, "mime_type") != "image/png" ||
		num(a, "size") != len(tinyPNG(t)) || filepath.Dir(path) != dataDir || str(f, "text") != "" {
		t.Fatalf("attachment = %v", a)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, tinyPNG(t)) {
		t.Fatalf("data_dir file: %v; bytes match %v", err, bytes.Equal(got, tinyPNG(t)))
	}
	conn.shutdown()

	// After a restart nothing remembers the reaction; it comes back from
	// the server's relations.
	conn = spawn(t, home)
	conn.handshake()
	conn.write(connproto.ReactFromHost{Type: "react", ID: "ev-7", ChatID: room.String(), MessageID: hello.String(), Key: "👀", Remove: true})
	result(t, conn, "ev-7")
	keys := reactionKeysBy(t, ctx, hu, room, hello, bot)
	slices.Sort(keys)
	if want := []string{"✅", "❤"}; !slices.Equal(keys, want) {
		t.Fatalf("the bot's reactions on hello after removing 👀 = %v, want %v", keys, want)
	}
	conn.shutdown()
}

func TestDMMessageEvents(t *testing.T)          { messageEvents(t, false) }
func TestEncryptedDMMessageEvents(t *testing.T) { messageEvents(t, true) }
