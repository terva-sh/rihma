//go:build e2e

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connproto"

	"terva.sh/rihma"
)

// inThread is a text message in root's thread: a real reply to replyTo,
// or fallback-shaped (as clients send a plain thread message) without.
func inThread(body string, root, replyTo id.EventID) *event.MessageEventContent {
	c := text(body)
	if replyTo != "" {
		c.RelatesTo = (&event.RelatesTo{}).SetThread(root, "").SetReplyTo(replyTo)
	} else {
		c.RelatesTo = (&event.RelatesTo{}).SetThread(root, root)
	}
	return c
}

func threaded(m seenMsg, root id.EventID) bool {
	return m.content != nil && m.content.RelatesTo.GetThreadParent() == root
}

// threadRoundTrip ports terva-conn-matrix's thread_round_trip: an
// anchored thread_start, a send into the thread, inbound thread routing
// with the root's title, a real in-thread reply, typing, and edits,
// reactions, and deletes carrying the thread's chat id. It adds threads
// for asks and attachments both ways, an anchorless thread_start, and a
// restart, after which events about thread messages from before it still
// carry the thread's chat id.
func threadRoundTrip(t *testing.T, encrypted bool) {
	hs := homeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	tg := tag()
	botLocal := "thrbot-" + tg
	bot := id.UserID("@" + botLocal + ":localhost")
	register(t, ctx, hs, botLocal, "bot-pw")
	home := t.TempDir()
	provision(t, home, hs, bot.String(), "bot-pw")
	hu := newHuman(t, ctx, hs, "thrdrew-"+tg, "human-pw", bot)
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
	isMsg := func(evt id.EventID) func(map[string]any) bool {
		return func(f map[string]any) bool { return f["type"] == "message" && f["id"] == evt.String() }
	}

	anchor := hu.send(t, ctx, room, text("the flaky test strikes again"))
	conn.expect("anchor", 60*time.Second, isMsg(anchor))

	// thread_start anchored at the human's message.
	conn.write(connproto.ThreadStartFromHost{Type: "thread_start", ID: "th-1", ChatID: room.String(), FromMessageID: anchor.String(), Name: "investigate: flaky test"})
	thread := str(result(t, conn, "th-1"), "chat_id")
	if want := room.String() + ";thread=" + anchor.String(); thread != want {
		t.Fatalf("thread chat = %q, want %q", thread, want)
	}
	hu.waitSeen(t, ctx, "the starter", func(m seenMsg) bool {
		return m.body == "investigate: flaky test" && threaded(m, anchor) && m.content.RelatesTo.IsFallingBack
	})

	// A send into the thread rides the thread.
	conn.write(connproto.SendFromHost{Type: "send", ID: "th-2", ChatID: thread, Text: "tracked it to a race in teardown"})
	botMsg := id.EventID(str(result(t, conn, "th-2"), "message_id"))
	hu.waitSeen(t, ctx, "the thread send", func(m seenMsg) bool { return m.id == botMsg && threaded(m, anchor) })

	// The human's thread message routes to the thread, titled by the
	// root; its fallback is not a reply.
	nice := hu.send(t, ctx, room, inThread("nice find", anchor, ""))
	f := conn.expect("thread message", 60*time.Second, isMsg(nice))
	if str(f, "chat_id") != thread || str(f, "chat_kind") != "thread" || str(f, "chat_title") != "the flaky test strikes again" || f["reply_to"] != nil {
		t.Fatalf("thread message = %v", f)
	}

	// A real in-thread reply to the bot keeps reply_to.
	ship := hu.send(t, ctx, room, inThread("ship the fix", anchor, botMsg))
	f = conn.expect("in-thread reply", 60*time.Second, isMsg(ship))
	if str(f, "chat_id") != thread || str(f, "reply_to") != botMsg.String() {
		t.Fatalf("in-thread reply = %v", f)
	}

	// Typing into the thread shows in the room.
	conn.write(connproto.TypingFromHost{Type: "typing", ChatID: thread})
	hu.waitTyping(t, true, 15*time.Second)

	// Edits, reactions, and deletes carry the thread's chat id.
	edit := text("* nice find — confirmed")
	edit.NewContent = text("nice find — confirmed")
	edit.RelatesTo = (&event.RelatesTo{}).SetReplace(nice)
	hu.send(t, ctx, room, edit)
	f = conn.expect("thread edit", 60*time.Second, func(f map[string]any) bool { return f["type"] == "message_edited" && f["id"] == nice.String() })
	if str(f, "chat_id") != thread {
		t.Fatalf("thread edit = %v", f)
	}
	react, err := hu.SendReaction(ctx, room, botMsg, "🎉")
	if err != nil {
		t.Fatal(err)
	}
	f = conn.expect("thread reaction", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "reaction" && f["message_id"] == botMsg.String() && f["removed"] != true
	})
	if str(f, "chat_id") != thread {
		t.Fatalf("thread reaction = %v", f)
	}
	if _, err := hu.RedactEvent(ctx, room, react.EventID); err != nil {
		t.Fatal(err)
	}
	f = conn.expect("thread reaction removal", 60*time.Second, func(f map[string]any) bool { return f["type"] == "reaction" && f["removed"] == true })
	if str(f, "chat_id") != thread {
		t.Fatalf("thread reaction removal = %v", f)
	}
	if _, err := hu.RedactEvent(ctx, room, nice); err != nil {
		t.Fatal(err)
	}
	f = conn.expect("thread delete", 60*time.Second, func(f map[string]any) bool { return f["type"] == "message_deleted" && f["id"] == nice.String() })
	if str(f, "chat_id") != thread {
		t.Fatalf("thread delete = %v", f)
	}

	// An ask into the thread renders inside it.
	conn.write(connproto.AskFromHost{Type: "ask", ID: "th-ask", ChatID: thread, Text: "Merge it?",
		Options: []connproto.AskOption{{Key: "yes", Label: "Yes", Hint: "✅"}}})
	askMsg := id.EventID(str(result(t, conn, "th-ask"), "message_id"))
	hu.waitSeen(t, ctx, "the threaded ask", func(m seenMsg) bool { return m.id == askMsg && threaded(m, anchor) })

	// Attachments both ways ride the thread.
	notes := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(notes, []byte("race in teardown"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn.write(connproto.SendFileFromHost{Type: "send_file", ID: "th-file", ChatID: thread, Path: notes})
	result(t, conn, "th-file")
	hu.waitSeen(t, ctx, "the threaded file", func(m seenMsg) bool { return m.body == "notes.txt" && threaded(m, anchor) })
	dot, err := hu.SendMedia(ctx, room, rihma.Media{Data: tinyPNG(t), Name: "dot.png", MimeType: "image/png", MsgType: event.MsgImage,
		RelatesTo: (&event.RelatesTo{}).SetThread(anchor, anchor)})
	if err != nil {
		t.Fatal(err)
	}
	f = conn.expect("threaded attachment", 60*time.Second, isMsg(dot))
	if str(f, "chat_id") != thread || str(f, "chat_kind") != "thread" {
		t.Fatalf("threaded attachment = %v", f)
	}

	// Anchorless: the starter is the root.
	conn.write(connproto.ThreadStartFromHost{Type: "thread_start", ID: "th-3", ChatID: room.String(), Name: "ops review"})
	ops := str(result(t, conn, "th-3"), "chat_id")
	_, opsRoot, ok := strings.Cut(ops, ";thread=")
	if !ok || !strings.HasPrefix(ops, room.String()+";thread=$") {
		t.Fatalf("anchorless thread chat = %q", ops)
	}
	hu.waitSeen(t, ctx, "the anchorless starter", func(m seenMsg) bool { return m.id == id.EventID(opsRoot) && m.content.RelatesTo == nil })
	conn.write(connproto.SendFromHost{Type: "send", ID: "th-4", ChatID: ops, Text: "agenda"})
	agenda := id.EventID(str(result(t, conn, "th-4"), "message_id"))
	hu.waitSeen(t, ctx, "a send into the anchorless thread", func(m seenMsg) bool { return m.id == agenda && threaded(m, id.EventID(opsRoot)) })

	// Nested threads and empty names are refused.
	conn.write(connproto.ThreadStartFromHost{Type: "thread_start", ID: "th-5", ChatID: thread, Name: "nested"})
	conn.write(connproto.ThreadStartFromHost{Type: "thread_start", ID: "th-6", ChatID: room.String()})
	// connsdk runs each command on its own goroutine, so the two results
	// arrive in either order.
	refused := map[string]bool{}
	for len(refused) < 2 {
		r := conn.expect("results th-5 and th-6", 30*time.Second, func(f map[string]any) bool {
			return f["type"] == "result" && (f["id"] == "th-5" || f["id"] == "th-6")
		})
		if str(r, "error") == "" {
			t.Fatalf("result %s succeeded: %v", str(r, "id"), r)
		}
		refused[str(r, "id")] = true
	}
	conn.shutdown()

	// After a restart nothing is cached: events about thread messages
	// from before it are fetched to find their thread.
	conn = spawn(t, home)
	conn.handshake()
	edit = text("* ship the fix today")
	edit.NewContent = text("ship the fix today")
	edit.RelatesTo = (&event.RelatesTo{}).SetReplace(ship)
	hu.send(t, ctx, room, edit)
	f = conn.expect("edit after restart", 60*time.Second, func(f map[string]any) bool { return f["type"] == "message_edited" && f["id"] == ship.String() })
	if str(f, "chat_id") != thread {
		t.Fatalf("edit after restart = %v", f)
	}
	if _, err := hu.SendReaction(ctx, room, botMsg, "👀"); err != nil {
		t.Fatal(err)
	}
	f = conn.expect("reaction after restart", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "reaction" && f["message_id"] == botMsg.String() && f["key"] == "👀"
	})
	if str(f, "chat_id") != thread {
		t.Fatalf("reaction after restart = %v", f)
	}
	// A room message from before the restart stays room-scoped.
	if _, err := hu.SendReaction(ctx, room, anchor, "👍"); err != nil {
		t.Fatal(err)
	}
	f = conn.expect("room reaction after restart", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "reaction" && f["message_id"] == anchor.String()
	})
	if str(f, "chat_id") != room.String() {
		t.Fatalf("room reaction after restart = %v", f)
	}
	conn.shutdown()
}

func TestDMThreadRoundTrip(t *testing.T)          { threadRoundTrip(t, false) }
func TestEncryptedDMThreadRoundTrip(t *testing.T) { threadRoundTrip(t, true) }
