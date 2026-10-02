//go:build e2e

package e2e

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connproto"
)

// waitKeys polls until sender's reactions on target are exactly want, in
// any order.
func waitKeys(t *testing.T, ctx context.Context, hu *human, room id.RoomID, target id.EventID, sender id.UserID, want []string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		got := reactionKeysBy(t, ctx, hu, room, target, sender)
		slices.Sort(got)
		w := slices.Clone(want)
		slices.Sort(w)
		if slices.Equal(got, w) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("reactions by %s on %s = %q, want %q", sender, target, got, want)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// askWidgetLifecycle ports terva-conn-matrix's ask_widget_lifecycle: an
// ask renders and seeds, a tap answers attested, ask_close withdraws the
// seeds and edits in the outcome, and an expired ask withdraws itself so
// that a late tap is a plain reaction. It adds that the answer's un-tap
// is not reported as anything.
func askWidgetLifecycle(t *testing.T, encrypted bool) {
	hs := homeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	tg := tag()
	botLocal := "askbot-" + tg
	bot := id.UserID("@" + botLocal + ":localhost")
	register(t, ctx, hs, botLocal, "bot-pw")
	home := t.TempDir()
	provision(t, home, hs, bot.String(), "bot-pw")
	hu := newHuman(t, ctx, hs, "askdrew-"+tg, "human-pw", bot)
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
	hi := hu.send(t, ctx, room, text("hi"))
	conn.expect("hi", 60*time.Second, func(f map[string]any) bool { return f["type"] == "message" && f["id"] == hi.String() })

	// The widget: legend, and one seed per option.
	conn.write(connproto.AskFromHost{
		Type: "ask", ID: "ask-1", ChatID: room.String(), Text: "Deploy to prod?",
		Options: []connproto.AskOption{
			{Key: "approve", Label: "Approve", Style: "affirm", Hint: "👍"},
			{Key: "deny", Label: "Deny", Style: "deny"},
		},
		RestrictTo: []string{hu.UserID.String()}, ExpiresMS: 120000,
	})
	askMsg := id.EventID(str(result(t, conn, "ask-1"), "message_id"))
	if askMsg == "" {
		t.Fatal("ask result carries no message_id")
	}
	hu.waitSeen(t, ctx, "the ask", func(m seenMsg) bool {
		return m.id == askMsg && strings.Contains(m.body, "Deploy to prod?") && strings.Contains(m.body, "👍 Approve") && strings.Contains(m.body, "① Deny")
	})
	waitKeys(t, ctx, hu, room, askMsg, bot, []string{"👍", "①"}, 15*time.Second)

	// A tap answers, attested.
	answerTap, err := hu.SendReaction(ctx, room, askMsg, "👍")
	if err != nil {
		t.Fatal(err)
	}
	f := conn.expect("answer", 60*time.Second, isType("answer"))
	if str(f, "ask_id") != "ask-1" || str(f, "key") != "approve" || str(f, "user_id") != hu.UserID.String() ||
		str(f, "username") != "askdrew-"+tg || str(f, "attestation") != "attested" {
		t.Fatalf("answer = %v", f)
	}
	// Un-tapping it is not a deleted message, nor anything else.
	if _, err := hu.RedactEvent(ctx, room, answerTap.EventID); err != nil {
		t.Fatal(err)
	}

	// Close: seeds withdrawn, outcome edited in.
	conn.write(connproto.AskCloseFromHost{Type: "ask_close", ID: "ask-2", AskID: "ask-1", Outcome: "Approved"})
	result(t, conn, "ask-2")
	hu.waitSeen(t, ctx, "the outcome edit", func(m seenMsg) bool {
		return m.content != nil && m.content.NewContent != nil && m.content.RelatesTo.GetReplaceID() == askMsg &&
			m.content.NewContent.Body == "Deploy to prod?\n\n**Approved**"
	})
	waitKeys(t, ctx, hu, room, askMsg, bot, nil, 15*time.Second)
	// Closing again succeeds, as connproto says.
	conn.write(connproto.AskCloseFromHost{Type: "ask_close", ID: "ask-2b", AskID: "ask-1", Outcome: "Approved"})
	result(t, conn, "ask-2b")

	// Expiry withdraws the widget; a late tap is a plain reaction.
	conn.write(connproto.AskFromHost{
		Type: "ask", ID: "ask-3", ChatID: room.String(), Text: "Still there?",
		Options: []connproto.AskOption{{Key: "yes", Label: "Yes", Hint: "✅"}}, ExpiresMS: 2000,
	})
	stale := id.EventID(str(result(t, conn, "ask-3"), "message_id"))
	waitKeys(t, ctx, hu, room, stale, bot, nil, 20*time.Second)
	if _, err := hu.SendReaction(ctx, room, stale, "✅"); err != nil {
		t.Fatal(err)
	}
	var plain bool
	for _, f := range conn.drain(5 * time.Second) {
		switch {
		case f["type"] == "answer":
			t.Fatalf("an expired ask answered: %v", f)
		case f["type"] == "message_deleted" || (f["type"] == "reaction" && f["message_id"] == askMsg.String()):
			t.Fatalf("the answer's un-tap was reported: %v", f)
		case f["type"] == "reaction" && f["key"] == "✅" && f["message_id"] == stale.String():
			plain = true
		}
	}
	for _, f := range conn.skipped {
		if f["type"] == "message_deleted" {
			t.Fatalf("the answer's un-tap was reported: %v", f)
		}
	}
	if !plain {
		t.Fatal("the late tap was not delivered as a plain reaction")
	}
	conn.shutdown()
}

func TestDMAskWidgetLifecycle(t *testing.T)          { askWidgetLifecycle(t, false) }
func TestEncryptedDMAskWidgetLifecycle(t *testing.T) { askWidgetLifecycle(t, true) }
