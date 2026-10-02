//go:build e2e

package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"maunium.net/go/mautrix/id"
)

// A setup whose login fails (here, a homeserver that is not there) must
// leave a configured bot working: same device, and it still runs and
// receives. Element's escaped command rides along, since it needs a DM.
func TestSetupFailureKeepsBotWorking(t *testing.T) {
	hs := homeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	tg := tag()
	botLocal, botPW := "bot-"+tg, "bot-pw"
	bot := id.UserID("@" + botLocal + ":localhost")
	register(t, ctx, hs, botLocal, botPW)
	home := t.TempDir()
	first := provision(t, home, hs, bot.String(), botPW)
	if strings.Contains(first, `"level":"info"`) {
		t.Fatalf("setup printed info-level library logs into the terminal:\n%s", first)
	}
	before, _ := verb(t, home, "", "status")

	out, code := verb(t, home, "http://127.0.0.1:1\n"+bot.String()+"\n"+botPW+"\n", "setup")
	if code == 0 || !strings.Contains(out, "untouched") {
		t.Fatalf("setup against a dead homeserver exited %d:\n%s", code, out)
	}
	if strings.Contains(out, "replacing") {
		t.Fatalf("setup retired the old session before the new login worked:\n%s", out)
	}
	after, _ := verb(t, home, "", "status")
	if deviceLine(after) != deviceLine(before) || deviceLine(after) == "" {
		t.Fatalf("status after a failed setup:\n%s\nwant the device from before:\n%s", after, before)
	}

	hu := newHuman(t, ctx, hs, "human-"+tg, "human-pw", bot)
	conn := spawn(t, home)
	defer conn.shutdown()
	if got := conn.handshake(); str(got, "id") != bot.String() {
		t.Fatalf("connected id = %v, want %s", got["id"], bot)
	}
	room := openEncryptedDM(t, ctx, hu, bot)
	hu.send(t, ctx, room, text(`\/status`))
	conn.expect("Element's escaped /status, unescaped", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "message" && f["text"] == "/status"
	})
}

func deviceLine(status string) string {
	for _, l := range strings.Split(status, "\n") {
		if strings.HasPrefix(l, "rihma bot:") {
			return l
		}
	}
	return ""
}
