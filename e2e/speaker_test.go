//go:build e2e

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connproto"
)

func features(h *host) []string {
	caps, _ := h.hello["capabilities"].(map[string]any)
	raw, _ := caps["features"].([]any)
	var out []string
	for _, f := range raw {
		s, _ := f.(string)
		out = append(out, s)
	}
	return out
}

func hasSpeakerFeature(fs []string) bool {
	return slices.ContainsFunc(fs, func(f string) bool { return strings.HasPrefix(f, "speaker:") })
}

// speakerProfilesRender ports terva-conn-matrix's speaker_profiles_render.
// With speaker off nothing is declared and a speaker send carries no
// profile. Switched to mode, the hello declares it, and a speaker send
// carries an MSC4144 profile: id and name, and at full an avatar
// uploaded to mxc. A send without a speaker carries none.
func speakerProfilesRender(t *testing.T, mode string, encrypted bool) {
	hs := homeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	tg := tag()
	botLocal := "spkbot-" + tg
	bot := id.UserID("@" + botLocal + ":localhost")
	register(t, ctx, hs, botLocal, "bot-pw")
	home := t.TempDir()
	provision(t, home, hs, bot.String(), "bot-pw")
	hu := newHuman(t, ctx, hs, "spkdrew-"+tg, "human-pw", bot)
	hu.plain = !encrypted
	avatar := filepath.Join(home, "kaiku.png")
	if err := os.WriteFile(avatar, tinyPNG(t), 0o600); err != nil {
		t.Fatal(err)
	}
	kaiku := &connproto.Speaker{Key: "kaiku", Name: "Kaiku", AvatarPath: avatar}

	// Off: nothing declared, and a host that sends a speaker anyway gets
	// plain text.
	conn := spawn(t, home)
	conn.handshake()
	if fs := features(conn); hasSpeakerFeature(fs) {
		t.Fatalf("speaker off declared %q", fs)
	}
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
	conn.write(connproto.SendFromHost{Type: "send", ID: "spk-0", ChatID: room.String(), Text: "Nobody speaks.", Speaker: kaiku})
	off := id.EventID(str(result(t, conn, "spk-0"), "message_id"))
	hu.waitSeen(t, ctx, "the speaker send while off", func(m seenMsg) bool {
		return m.id == off && m.body == "Nobody speaks." && m.content.BeeperPerMessageProfile == nil
	})
	conn.shutdown()

	setConfig(t, home, "speaker", mode)
	conn = spawn(t, home)
	conn.handshake()
	if fs := features(conn); !slices.Contains(fs, "speaker:"+mode) {
		t.Fatalf("speaker %s declared %q", mode, fs)
	}
	conn.write(connproto.SendFromHost{Type: "send", ID: "spk-1", ChatID: room.String(), Text: "The airlock hisses open.", Speaker: kaiku})
	spoken := id.EventID(str(result(t, conn, "spk-1"), "message_id"))
	m := hu.waitSeen(t, ctx, "the speaker send", func(m seenMsg) bool { return m.id == spoken })
	p := m.content.BeeperPerMessageProfile
	if m.body != "The airlock hisses open." || p == nil || p.ID != "kaiku" || p.Displayname != "Kaiku" {
		t.Fatalf("speaker send = %q, profile %+v", m.body, p)
	}
	switch mode {
	case "full":
		if p.AvatarURL == nil || !strings.HasPrefix(string(*p.AvatarURL), "mxc://") {
			t.Fatalf("full sent no avatar: %+v", p)
		}
	default:
		if p.AvatarURL != nil {
			t.Fatalf("%s sent an avatar: %+v", mode, p)
		}
	}

	conn.write(connproto.SendFromHost{Type: "send", ID: "spk-2", ChatID: room.String(), Text: "Plain narration."})
	plain := id.EventID(str(result(t, conn, "spk-2"), "message_id"))
	hu.waitSeen(t, ctx, "the speaker-less send", func(m seenMsg) bool {
		return m.id == plain && m.content.BeeperPerMessageProfile == nil
	})
	conn.shutdown()
}

func TestSpeakerProfilesRenderFull(t *testing.T) { speakerProfilesRender(t, "full", true) }
func TestSpeakerProfilesRenderNameOnly(t *testing.T) {
	speakerProfilesRender(t, "name_only", false)
}
