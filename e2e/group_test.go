//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"
	"unicode/utf8"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connproto"
)

func membershipFrame(room id.RoomID, change string) func(map[string]any) bool {
	return func(f map[string]any) bool {
		chat, _ := f["chat"].(map[string]any)
		return f["type"] == "chat_membership" && f["change"] == change && chat["id"] == room.String()
	}
}

func chatField(f map[string]any, k string) string {
	chat, _ := f["chat"].(map[string]any)
	s, _ := chat[k].(string)
	return s
}

func mention(body string, bot id.UserID) *event.MessageEventContent {
	c := text(body)
	c.Mentions = &event.Mentions{UserIDs: []id.UserID{bot}}
	return c
}

func entityList(f map[string]any) []map[string]any {
	raw, _ := f["entities"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		m, _ := e.(map[string]any)
		out = append(out, m)
	}
	return out
}

func num(m map[string]any, k string) int { n, _ := m[k].(float64); return int(n) }

// TestGroupAdmissionAndMentionSignals ports
// group_admission_and_mention_signals, then checks what rihma adds: a
// re-invite announces again, and a kick while the connector was down is
// reported on resume.
func TestGroupAdmissionAndMentionSignals(t *testing.T) {
	hs := homeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	tg := tag()
	botLocal := "grpbot-" + tg
	bot := id.UserID("@" + botLocal + ":localhost")
	register(t, ctx, hs, botLocal, "bot-pw")
	home := t.TempDir()
	provision(t, home, hs, bot.String(), "bot-pw")
	hu := newHuman(t, ctx, hs, "grpdrew-"+tg, "human-pw", bot)

	conn := spawn(t, home)
	conn.handshake()

	resp, err := hu.CreateRoom(ctx, &mautrix.ReqCreateRoom{Name: "ops", Invite: []id.UserID{bot}})
	if err != nil {
		t.Fatal(err)
	}
	room := resp.RoomID
	f := conn.expect("added to ops", 60*time.Second, membershipFrame(room, "added"))
	if chatField(f, "kind") != "group" || chatField(f, "title") != "ops" || str(f, "by_user_id") != hu.UserID.String() {
		t.Fatalf("added frame = %v", f)
	}

	hu.send(t, ctx, room, text("just chatting"))
	m := conn.expect("plain group message", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "message" && f["text"] == "just chatting"
	})
	if str(m, "chat_kind") != "group" || str(m, "chat_title") != "ops" {
		t.Fatalf("group message = %v", m)
	}
	if _, has := m["entities"]; has {
		t.Fatalf("a message with no mention carries entities: %v", m)
	}

	hu.send(t, ctx, room, mention("hey "+bot.String()+" deploy it", bot))
	m = conn.expect("the mention", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "message" && f["text"] == "hey "+bot.String()+" deploy it"
	})
	ents := entityList(m)
	if len(ents) != 1 || ents[0]["kind"] != "bot_mention" || num(ents[0], "offset") != 4 || num(ents[0], "length") != utf8.RuneCountInString(bot.String()) {
		t.Fatalf("mention entities = %v", m["entities"])
	}

	conn.write(connproto.SendFromHost{Type: "send", ID: "grp-1", ChatID: room.String(), Text: "deployed"})
	r := conn.expect("result grp-1", 30*time.Second, func(f map[string]any) bool { return f["type"] == "result" && f["id"] == "grp-1" })
	if str(r, "error") != "" || str(r, "message_id") == "" {
		t.Fatalf("result grp-1 = %v", r)
	}
	botEvt := id.EventID(str(r, "message_id"))

	reply := text("> <" + hu.UserID.String() + "> (quoted)\n\nthanks bot")
	reply.RelatesTo = (&event.RelatesTo{}).SetReplyTo(botEvt)
	hu.send(t, ctx, room, reply)
	m = conn.expect("the reply to the bot", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "message" && f["reply_to"] == botEvt.String()
	})
	found := false
	for _, e := range entityList(m) {
		if e["kind"] == "bot_mention" && num(e, "offset") == 0 && num(e, "length") == 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("a reply to the bot carries no 0/0 bot_mention: %v", m)
	}

	if _, err := hu.KickUser(ctx, room, &mautrix.ReqKickUser{UserID: bot, Reason: "e2e"}); err != nil {
		t.Fatal(err)
	}
	f = conn.expect("removed from ops", 60*time.Second, membershipFrame(room, "removed"))
	if str(f, "by_user_id") != hu.UserID.String() {
		t.Fatalf("removed frame = %v", f)
	}

	// Beyond the Rust scenario: invited back, then kicked while down.
	if _, err := hu.InviteUser(ctx, room, &mautrix.ReqInviteUser{UserID: bot}); err != nil {
		t.Fatal(err)
	}
	f = conn.expect("added again", 60*time.Second, membershipFrame(room, "added"))
	if str(f, "by_user_id") != hu.UserID.String() {
		t.Fatalf("second added frame = %v", f)
	}
	conn.shutdown()
	waitJoined(t, ctx, hu.Client, room, bot)
	if _, err := hu.KickUser(ctx, room, &mautrix.ReqKickUser{UserID: bot}); err != nil {
		t.Fatal(err)
	}
	conn = spawn(t, home)
	conn.handshake()
	f = conn.expect("removed while down", 60*time.Second, membershipFrame(room, "removed"))
	if str(f, "by_user_id") != hu.UserID.String() {
		t.Fatalf("removed-while-down frame = %v", f)
	}
	conn.shutdown()
}

// TestEncryptedGroupAdmissionAndTraffic ports
// encrypted_group_admission_and_traffic.
func TestEncryptedGroupAdmissionAndTraffic(t *testing.T) {
	hs := homeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	tg := tag()
	botLocal := "encgrp-" + tg
	bot := id.UserID("@" + botLocal + ":localhost")
	register(t, ctx, hs, botLocal, "bot-pw")
	home := t.TempDir()
	provision(t, home, hs, bot.String(), "bot-pw")
	hu := newHuman(t, ctx, hs, "encgdrew-"+tg, "human-pw", bot)

	conn := spawn(t, home)
	conn.handshake()
	resp, err := hu.CreateRoom(ctx, &mautrix.ReqCreateRoom{
		Name: "war room", Invite: []id.UserID{bot},
		InitialState: []*event.Event{{
			Type:    event.StateEncryption,
			Content: event.Content{Parsed: &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	room := resp.RoomID
	f := conn.expect("added to war room", 60*time.Second, membershipFrame(room, "added"))
	if chatField(f, "kind") != "group" || str(f, "by_user_id") != hu.UserID.String() {
		t.Fatalf("added frame = %v", f)
	}
	waitJoined(t, ctx, hu.Client, room, bot)

	evt := hu.send(t, ctx, room, mention(bot.String()+" deploy the thing", bot))
	m := conn.expect("the encrypted mention", 60*time.Second, func(f map[string]any) bool {
		return f["type"] == "message" && f["id"] == evt.String()
	})
	if str(m, "chat_kind") != "group" || str(m, "chat_title") != "war room" {
		t.Fatalf("encrypted group message = %v", m)
	}
	found := false
	for _, e := range entityList(m) {
		found = found || e["kind"] == "bot_mention"
	}
	if !found {
		t.Fatalf("no bot_mention in %v", m)
	}
	if typ := wireType(t, ctx, hu.Client, room, evt); typ != "m.room.encrypted" {
		t.Fatalf("the mention is %s on the server", typ)
	}

	conn.write(connproto.SendFromHost{Type: "send", ID: "encg-1", ChatID: room.String(), Text: "deploying"})
	r := conn.expect("result encg-1", 30*time.Second, func(f map[string]any) bool { return f["type"] == "result" && f["id"] == "encg-1" })
	if str(r, "error") != "" {
		t.Fatalf("result encg-1 = %v", r)
	}
	hu.waitSeen(t, ctx, "the encrypted group reply", func(s seenMsg) bool { return s.body == "deploying" })
	conn.shutdown()
}
