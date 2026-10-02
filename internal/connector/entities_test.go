package connector

import (
	"fmt"
	"testing"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"
)

// The cases port terva-conn-matrix's src/matrix/entities.rs tests, with
// the same inputs and spans.
func TestExtractEntities(t *testing.T) {
	bot := botIdentity{userID: "@tervabot:localhost", displayName: "Terva Bot"}
	mentions := func(u id.UserID) *event.Mentions { return &event.Mentions{UserIDs: []id.UserID{u}} }
	bm := func(off, n int) connsdk.Entity { return connsdk.Entity{Kind: "bot_mention", Offset: off, Length: n} }

	for _, tc := range []struct {
		name string
		in   mentionInput
		bot  *botIdentity
		want []connsdk.Entity
	}{
		{"m.mentions locates the display name", mentionInput{text: "hey Terva Bot, deploy please", mentions: mentions(bot.userID)}, nil,
			[]connsdk.Entity{bm(4, 9)}},
		{"offsets are code points, not bytes", mentionInput{text: "héllo → @tervabot go", mentions: mentions(bot.userID)}, nil,
			[]connsdk.Entity{bm(8, 9)}},
		{"unlocatable is present at 0/0", mentionInput{text: "no textual trace here", mentions: mentions(bot.userID)}, nil,
			[]connsdk.Entity{bm(0, 0)}},
		{"a typed MXID wins over a localpart-shaped display name",
			mentionInput{text: "hey @tervabot:localhost go", mentions: mentions(bot.userID)},
			&botIdentity{userID: bot.userID, displayName: "tervabot"},
			[]connsdk.Entity{bm(4, 19)}},
		{"someone else's m.mentions is not a bot mention", mentionInput{text: "hey Terva Bot in name only", mentions: mentions("@other:localhost")}, nil,
			nil},
		{"legacy pill spans its anchor text",
			mentionInput{text: "Terva Bot: hi", html: `<a href="https://matrix.to/#/%40tervabot%3Alocalhost">Terva Bot</a>: hi`}, nil,
			[]connsdk.Entity{bm(0, 9)}},
		{"matrix: URI pill", mentionInput{text: "Terva Bot hello", html: `<a href='matrix:u/tervabot:localhost'>Terva Bot</a> hello`}, nil,
			[]connsdk.Entity{bm(0, 9)}},
		{"other users' pills become mentions, bot first",
			mentionInput{text: "ask drew and Terva Bot", html: `ask <a href="https://matrix.to/#/@drew:localhost">drew</a> and <a href="https://matrix.to/#/@tervabot:localhost">Terva Bot</a>`}, nil,
			[]connsdk.Entity{bm(13, 9), {Kind: "mention", Offset: 4, Length: 4, UserID: "@drew:localhost"}}},
		{"unlocatable plain mentions are dropped",
			mentionInput{text: "actual", html: `<mx-reply><blockquote><a href="https://matrix.to/#/@third:localhost">third</a> said x</blockquote></mx-reply>actual`}, nil,
			nil},
		{"a reply-fallback pill to the bot is a bot mention",
			mentionInput{text: "ok do it", html: `<mx-reply><blockquote><a href="https://matrix.to/#/@tervabot:localhost">Terva Bot</a> earlier</blockquote></mx-reply>ok do it`}, nil,
			[]connsdk.Entity{bm(0, 0)}},
		{"replied-to-bot alone is a mention", mentionInput{text: "sounds good", repliedToBot: true}, nil,
			[]connsdk.Entity{bm(0, 0)}},
		{"no signal, no entities", mentionInput{text: "just chatting about tervabot's uptime"}, nil,
			nil},
		{"duplicate pills dedupe",
			mentionInput{text: "drew drew", html: `<a href="https://matrix.to/#/@drew:localhost">drew</a> <a href="https://matrix.to/#/@drew:localhost">drew</a>`}, nil,
			[]connsdk.Entity{{Kind: "mention", Offset: 0, Length: 4, UserID: "@drew:localhost"}}},
		{"HTML entities in anchor text unescape",
			mentionInput{text: "ping A & B now", html: `<a href="https://matrix.to/#/@amp:localhost">A &amp; B</a>`}, nil,
			[]connsdk.Entity{{Kind: "mention", Offset: 5, Length: 5, UserID: "@amp:localhost"}}},
		{"non-user matrix.to links are ignored",
			mentionInput{text: "see the room", html: `see <a href="https://matrix.to/#/!room:localhost?via=x">the room</a>`}, nil,
			nil},
		{"@room alone is nothing", mentionInput{text: "@room deploy", mentions: &event.Mentions{Room: true}}, nil,
			nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bot
			if tc.bot != nil {
				b = *tc.bot
			}
			got := extractEntities(tc.in, b)
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestSentCacheBounded(t *testing.T) {
	var c sentCache
	for i := range sentCacheSize + 10 {
		c.add(fmt.Sprintf("$ev%d", i))
	}
	if c.has("$ev0") || c.has("$ev9") {
		t.Fatal("the oldest ids were not evicted")
	}
	if !c.has("$ev10") || !c.has(fmt.Sprintf("$ev%d", sentCacheSize+9)) {
		t.Fatal("the newest ids were evicted")
	}
	if c.has("") {
		t.Fatal("an empty id matched")
	}
}
