package connector

import (
	"html"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"
)

// Entities follow terva-conn-matrix's src/matrix/entities.rs: one
// bot_mention at most, from m.mentions, a pill, or a reply to the bot,
// located in the delivered text when it can be and 0/0 when it cannot;
// and a mention for every other user's pill whose text is in the body.
// Offsets and lengths are Unicode code points, as connproto requires.

// mentionInput is what extraction reads from one message.
type mentionInput struct {
	text         string // as delivered: reply fallback already stripped
	html         string // formatted_body when its format is HTML
	mentions     *event.Mentions
	repliedToBot bool
}

// botIdentity is what the bot can be called in a message.
type botIdentity struct {
	userID      id.UserID
	displayName string // global profile name; "" when unknown
}

type pill struct {
	user id.UserID
	text string
}

func extractEntities(in mentionInput, bot botIdentity) []connsdk.Entity {
	pills := findPills(in.html)
	var botPill string
	pilled := false
	for _, p := range pills {
		if p.user == bot.userID {
			pilled = true
			if botPill == "" {
				botPill = p.text
			}
		}
	}
	mentioned := in.mentions != nil && slices.Contains(in.mentions.UserIDs, bot.userID)

	var out []connsdk.Entity
	if mentioned || pilled || in.repliedToBot {
		e := connsdk.Entity{Kind: "bot_mention"}
		local, _, _ := bot.userID.Parse()
		// Display name after the id forms: Synapse defaults it to the
		// localpart, and trying it first anchors the span inside a typed
		// MXID one character short (terva-conn-matrix 0.5.0).
		for _, needle := range []string{botPill, bot.userID.String(), "@" + local, bot.displayName, local} {
			if off, n, ok := findSpan(in.text, needle); ok {
				e.Offset, e.Length = off, n
				break
			}
		}
		out = append(out, e)
	}
	for _, p := range pills {
		if p.user == bot.userID {
			continue
		}
		off, n, ok := findSpan(in.text, p.text)
		if !ok {
			continue
		}
		e := connsdk.Entity{Kind: "mention", Offset: off, Length: n, UserID: p.user.String()}
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

// findSpan returns the first occurrence of needle in text as code-point
// offset and length.
func findSpan(text, needle string) (offset, length int, ok bool) {
	if needle == "" {
		return 0, 0, false
	}
	i := strings.Index(text, needle)
	if i < 0 {
		return 0, 0, false
	}
	return utf8.RuneCountInString(text[:i]), utf8.RuneCountInString(needle), true
}

var (
	anchorRE = regexp.MustCompile(`(?is)<a\s[^>]*?href\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*>(.*?)</a\s*>`)
	tagRE    = regexp.MustCompile(`(?s)<[^>]*>`)
)

// findPills returns the user pills in an HTML body, in order. Pills in
// <mx-reply> count, as they do in terva-conn-matrix.
func findPills(body string) []pill {
	var out []pill
	for _, m := range anchorRE.FindAllStringSubmatch(body, -1) {
		href := m[1] + m[2]
		user, ok := pillTarget(html.UnescapeString(href))
		if !ok {
			continue
		}
		text := strings.TrimSpace(html.UnescapeString(tagRE.ReplaceAllString(m[3], "")))
		if text == "" {
			continue
		}
		out = append(out, pill{user: user, text: text})
	}
	return out
}

// pillTarget reads a user id from a matrix.to or matrix: URI.
func pillTarget(href string) (id.UserID, bool) {
	var raw string
	switch {
	case strings.HasPrefix(href, "https://matrix.to/#/"):
		dec, err := url.PathUnescape(strings.TrimPrefix(href, "https://matrix.to/#/"))
		if err != nil {
			return "", false
		}
		raw, _, _ = strings.Cut(dec, "?")
		raw, _, _ = strings.Cut(raw, "/")
	case strings.HasPrefix(href, "matrix:u/"):
		raw, _, _ = strings.Cut(strings.TrimPrefix(href, "matrix:u/"), "?")
		raw = "@" + raw
	default:
		return "", false
	}
	if !strings.HasPrefix(raw, "@") {
		return "", false
	}
	return id.UserID(raw), true
}

// sentCache remembers the last ids the bot sent, for reply-to-bot. It is
// in memory only, like terva-conn-matrix's: a reply to a message sent
// before a restart is not a mention.
type sentCache struct {
	mu  sync.Mutex
	ids []string
}

const sentCacheSize = 256

func (s *sentCache) add(evtID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ids) == sentCacheSize {
		s.ids = s.ids[1:]
	}
	s.ids = append(s.ids, evtID)
}

func (s *sentCache) has(evtID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return evtID != "" && slices.Contains(s.ids, evtID)
}
