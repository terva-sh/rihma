//go:build dogfood

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"image/color"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"terva.sh/rihma"
)

const (
	turn    = 3 * time.Minute // a model reply, tools included
	quiet   = 45 * time.Second
	askWait = 90 * time.Second
)

type result struct {
	row    int
	title  string
	status string // PASS, FAIL, SKIP, REVIEW
	detail string
}

// dogfood is one run's shared state.
type dogfood struct {
	o        options
	owner    *human
	stranger *human
	bot      *botProc
	botLog   string
	dm       id.RoomID
	group    id.RoomID // plain, admitted mention-only
	encGroup id.RoomID // encrypted, admitted mention-only, owner joined
	thread   id.EventID
	threadIn id.EventID // the owner's message in the thread
	passed   map[int]bool
	results  []result
}

func (d *dogfood) add(row int, title, status, detail string, args ...any) {
	if len(args) > 0 {
		detail = fmt.Sprintf(detail, args...)
	}
	d.results = append(d.results, result{row, title, status, detail})
	if status == "PASS" {
		d.passed[row] = true
	}
	fmt.Fprintf(os.Stderr, "row %d %s: %s %s\n", row, title, status, oneLine(detail))
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 160 {
		return string(r[:160]) + "…"
	}
	return s
}

func quote(evt *event.Event) string {
	if evt == nil {
		return "(nothing)"
	}
	return fmt.Sprintf("%q", strings.Join(strings.Fields(body(evt)), " "))
}

func contains(evt *event.Event, words ...string) bool {
	if evt == nil {
		return false
	}
	b := strings.ToLower(body(evt))
	for _, w := range words {
		if strings.Contains(b, strings.ToLower(w)) {
			return true
		}
	}
	return false
}

func run(o options) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := os.MkdirAll(o.stateDir, 0o700); err != nil {
		return err
	}
	d := &dogfood{o: o, passed: map[int]bool{}, botLog: filepath.Join(o.stateDir, "bot.log")}
	var err error
	if d.owner, err = login(ctx, o, o.owner, o.ownerPW); err != nil {
		return err
	}
	if d.stranger, err = login(ctx, o, o.stranger, o.strangerPW); err != nil {
		return err
	}

	if o.launch != "" {
		if o.pairing != "" {
			if err := setAside(o.pairing); err != nil {
				return err
			}
			defer restore(o.pairing)
		}
		if d.bot, err = startBot(o.launch, d.botLog); err != nil {
			return err
		}
		defer func() { d.bot.stop() }()
		time.Sleep(20 * time.Second) // run.sh may build; the connector connects
	}

	if d.dm, err = d.owner.room(ctx, "rihma dogfood", true, true, o.bot); err != nil {
		return err
	}
	if !d.owner.waitMember(ctx, d.dm, o.bot, event.MembershipJoin, 2*time.Minute) {
		return fmt.Errorf("the bot never joined the DM %s", d.dm)
	}

	want, skip := rowSet(o.rows), rowSet(o.skip)
	for _, r := range rows {
		if len(want) > 0 && !want[r.n] || skip[r.n] {
			continue
		}
		d.settle(ctx)
		r.fn(ctx, d)
	}
	return d.write()
}

func rowSet(list string) map[int]bool {
	set := map[int]bool{}
	for _, f := range strings.Split(list, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil {
			set[n] = true
		}
	}
	return set
}

type row struct {
	n  int
	fn func(context.Context, *dogfood)
}

var rows = []row{
	{1, rowPair}, {2, rowRoundTrip}, {3, rowMarkdown}, {4, rowReply}, {6, rowStatus},
	{7, rowDowntime}, {8, rowCrash}, {9, rowEncrypted}, {11, rowSkip(11, "Unable-to-decrypt", "needs the human to lose keys on a fresh login; left to a person")},
	{12, rowInvite}, {13, rowSkip(13, "Cold addressing", "needs a restart before any DM in the host run; left to a person")},
	{14, rowApprove}, {15, rowMentionGate}, {16, rowOutsider}, {17, rowKick}, {18, rowEncryptedGroup},
	{19, rowEditBeforePickup}, {20, rowEditAfter}, {21, rowDeleteQueued}, {22, rowReactionNote}, {23, rowNoEcho},
	{24, rowSkip(24, "Bot-originated events", "the host has no caller for outbound edit, react, or delete; the live suite pins them")},
	{25, rowImage}, {26, rowFile}, {27, rowOversize},
	{28, rowApproval}, {29, rowDeny}, {30, rowExpiry}, {31, rowAlways}, {32, rowImposter}, {33, rowAgentQuestion},
	{34, rowThreadIn}, {35, rowThreadEvents}, {36, rowThreadRestart},
	{37, rowStatusCmd}, {38, rowSealed}, {39, rowSkip(39, "Reset", "logs the bot out and removes its state; run by hand at the very end")},
}

func rowSkip(n int, title, why string) func(context.Context, *dogfood) {
	return func(_ context.Context, d *dogfood) { d.add(n, title, "SKIP", why) }
}

// ask sends prompt to the owner's DM and returns the bot's reply.
func (d *dogfood) ask(ctx context.Context, room id.RoomID, h *human, c *event.MessageEventContent) (*event.Event, bool) {
	from := h.mark()
	if _, err := h.say(ctx, room, c); err != nil {
		return nil, false
	}
	return h.reply(ctx, from, room, turn)
}

func rowPair(ctx context.Context, d *dogfood) {
	if d.o.pairing == "" {
		d.add(1, "Pair", "SKIP", "no -pairing: the owner was not given the claim, so this row assumes it is already paired")
		return
	}
	evt, ok := d.ask(ctx, d.dm, d.owner, text("/start"))
	if !ok {
		d.add(1, "Pair", "FAIL", "no answer to /start within %s", turn)
		return
	}
	d.add(1, "Pair", "PASS", "claimed; the bot answered %s", quote(evt))
}

func rowRoundTrip(ctx context.Context, d *dogfood) {
	from := d.owner.mark()
	start := time.Now()
	if _, err := d.owner.say(ctx, d.dm, text("Reply with exactly the word: pong")); err != nil {
		d.add(2, "Round trip", "FAIL", "send: %v", err)
		return
	}
	evt, ok := d.owner.reply(ctx, from, d.dm, turn)
	if !ok {
		d.add(2, "Round trip", "FAIL", "no reply within %s", turn)
		return
	}
	status := "PASS"
	if !contains(evt, "pong") {
		status = "REVIEW"
	}
	d.add(2, "Round trip", status, "reply %s", quote(evt))

	// Row 5 rides this turn: typing shown during it, cleared after it.
	d.owner.mu.Lock()
	typed := d.owner.typedAt[d.dm]
	d.owner.mu.Unlock()
	deadline := time.Now().Add(15 * time.Second)
	cleared := false
	for time.Now().Before(deadline) {
		d.owner.mu.Lock()
		on := d.owner.typing[d.dm]
		d.owner.mu.Unlock()
		if !on {
			cleared = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	switch {
	case typed.Before(start):
		d.add(5, "Typing", "FAIL", "the bot was never seen typing during the turn")
	case !cleared:
		d.add(5, "Typing", "FAIL", "typing still shown 15 s after the reply")
	default:
		d.add(5, "Typing", "PASS", "typing shown during the turn and cleared after the reply")
	}
}

func rowMarkdown(ctx context.Context, d *dogfood) {
	evt, ok := d.ask(ctx, d.dm, d.owner, text("Reply with a bulleted list of two fruits, then a fenced code block containing `echo hi`."))
	if !ok {
		d.add(3, "Markdown", "FAIL", "no reply")
		return
	}
	html := evt.Content.AsMessage().FormattedBody
	if strings.Contains(html, "<li>") && strings.Contains(html, "<code") {
		d.add(3, "Markdown", "PASS", "formatted_body has a list and code; how Element draws it still wants eyes")
		return
	}
	d.add(3, "Markdown", "REVIEW", "formatted_body lacks a list or code: %q", oneLine(html))
}

func rowReply(ctx context.Context, d *dogfood) {
	target, ok := d.ask(ctx, d.dm, d.owner, text("Reply with exactly the word: anchor"))
	if !ok {
		d.add(4, "Reply mapping", "FAIL", "no first reply")
		return
	}
	c := text("What single word did you send in the message I am replying to?")
	c.RelatesTo = (&event.RelatesTo{}).SetReplyTo(target.ID)
	evt, ok := d.ask(ctx, d.dm, d.owner, c)
	switch {
	case !ok:
		d.add(4, "Reply mapping", "FAIL", "no answer to the reply")
	case contains(evt, "anchor"):
		d.add(4, "Reply mapping", "PASS", "answer %s", quote(evt))
	default:
		d.add(4, "Reply mapping", "REVIEW", "answer %s", quote(evt))
	}
}

func rowStatus(ctx context.Context, d *dogfood) {
	// Element sends a /command it does not know with the slash escaped,
	// as Markdown: body \/status. Both forms must reach the built-in.
	for _, form := range []string{"/status", `\/status`} {
		from := d.owner.mark()
		sent, err := d.owner.say(ctx, d.dm, text(form))
		if err != nil {
			d.add(6, "Built-ins", "FAIL", "send %s: %v", form, err)
			return
		}
		evt, ok := d.owner.next(ctx, from, d.dm, time.Minute, repliesTo(sent))
		if !ok {
			d.add(6, "Built-ins", "FAIL", "no answer to %s within a minute", form)
			return
		}
		if keys := d.owner.seeds(ctx, d.dm, evt.ID); len(keys) > 0 {
			d.add(6, "Built-ins", "FAIL", "%s went through an approval ask (%v), so the built-in did not fire", form, keys)
			return
		}
		d.settle(ctx)
	}
	d.add(6, "Built-ins", "PASS", "/status and Element's escaped \\/status both answered by the built-in; /stop not driven")
}

// repliesTo accepts the bot message that replies to sent, which is how
// the host answers a built-in.
func repliesTo(sent id.EventID) func(*event.MessageEventContent, *event.Event) bool {
	return func(c *event.MessageEventContent, _ *event.Event) bool {
		return sent != "" && c.RelatesTo.GetReplyTo() == sent
	}
}

func rowDowntime(ctx context.Context, d *dogfood) {
	if d.bot == nil {
		d.add(7, "Downtime recovery", "SKIP", "needs -launch")
		return
	}
	d.bot.stop()
	from := d.owner.mark()
	if _, err := d.owner.say(ctx, d.dm, text("Sent while you were down: reply with exactly the word kiwi")); err != nil {
		d.add(7, "Downtime recovery", "FAIL", "send: %v", err)
		return
	}
	time.Sleep(5 * time.Second)
	var err error
	if d.bot, err = startBot(d.o.launch, d.botLog); err != nil {
		d.add(7, "Downtime recovery", "FAIL", "restart: %v", err)
		return
	}
	evt, ok := d.owner.reply(ctx, from, d.dm, turn)
	switch {
	case !ok:
		d.add(7, "Downtime recovery", "FAIL", "the message sent while down never became a turn")
	case contains(evt, "kiwi"):
		d.add(7, "Downtime recovery", "PASS", "answered after restart: %s", quote(evt))
		d.add(10, "Encrypted downtime", "PASS", "row 7 ran in the encrypted DM")
	default:
		d.add(7, "Downtime recovery", "REVIEW", "answered after restart: %s", quote(evt))
	}
}

func rowCrash(ctx context.Context, d *dogfood) {
	if d.bot == nil {
		d.add(8, "Crash recovery", "SKIP", "needs -launch")
		return
	}
	pid := d.bot.connectorPID()
	if pid == 0 {
		d.add(8, "Crash recovery", "FAIL", "no terva-rihma process under the launched bot")
		return
	}
	before := d.owner.mark()
	_ = exec.Command("kill", "-9", strconv.Itoa(pid)).Run()
	time.Sleep(15 * time.Second)
	evt, ok := d.ask(ctx, d.dm, d.owner, text("After the crash: reply with exactly the word plum"))
	if !ok {
		d.add(8, "Crash recovery", "FAIL", "no reply after killing terva-rihma %d", pid)
		return
	}
	// Nothing delivered twice: no second kiwi answer arrived.
	dup, _ := d.owner.next(ctx, before, d.dm, time.Second, func(c *event.MessageEventContent, _ *event.Event) bool {
		return strings.Contains(strings.ToLower(c.Body), "kiwi")
	})
	status := "PASS"
	if dup != nil || !contains(evt, "plum") {
		status = "REVIEW"
	}
	d.add(8, "Crash recovery", status, "killed terva-rihma %d; then %s; repeated kiwi answer: %v", pid, quote(evt), dup != nil)
}

func rowEncrypted(ctx context.Context, d *dogfood) {
	d.owner.mu.Lock()
	var plain, total int
	for _, evt := range d.owner.msgs {
		if evt.RoomID == d.dm {
			total++
			if !evt.Mautrix.WasEncrypted {
				plain++
			}
		}
	}
	d.owner.mu.Unlock()
	if total > 0 && plain == 0 {
		d.add(9, "Encrypted DM", "PASS", "all %d bot messages in the DM arrived encrypted; Element's shields want eyes", total)
		return
	}
	if total == 0 {
		d.add(9, "Encrypted DM", "SKIP", "no bot messages in the DM to check; run it after the chat rows")
		return
	}
	d.add(9, "Encrypted DM", "FAIL", "%d of %d bot messages arrived unencrypted", plain, total)
}

// admission waits for the admission ask in the owner's DM.
func (d *dogfood) admission(ctx context.Context, from int) (*event.Event, []string, bool) {
	return d.owner.ask(ctx, from, d.dm, askWait)
}

func rowInvite(ctx context.Context, d *dogfood) {
	from := d.owner.mark()
	var err error
	if d.group, err = d.stranger.room(ctx, "rihma dogfood group", false, false, d.o.bot); err != nil {
		d.add(12, "Invite → admission ask", "FAIL", "create: %v", err)
		return
	}
	if !d.stranger.waitMember(ctx, d.group, d.o.bot, event.MembershipJoin, time.Minute) {
		d.add(12, "Invite → admission ask", "FAIL", "the bot never joined")
		return
	}
	evt, keys, ok := d.admission(ctx, from)
	if !ok {
		d.add(12, "Invite → admission ask", "FAIL", "no admission ask in the owner's DM")
		return
	}
	d.add(12, "Invite → admission ask", "PASS", "seeds %v on %s", keys, quote(evt))
}

func rowApprove(ctx context.Context, d *dogfood) {
	if d.group == "" {
		d.add(14, "Approve", "SKIP", "row 12 made no group")
		return
	}
	askMsg, ok := d.owner.next(ctx, 0, d.dm, time.Second, func(c *event.MessageEventContent, _ *event.Event) bool {
		return strings.Contains(c.Body, "Approve (mention-only)")
	})
	if !ok {
		d.add(14, "Approve", "FAIL", "no admission ask to answer")
		return
	}
	gFrom := d.stranger.mark()
	d.stranger.say(ctx, d.group, mention(d.o.bot, "what is 2+2? Answer with just the number."))
	d.stranger.say(ctx, d.group, text("a plain line that must not be replayed"))
	time.Sleep(3 * time.Second)
	from := d.owner.mark()
	if _, err := d.owner.SendReaction(ctx, d.dm, askMsg.ID, "①"); err != nil {
		d.add(14, "Approve", "FAIL", "tap: %v", err)
		return
	}
	out, outOK := d.owner.outcome(ctx, from, askMsg.ID, askWait)
	evt, ok := d.stranger.reply(ctx, gFrom, d.group, turn)
	switch {
	case !outOK:
		d.add(14, "Approve", "FAIL", "no outcome rendered into the ask")
	case !ok:
		d.add(14, "Approve", "FAIL", "outcome %q, but the held mention was never answered", oneLine(out))
	case contains(evt, "4", "four"):
		d.add(14, "Approve", "PASS", "outcome %q; the held mention answered %s", oneLine(out), quote(evt))
	default:
		d.add(14, "Approve", "REVIEW", "outcome %q; the group got %s", oneLine(out), quote(evt))
	}
}

func rowMentionGate(ctx context.Context, d *dogfood) {
	if d.group == "" {
		d.add(15, "Mention gate", "SKIP", "no admitted group")
		return
	}
	from := d.stranger.mark()
	d.stranger.say(ctx, d.group, text("just chatting, reply with the word nope if you see this"))
	if !d.stranger.silent(ctx, from, d.group, quiet) {
		d.add(15, "Mention gate", "FAIL", "the bot answered a plain group message")
		return
	}
	evt, ok := d.ask(ctx, d.group, d.stranger, mention(d.o.bot, "reply with exactly the word fig"))
	switch {
	case !ok:
		d.add(15, "Mention gate", "FAIL", "a mention got no answer")
	case contains(evt, "fig"):
		d.add(15, "Mention gate", "PASS", "plain ignored; mention answered %s", quote(evt))
	default:
		d.add(15, "Mention gate", "REVIEW", "plain ignored; mention answered %s", quote(evt))
	}
}

func rowOutsider(ctx context.Context, d *dogfood) {
	if d.group == "" || !d.passed[15] {
		d.add(16, "Outsider", "SKIP", "row 15 did not pass")
		return
	}
	from := d.stranger.mark()
	a, _ := d.stranger.say(ctx, d.group, mention(d.o.bot, "/status"))
	b, _ := d.stranger.say(ctx, d.group, text("/status"))
	if _, got := d.stranger.next(ctx, from, d.group, quiet, func(c *event.MessageEventContent, evt *event.Event) bool {
		return repliesTo(a)(c, evt) || repliesTo(b)(c, evt) || strings.HasPrefix(c.Body, "(")
	}); got {
		d.add(16, "Outsider", "FAIL", "the outsider got /status output")
		return
	}
	d.add(16, "Outsider", "PASS", "the outsider's mention was answered (row 15); its /status got no status output")
}

func rowKick(ctx context.Context, d *dogfood) {
	if d.group == "" {
		d.add(17, "Kick", "SKIP", "no group")
		return
	}
	if _, err := d.stranger.KickUser(ctx, d.group, &mautrix.ReqKickUser{UserID: d.o.bot, Reason: "dogfood row 17"}); err != nil {
		d.add(17, "Kick", "FAIL", "kick: %v", err)
		return
	}
	time.Sleep(5 * time.Second)
	from := d.owner.mark()
	if _, err := d.stranger.InviteUser(ctx, d.group, &mautrix.ReqInviteUser{UserID: d.o.bot}); err != nil {
		d.add(17, "Kick", "FAIL", "re-invite: %v", err)
		return
	}
	evt, keys, ok := d.admission(ctx, from)
	if !ok {
		d.add(17, "Kick", "FAIL", "re-invite after the kick raised no admission ask")
		return
	}
	d.owner.SendReaction(ctx, d.dm, evt.ID, "③")
	d.add(17, "Kick", "PASS", "kicked; the re-invite ran admission again (seeds %v), answered Ignore", keys)
}

func rowEncryptedGroup(ctx context.Context, d *dogfood) {
	from := d.owner.mark()
	var err error
	if d.encGroup, err = d.stranger.room(ctx, "rihma dogfood encrypted group", true, false, d.o.bot, d.o.owner); err != nil {
		d.add(18, "Encrypted group", "FAIL", "create: %v", err)
		return
	}
	if _, err := d.owner.JoinRoomByID(ctx, d.encGroup); err != nil {
		d.add(18, "Encrypted group", "FAIL", "owner join: %v", err)
		return
	}
	askMsg, _, ok := d.admission(ctx, from)
	if !ok {
		d.add(18, "Encrypted group", "FAIL", "no admission ask")
		return
	}
	d.owner.SendReaction(ctx, d.dm, askMsg.ID, "①")
	time.Sleep(5 * time.Second)
	evt, ok := d.ask(ctx, d.encGroup, d.stranger, mention(d.o.bot, "reply with exactly the word lime"))
	switch {
	case !ok:
		d.add(18, "Encrypted group", "FAIL", "the mention got no answer")
	case !evt.Mautrix.WasEncrypted:
		d.add(18, "Encrypted group", "FAIL", "the answer arrived unencrypted")
	case contains(evt, "lime"):
		d.add(18, "Encrypted group", "PASS", "admitted; mention answered encrypted %s", quote(evt))
	default:
		d.add(18, "Encrypted group", "REVIEW", "admitted; mention answered encrypted %s", quote(evt))
	}
}

func rowEditBeforePickup(ctx context.Context, d *dogfood) {
	from := d.owner.mark()
	d.owner.say(ctx, d.dm, text("Write a 200-word paragraph about rivers."))
	queued, err := d.owner.say(ctx, d.dm, text("Reply with only the color red."))
	if err != nil {
		d.add(19, "Edit before pickup", "FAIL", "send: %v", err)
		return
	}
	edit := text("* Reply with only the color blue.")
	edit.NewContent = text("Reply with only the color blue.")
	edit.RelatesTo = (&event.RelatesTo{}).SetReplace(queued)
	d.owner.say(ctx, d.dm, edit)
	evt, ok := d.owner.next(ctx, from, d.dm, 2*turn, func(c *event.MessageEventContent, _ *event.Event) bool {
		b := strings.ToLower(c.Body)
		return len(b) < 80 && (strings.Contains(b, "blue") || strings.Contains(b, "red"))
	})
	switch {
	case !ok:
		d.add(19, "Edit before pickup", "REVIEW", "no short color answer found; read the transcript")
	case contains(evt, "blue"):
		d.add(19, "Edit before pickup", "PASS", "answered the edited text: %s", quote(evt))
	default:
		d.add(19, "Edit before pickup", "FAIL", "answered the original text: %s", quote(evt))
	}
}

func rowEditAfter(ctx context.Context, d *dogfood) {
	first, ok := d.ask(ctx, d.dm, d.owner, text("Reply with exactly the word cedar."))
	if !ok {
		d.add(20, "Edit after", "FAIL", "no first answer")
		return
	}
	orig := d.lastOwn(ctx, first)
	edit := text("* Reply with exactly the word birch.")
	edit.NewContent = text("Reply with exactly the word birch.")
	edit.RelatesTo = (&event.RelatesTo{}).SetReplace(orig)
	d.owner.say(ctx, d.dm, edit)
	time.Sleep(3 * time.Second)
	evt, ok := d.ask(ctx, d.dm, d.owner, text("Did I edit one of my earlier messages? If so, quote its new text."))
	switch {
	case !ok:
		d.add(20, "Edit after", "FAIL", "no answer")
	case contains(evt, "birch"):
		d.add(20, "Edit after", "PASS", "the agent saw the edit: %s", quote(evt))
	default:
		d.add(20, "Edit after", "REVIEW", "answer %s", quote(evt))
	}
}

// lastOwn is the owner's message the reply answered: the newest owner
// message in the DM before it.
func (d *dogfood) lastOwn(ctx context.Context, reply *event.Event) id.EventID {
	resp, err := d.owner.Messages(ctx, d.dm, "", "", 'b', nil, 20)
	if err != nil {
		return ""
	}
	for _, evt := range resp.Chunk {
		if evt.Sender == d.o.owner && evt.Timestamp < reply.Timestamp && (evt.Type == event.EventMessage || evt.Type == event.EventEncrypted) {
			return evt.ID
		}
	}
	return ""
}

func rowDeleteQueued(ctx context.Context, d *dogfood) {
	from := d.owner.mark()
	d.owner.say(ctx, d.dm, text("Write a 200-word paragraph about mountains."))
	queued, err := d.owner.say(ctx, d.dm, text("Reply with only the word giraffe."))
	if err != nil {
		d.add(21, "Delete queued", "FAIL", "send: %v", err)
		return
	}
	d.owner.RedactEvent(ctx, d.dm, queued)
	if evt, got := d.owner.next(ctx, from, d.dm, 2*turn, func(c *event.MessageEventContent, _ *event.Event) bool {
		return strings.Contains(strings.ToLower(c.Body), "giraffe")
	}); got {
		d.add(21, "Delete queued", "FAIL", "the deleted message became a turn: %s", quote(evt))
		return
	}
	d.add(21, "Delete queued", "PASS", "no giraffe in %s", 2*turn)
}

func rowReactionNote(ctx context.Context, d *dogfood) {
	target, ok := d.ask(ctx, d.dm, d.owner, text("Reply with exactly the word ember."))
	if !ok {
		d.add(22, "Reaction as note", "FAIL", "no target message")
		return
	}
	r, err := d.owner.SendReaction(ctx, d.dm, target.ID, "👀")
	if err != nil {
		d.add(22, "Reaction as note", "FAIL", "react: %v", err)
		return
	}
	time.Sleep(3 * time.Second)
	seen, _ := d.ask(ctx, d.dm, d.owner, text("Did I react to one of your messages? Which emoji?"))
	d.owner.RedactEvent(ctx, d.dm, r.EventID)
	time.Sleep(3 * time.Second)
	gone, _ := d.ask(ctx, d.dm, d.owner, text("Is that reaction still there?"))
	status := "REVIEW"
	if contains(seen, "👀", "eyes") {
		status = "PASS"
	}
	d.add(22, "Reaction as note", status, "after 👀: %s; after removing it: %s", quote(seen), quote(gone))
}

func rowNoEcho(ctx context.Context, d *dogfood) {
	evt, ok := d.ask(ctx, d.dm, d.owner, text("List every chat event (reactions, edits, deletions) you have been told about in this chat, with who did it."))
	if !ok {
		d.add(23, "No bot echo", "FAIL", "no answer")
		return
	}
	d.add(23, "No bot echo", "REVIEW", "none of these may be the bot's own seeds, withdrawals, or outcome edits: %s", quote(evt))
}

func rowImage(ctx context.Context, d *dogfood) {
	from := d.owner.mark()
	_, err := d.owner.SendMedia(ctx, d.dm, rihma.Media{Data: colorPNG(color.RGBA{R: 220, A: 255}), Name: "swatch.png", MimeType: "image/png",
		MsgType: event.MsgImage, Caption: "What color is this image? Answer with one word."})
	if err != nil {
		d.add(25, "Inbound image", "FAIL", "send: %v", err)
		return
	}
	evt, ok := d.owner.reply(ctx, from, d.dm, turn)
	switch {
	case !ok:
		d.add(25, "Inbound image", "FAIL", "no answer")
	case contains(evt, "red"):
		d.add(25, "Inbound image", "PASS", "the model saw it: %s", quote(evt))
	default:
		d.add(25, "Inbound image", "REVIEW", "answer %s (the model may not take images)", quote(evt))
	}
}

func rowFile(ctx context.Context, d *dogfood) {
	from := d.owner.mark()
	_, err := d.owner.SendMedia(ctx, d.dm, rihma.Media{Data: []byte("The secret word is pumpkin.\n"), Name: "notes.txt", MimeType: "text/plain",
		MsgType: event.MsgFile, Caption: "What is the secret word in this file?"})
	if err != nil {
		d.add(26, "Inbound file", "FAIL", "send: %v", err)
		return
	}
	evt, ok := d.owner.reply(ctx, from, d.dm, turn)
	// Reading the staged file is a tool call, so the host may ask first.
	if ok && len(d.owner.seeds(ctx, d.dm, evt.ID)) > 0 {
		next := d.owner.indexOf(evt.ID) + 1
		d.owner.SendReaction(ctx, d.dm, evt.ID, "👍")
		evt, ok = d.owner.next(ctx, next, d.dm, turn, func(_ *event.MessageEventContent, e *event.Event) bool {
			return e.Content.AsMessage().RelatesTo.GetReplaceID() == "" && len(d.owner.seeds(ctx, d.dm, e.ID)) == 0
		})
	}
	switch {
	case !ok:
		d.add(26, "Inbound file", "FAIL", "no answer")
	case contains(evt, "pumpkin"):
		d.add(26, "Inbound file", "PASS", "read it: %s", quote(evt))
	default:
		d.add(26, "Inbound file", "REVIEW", "answer %s", quote(evt))
	}
}

func rowOversize(ctx context.Context, d *dogfood) {
	if d.bot == nil || d.o.config == "" || d.o.connectorLog == "" {
		d.add(27, "Oversize", "SKIP", "needs -launch, -config (or -pairing), and -connector-log")
		return
	}
	cfgPath := d.o.config
	prev, err := setLimit(cfgPath, 1)
	if err != nil {
		d.add(27, "Oversize", "FAIL", "config: %v", err)
		return
	}
	defer func() {
		d.bot.stop()
		_, _ = setLimit(cfgPath, prev)
		d.bot, _ = startBot(d.o.launch, d.botLog)
		time.Sleep(20 * time.Second)
	}()
	d.bot.stop()
	if d.bot, err = startBot(d.o.launch, d.botLog); err != nil {
		d.add(27, "Oversize", "FAIL", "restart: %v", err)
		return
	}
	time.Sleep(20 * time.Second)
	logBefore, _ := os.ReadFile(d.o.connectorLog)
	from := d.owner.mark()
	if _, err := d.owner.SendMedia(ctx, d.dm, rihma.Media{Data: make([]byte, 3<<19), Name: "big.bin", MimeType: "application/octet-stream",
		MsgType: event.MsgFile, Caption: "reply with exactly the word oak"}); err != nil {
		d.add(27, "Oversize", "FAIL", "send: %v", err)
		return
	}
	silent := d.owner.silent(ctx, from, d.dm, quiet)
	logAfter, _ := os.ReadFile(d.o.connectorLog)
	dropped := strings.Contains(string(logAfter[min(len(logBefore), len(logAfter)):]), "dropping attachment")
	if silent && dropped {
		d.add(27, "Oversize", "PASS", "1.5 MiB over a 1 MiB limit: dropped with a warning, no turn")
		return
	}
	d.add(27, "Oversize", "FAIL", "silent %v, warning logged %v", silent, dropped)
}

// setLimit sets max_attachment_mb (0 removes it) and returns the old one.
func setLimit(path string, mb int) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return 0, err
	}
	prev, _ := cfg["max_attachment_mb"].(float64)
	if mb == 0 {
		delete(cfg, "max_attachment_mb")
	} else {
		cfg["max_attachment_mb"] = mb
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return 0, err
	}
	return int(prev), os.WriteFile(path, out, 0o600)
}

// approval asks the agent to run a shell command and returns the
// approval ask.
func (d *dogfood) approval(ctx context.Context, room id.RoomID, h *human, c *event.MessageEventContent) (int, *event.Event, []string, bool) {
	return d.seeded(ctx, room, h, c, true)
}

// seeded sends c and waits for an ask in room: a tool approval when
// approval is set, and an agent's own question otherwise. Asks of the
// other kind, left over from an earlier row, are passed over.
func (d *dogfood) seeded(ctx context.Context, room id.RoomID, h *human, c *event.MessageEventContent, approval bool) (int, *event.Event, []string, bool) {
	from := h.mark()
	if _, err := h.say(ctx, room, c); err != nil {
		return from, nil, nil, false
	}
	deadline := time.Now().Add(turn)
	for next := from; time.Now().Before(deadline); {
		evt, keys, ok := h.ask(ctx, next, room, time.Until(deadline))
		if !ok {
			break
		}
		if strings.HasPrefix(body(evt), "approval needed") == approval {
			return from, evt, keys, true
		}
		next = h.indexOf(evt.ID) + 1
	}
	return from, nil, nil, false
}

// settle waits until the bot has been quiet for a while, so one row's
// late messages are not read as the next row's answers.
func (d *dogfood) settle(ctx context.Context) {
	const still = 20 * time.Second
	deadline := time.Now().Add(5 * time.Minute)
	last, quietSince := -1, time.Now()
	for time.Now().Before(deadline) && ctx.Err() == nil {
		n := d.owner.mark() + d.stranger.mark()
		if n != last {
			last, quietSince = n, time.Now()
		} else if time.Since(quietSince) >= still {
			return
		}
		time.Sleep(time.Second)
	}
}

const runDate = "Use your shell tool to run the command `date`, then tell me the year it printed."

func rowApproval(ctx context.Context, d *dogfood) {
	from, askMsg, keys, ok := d.approval(ctx, d.dm, d.owner, text(runDate))
	if !ok {
		d.add(28, "Approval widget", "FAIL", "no approval ask")
		return
	}
	d.owner.SendReaction(ctx, d.dm, askMsg.ID, "👍")
	out, _ := d.owner.outcome(ctx, from, askMsg.ID, askWait)
	evt, _ := d.owner.reply(ctx, d.owner.indexOf(askMsg.ID)+1, d.dm, turn)
	time.Sleep(3 * time.Second)
	left := d.owner.seeds(ctx, d.dm, askMsg.ID)
	switch {
	case !strings.Contains(out, "Approve"):
		d.add(28, "Approval widget", "FAIL", "seeds %v; outcome %q", keys, oneLine(out))
	case len(left) > 0:
		d.add(28, "Approval widget", "FAIL", "outcome %q but seeds %v were not withdrawn", oneLine(out), left)
	case regexp.MustCompile(`20\d\d`).MatchString(body(orEmpty(evt))):
		d.add(28, "Approval widget", "PASS", "seeds %v; outcome %q; the tool ran: %s", keys, oneLine(out), quote(evt))
	default:
		d.add(28, "Approval widget", "REVIEW", "seeds %v; outcome %q; then %s", keys, oneLine(out), quote(evt))
	}
}

func orEmpty(evt *event.Event) *event.Event {
	if evt == nil {
		return &event.Event{Content: event.Content{Parsed: &event.MessageEventContent{}}}
	}
	return evt
}

func rowDeny(ctx context.Context, d *dogfood) {
	from, askMsg, _, ok := d.approval(ctx, d.dm, d.owner, text(runDate))
	if !ok {
		d.add(29, "Deny", "FAIL", "no approval ask")
		return
	}
	d.owner.SendReaction(ctx, d.dm, askMsg.ID, "👎")
	out, _ := d.owner.outcome(ctx, from, askMsg.ID, askWait)
	evt, _ := d.owner.reply(ctx, d.owner.indexOf(askMsg.ID)+1, d.dm, turn)
	if strings.Contains(out, "Deny") {
		d.add(29, "Deny", "PASS", "outcome %q; the agent said %s", oneLine(out), quote(evt))
		return
	}
	d.add(29, "Deny", "FAIL", "outcome %q", oneLine(out))
}

func rowExpiry(ctx context.Context, d *dogfood) {
	_, askMsg, keys, ok := d.approval(ctx, d.dm, d.owner, text(runDate))
	if !ok {
		d.add(30, "Expiry", "FAIL", "no approval ask")
		return
	}
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if len(d.owner.seeds(ctx, d.dm, askMsg.ID)) == 0 {
			evt, _ := d.owner.reply(ctx, d.owner.indexOf(askMsg.ID)+1, d.dm, turn)
			d.add(30, "Expiry", "PASS", "seeds %v withdrew themselves; the agent said %s", keys, quote(evt))
			return
		}
		time.Sleep(5 * time.Second)
	}
	d.add(30, "Expiry", "FAIL", "seeds %v still there after 3 minutes", keys)
}

func rowAlways(ctx context.Context, d *dogfood) {
	if !d.o.allowAlways {
		d.add(31, "Attestation", "SKIP", "leaves a durable tool grant in terva; run with -allow-always to include it")
		return
	}
	from, askMsg, keys, ok := d.approval(ctx, d.dm, d.owner, text(runDate))
	if !ok || !slices.Contains(keys, "①") {
		d.add(31, "Attestation", "FAIL", "no approval ask with an Always option (seeds %v)", keys)
		return
	}
	d.owner.SendReaction(ctx, d.dm, askMsg.ID, "①")
	out, _ := d.owner.outcome(ctx, from, askMsg.ID, askWait)
	_, _, _, asked := d.approval(ctx, d.dm, d.owner, text(runDate))
	if asked {
		d.add(31, "Attestation", "FAIL", "outcome %q, but the next call asked again", oneLine(out))
		return
	}
	d.add(31, "Attestation", "PASS", "outcome %q; the next call ran without asking", oneLine(out))
}

// rowImposter checks the owner-only approval path for a group turn. The
// host asks approvals for a turn that did not start in a DM in the
// owner's DM (chat.Loop.AskTarget), so an outsider never sees one to tap.
func rowImposter(ctx context.Context, d *dogfood) {
	if d.encGroup == "" {
		d.add(32, "Imposter", "SKIP", "row 18 made no group with the owner in it")
		return
	}
	ownerFrom, groupFrom := d.owner.mark(), d.stranger.mark()
	if _, err := d.stranger.say(ctx, d.encGroup, mention(d.o.bot, runDate)); err != nil {
		d.add(32, "Imposter", "FAIL", "send: %v", err)
		return
	}
	var askMsg *event.Event
	deadline := time.Now().Add(turn)
	for next := ownerFrom; time.Now().Before(deadline); {
		evt, _, ok := d.owner.ask(ctx, next, d.dm, time.Until(deadline))
		if !ok {
			break
		}
		if strings.HasPrefix(body(evt), "approval needed") {
			askMsg = evt
			break
		}
		next = d.owner.indexOf(evt.ID) + 1
	}
	if askMsg == nil {
		d.add(32, "Imposter", "FAIL", "the outsider's tool call raised no approval in the owner's DM")
		return
	}
	if inGroup, _ := d.stranger.next(ctx, groupFrom, d.encGroup, time.Second, func(c *event.MessageEventContent, _ *event.Event) bool {
		return strings.HasPrefix(c.Body, "approval needed")
	}); inGroup != nil {
		d.add(32, "Imposter", "FAIL", "an approval was posted in the group, where the outsider can tap it")
		return
	}
	d.owner.SendReaction(ctx, d.dm, askMsg.ID, "👎")
	out, ok := d.owner.outcome(ctx, ownerFrom, askMsg.ID, askWait)
	if ok && strings.Contains(out, "Deny") {
		d.add(32, "Imposter", "PASS", "the group turn's approval went only to the owner's DM; the owner's tap closed it: %q", oneLine(out))
		return
	}
	d.add(32, "Imposter", "FAIL", "after the owner's tap: %q", oneLine(out))
}

func rowAgentQuestion(ctx context.Context, d *dogfood) {
	from, askMsg, keys, ok := d.seeded(ctx, d.dm, d.owner, text("Use your ask tool to ask me a multiple-choice question with exactly three options."), false)
	if !ok {
		d.add(33, "Agent question", "REVIEW", "no seeded question arrived; the model may have asked in plain text")
		return
	}
	d.owner.SendReaction(ctx, d.dm, askMsg.ID, keys[0])
	out, _ := d.owner.outcome(ctx, from, askMsg.ID, askWait)
	// A free-text question has no widget: the host sends it as numbered
	// plain text and takes the next message as the answer.
	freeFrom := d.owner.mark()
	d.owner.say(ctx, d.dm, text("Now use your ask tool to ask me a free-text question."))
	free, _ := d.owner.next(ctx, freeFrom, d.dm, turn, func(c *event.MessageEventContent, _ *event.Event) bool {
		return strings.Contains(c.Body, "write your own answer")
	})
	freeSeeds := []string{}
	if free != nil {
		freeSeeds = d.owner.seeds(ctx, d.dm, free.ID)
		// Answer it, or the agent's turn stays blocked on the question.
		d.owner.say(ctx, d.dm, text("blue"))
	}
	status := "PASS"
	if len(keys) != 3 || free == nil || len(freeSeeds) > 0 {
		status = "REVIEW"
	}
	d.add(33, "Agent question", status, "seeds %v, answered %s, outcome %q; free-text came as %s with seeds %v", keys, keys[0], oneLine(out), quote(free), freeSeeds)
}

func rowThreadIn(ctx context.Context, d *dogfood) {
	root, ok := d.ask(ctx, d.dm, d.owner, text("Reply with exactly the word root."))
	if !ok {
		d.add(34, "Thread in", "FAIL", "no root message")
		return
	}
	d.thread = root.ID
	// With chat_parents, a thread in the owner's DM is admitted as the DM
	// is. A host without it gates the thread as its own unadmitted chat of
	// kind thread and asks nobody, so the owner approves it in the thread,
	// for every message, since a thread in a DM carries no mentions.
	how := "with no approval of its own, as its DM is admitted"
	if d.o.approveThreads {
		approve := text("/approve all")
		approve.RelatesTo = (&event.RelatesTo{}).SetThread(root.ID, root.ID)
		aFrom := d.owner.mark()
		d.owner.say(ctx, d.dm, approve)
		ack, acked := d.owner.reply(ctx, aFrom, d.dm, time.Minute)
		if !acked {
			d.add(34, "Thread in", "FAIL", "/approve in the thread got no answer")
			return
		}
		how = fmt.Sprintf("after /approve all in the thread (%s)", quote(ack))
	}
	c := text("In this thread, reply with exactly the word banana.")
	c.RelatesTo = (&event.RelatesTo{}).SetThread(root.ID, root.ID)
	from := d.owner.mark()
	var err error
	if d.threadIn, err = d.owner.say(ctx, d.dm, c); err != nil {
		d.add(34, "Thread in", "FAIL", "send: %v", err)
		return
	}
	evt, ok := d.owner.reply(ctx, from, d.dm, turn)
	switch {
	case !ok && !d.o.approveThreads:
		d.add(34, "Thread in", "FAIL", "no reply; a host without chat_parents needs -approve-threads")
	case !ok:
		d.add(34, "Thread in", "FAIL", "no reply")
	case evt.Content.AsMessage().RelatesTo.GetThreadParent() != root.ID:
		d.add(34, "Thread in", "FAIL", "the reply landed outside the thread: %s", quote(evt))
	default:
		d.add(34, "Thread in", "PASS", "%s, the reply is in the thread: %s", how, quote(evt))
	}
}

func rowThreadEvents(ctx context.Context, d *dogfood) {
	if d.threadIn == "" {
		d.add(35, "Thread events", "SKIP", "row 34 made no thread")
		return
	}
	edit := text("* In this thread, reply with exactly the word mango.")
	edit.NewContent = text("In this thread, reply with exactly the word mango.")
	edit.RelatesTo = (&event.RelatesTo{}).SetReplace(d.threadIn)
	d.owner.say(ctx, d.dm, edit)
	time.Sleep(3 * time.Second)
	q := text("Did I edit a message in this thread? Quote its new text.")
	q.RelatesTo = (&event.RelatesTo{}).SetThread(d.thread, d.threadIn)
	from := d.owner.mark()
	d.owner.say(ctx, d.dm, q)
	evt, ok := d.owner.reply(ctx, from, d.dm, turn)
	switch {
	case !ok:
		d.add(35, "Thread events", "FAIL", "no answer in the thread")
	case contains(evt, "mango"):
		d.add(35, "Thread events", "PASS", "the thread saw its edit: %s", quote(evt))
	default:
		d.add(35, "Thread events", "REVIEW", "answer %s", quote(evt))
	}
}

func rowThreadRestart(ctx context.Context, d *dogfood) {
	if d.bot == nil || d.threadIn == "" {
		d.add(36, "Thread after restart", "SKIP", "needs -launch and row 34")
		return
	}
	d.bot.stop()
	var err error
	if d.bot, err = startBot(d.o.launch, d.botLog); err != nil {
		d.add(36, "Thread after restart", "FAIL", "restart: %v", err)
		return
	}
	time.Sleep(20 * time.Second)
	edit := text("* In this thread, reply with exactly the word papaya.")
	edit.NewContent = text("In this thread, reply with exactly the word papaya.")
	edit.RelatesTo = (&event.RelatesTo{}).SetReplace(d.threadIn)
	d.owner.say(ctx, d.dm, edit)
	time.Sleep(3 * time.Second)
	q := text("After the restart: did a message in this thread change? Quote its new text.")
	q.RelatesTo = (&event.RelatesTo{}).SetThread(d.thread, d.threadIn)
	from := d.owner.mark()
	d.owner.say(ctx, d.dm, q)
	evt, ok := d.owner.reply(ctx, from, d.dm, turn)
	switch {
	case !ok:
		d.add(36, "Thread after restart", "FAIL", "no answer")
	case contains(evt, "papaya"):
		d.add(36, "Thread after restart", "PASS", "the pre-restart edit landed in the thread: %s", quote(evt))
	default:
		d.add(36, "Thread after restart", "REVIEW", "answer %s", quote(evt))
	}
}

func rowStatusCmd(ctx context.Context, d *dogfood) {
	out, err := exec.CommandContext(ctx, "terva", "bot", "status", "--connector", "rihma").CombinedOutput()
	if err != nil {
		d.add(37, "Status", "FAIL", "terva bot status: %v", err)
		return
	}
	if regexp.MustCompile(`(?m)token:\s+(\S{4}\.\.\.\S{4}|<hidden>)\s*$`).Match(out) {
		d.add(37, "Status", "PASS", "the rihma block shows the token masked")
		return
	}
	d.add(37, "Status", "FAIL", "no masked token line in the status output")
}

func rowSealed(_ context.Context, d *dogfood) {
	if d.o.config == "" {
		d.add(38, "Sealed at rest", "SKIP", "needs -config (or -pairing)")
		return
	}
	raw, err := os.ReadFile(d.o.config)
	if err != nil {
		d.add(38, "Sealed at rest", "FAIL", "%v", err)
		return
	}
	var cfg struct {
		Session struct {
			AccessToken string `json:"access_token"`
		} `json:"session"`
	}
	_ = json.Unmarshal(raw, &cfg)
	if strings.HasPrefix(cfg.Session.AccessToken, "enc:age:") {
		d.add(38, "Sealed at rest", "PASS", "session.access_token is sealed (enc:age:)")
		return
	}
	d.add(38, "Sealed at rest", "FAIL", "session.access_token is not sealed; has `terva secret init` run?")
}

func setAside(path string) error {
	if _, err := os.Stat(path); err != nil {
		return nil // nothing paired
	}
	return os.Rename(path, path+".dogfood-saved")
}

// restore puts the operator's pairing back, replacing the owner's claim.
func restore(path string) {
	saved := path + ".dogfood-saved"
	if _, err := os.Stat(saved); err != nil {
		return
	}
	_ = os.Rename(saved, path)
}

func (d *dogfood) write() error {
	var b strings.Builder
	fmt.Fprintf(&b, "# rihma dogfood run, %s\n\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "Homeserver %s; bot %s; owner %s; outsider %s; DM %s.\n\n", d.o.homeserver, d.o.bot, d.o.owner, d.o.stranger, d.dm)
	slices.SortStableFunc(d.results, func(a, b result) int { return a.row - b.row })
	counts := map[string]int{}
	b.WriteString("| # | Row | Result | Detail |\n|---|---|---|---|\n")
	for _, r := range d.results {
		counts[r.status]++
		fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", r.row, r.title, r.status, strings.ReplaceAll(strings.Join(strings.Fields(r.detail), " "), "|", "\\|"))
	}
	fmt.Fprintf(&b, "\nPASS %d, FAIL %d, REVIEW %d, SKIP %d.\n", counts["PASS"], counts["FAIL"], counts["REVIEW"], counts["SKIP"])
	if d.o.report == "" {
		fmt.Print(b.String())
		return nil
	}
	return os.WriteFile(d.o.report, []byte(b.String()), 0o600)
}
