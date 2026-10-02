//go:build dogfood

// Command dogfood plays the humans in testing/DOGFOOD.md against a real
// terva host running the rihma connector, so the checklist can run
// without a person at a client. It logs in as two password accounts, an
// owner and an outsider, drives each row through the Matrix API, and
// writes a report: pass, fail, skip, or review for rows whose outcome is
// a model's wording and needs a reader.
//
// It cannot judge how a client renders anything; the rows that need eyes
// on Element say so in the report. It never prints a password.
//
//	go run -tags 'goolm dogfood' ./testing/dogfood -h
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"terva.sh/rihma"
)

type options struct {
	homeserver     string
	bot            id.UserID
	owner          id.UserID
	ownerPW        string
	stranger       id.UserID
	strangerPW     string
	stateDir       string
	report         string
	launch         string
	pairing        string
	connectorLog   string
	rows           string
	skip           string
	config         string
	allowAlways    bool
	approveThreads bool
}

func main() {
	var o options
	var bot, owner, stranger string
	flag.StringVar(&o.homeserver, "hs", "", "homeserver URL")
	flag.StringVar(&bot, "bot", "", "the bot's user id")
	flag.StringVar(&owner, "owner", "", "the owner's user id (password login)")
	flag.StringVar(&o.ownerPW, "owner-password-file", "", "file holding the owner's password")
	flag.StringVar(&stranger, "stranger", "", "the outsider's user id (password login)")
	flag.StringVar(&o.strangerPW, "stranger-password-file", "", "file holding the outsider's password")
	flag.StringVar(&o.stateDir, "state", "", "a directory for the humans' Matrix state (created; keep it between runs)")
	flag.StringVar(&o.report, "report", "", "where to write the report (default: stdout)")
	flag.StringVar(&o.launch, "launch", "", "shell command that runs the bot in the foreground; enables the restart rows")
	flag.StringVar(&o.pairing, "pairing", "", "the connector's pairing.json: set aside before launch so the owner can claim, restored at exit")
	flag.StringVar(&o.connectorLog, "connector-log", "", "the connector's log, for the oversize row")
	flag.StringVar(&o.rows, "rows", "", "comma-separated row numbers to run (default: all)")
	flag.StringVar(&o.skip, "skip", "", "comma-separated row numbers to leave out")
	flag.StringVar(&o.config, "config", "", "the connector's config.json (default: beside -pairing)")
	flag.BoolVar(&o.allowAlways, "allow-always", false, "run row 31, which leaves a durable tool grant in terva")
	flag.BoolVar(&o.approveThreads, "approve-threads", false, "send /approve all in row 34's thread first, for a host without chat_parents (before terva v0.139.7)")
	flag.Parse()
	o.bot, o.owner, o.stranger = id.UserID(bot), id.UserID(owner), id.UserID(stranger)
	if o.config == "" && o.pairing != "" {
		o.config = filepath.Join(filepath.Dir(o.pairing), "config.json")
	}
	if o.homeserver == "" || bot == "" || owner == "" || o.ownerPW == "" || stranger == "" || o.strangerPW == "" || o.stateDir == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "dogfood:", err)
		os.Exit(1)
	}
}

// human is one scripted person: a Matrix client and what it has seen.
type human struct {
	*rihma.Client
	bot id.UserID

	mu       sync.Mutex
	msgs     []*event.Event // the bot's messages, in arrival order
	typing   map[id.RoomID]bool
	typedAt  map[id.RoomID]time.Time // last time the bot was seen typing
	redacted map[id.EventID]bool
}

func login(ctx context.Context, o options, user id.UserID, pwFile string) (*human, error) {
	pw, err := os.ReadFile(pwFile)
	if err != nil {
		return nil, fmt.Errorf("read %s's password file: %w", user, err)
	}
	local, _, err := user.Parse()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(o.stateDir, local)
	logf, err := os.OpenFile(filepath.Join(o.stateDir, local+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	c, err := rihma.Open(ctx, rihma.Options{
		Homeserver: o.homeserver,
		StateDir:   filepath.Join(dir, "state"),
		Sessions:   rihma.FileSessionStore{Path: filepath.Join(dir, "session.json")},
		Login: &mautrix.ReqLogin{
			Type:       mautrix.AuthTypePassword,
			Identifier: mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: local},
			Password:   strings.TrimRight(string(pw), "\r\n"),
		},
		DeviceName: "rihma dogfood",
		Logger:     zerolog.New(logf).Level(zerolog.InfoLevel),
	})
	if err != nil {
		return nil, fmt.Errorf("log in as %s: %w", user, err)
	}
	h := &human{Client: c, bot: o.bot, typing: map[id.RoomID]bool{}, typedAt: map[id.RoomID]time.Time{}, redacted: map[id.EventID]bool{}}
	c.Handlers().OnEventType(event.EventMessage, func(_ context.Context, evt *event.Event) {
		if evt.Sender == o.bot {
			h.mu.Lock()
			h.msgs = append(h.msgs, evt)
			h.mu.Unlock()
		}
	})
	c.Handlers().OnEventType(event.EventRedaction, func(_ context.Context, evt *event.Event) {
		target := evt.Redacts
		if target == "" {
			target = evt.Content.AsRedaction().Redacts
		}
		h.mu.Lock()
		h.redacted[target] = true
		h.mu.Unlock()
	})
	c.Handlers().OnEventType(event.EphemeralEventTyping, func(_ context.Context, evt *event.Event) {
		on := slices.Contains(evt.Content.AsTyping().UserIDs, o.bot)
		h.mu.Lock()
		h.typing[evt.RoomID] = on
		if on {
			h.typedAt[evt.RoomID] = time.Now()
		}
		h.mu.Unlock()
	})
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	go func() { _ = c.Sync(ctx) }()
	return h, nil
}

// mark is a position in the bot's message stream.
func (h *human) mark() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.msgs)
}

// next waits for a bot message after mark in room that pred accepts. A
// message that edits another counts with its new content.
func (h *human) next(ctx context.Context, from int, room id.RoomID, within time.Duration, pred func(*event.MessageEventContent, *event.Event) bool) (*event.Event, bool) {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		h.mu.Lock()
		for _, evt := range h.msgs[min(from, len(h.msgs)):] {
			if room != "" && evt.RoomID != room {
				continue
			}
			c := evt.Content.AsMessage()
			if c.NewContent != nil {
				c = c.NewContent
			}
			if pred == nil || pred(c, evt) {
				h.mu.Unlock()
				return evt, true
			}
		}
		h.mu.Unlock()
		time.Sleep(250 * time.Millisecond)
	}
	return nil, false
}

// reply waits for the bot's next message in room that is not an edit.
func (h *human) reply(ctx context.Context, from int, room id.RoomID, within time.Duration) (*event.Event, bool) {
	return h.next(ctx, from, room, within, func(_ *event.MessageEventContent, evt *event.Event) bool {
		return evt.Content.AsMessage().RelatesTo.GetReplaceID() == ""
	})
}

// silent is true when the bot says nothing in room for d after from.
func (h *human) silent(ctx context.Context, from int, room id.RoomID, d time.Duration) bool {
	_, got := h.reply(ctx, from, room, d)
	return !got
}

func (h *human) say(ctx context.Context, room id.RoomID, c *event.MessageEventContent) (id.EventID, error) {
	resp, err := h.SendMessageEvent(ctx, room, event.EventMessage, c)
	if err != nil {
		return "", err
	}
	return resp.EventID, nil
}

func text(body string) *event.MessageEventContent {
	return &event.MessageEventContent{MsgType: event.MsgText, Body: body}
}

// mention addresses the bot the way Element's pill does.
func mention(bot id.UserID, body string) *event.MessageEventContent {
	local, _, _ := bot.Parse()
	return &event.MessageEventContent{
		MsgType: event.MsgText, Body: local + ": " + body,
		Format:        event.FormatHTML,
		FormattedBody: fmt.Sprintf(`<a href="https://matrix.to/#/%s">%s</a>: %s`, bot, local, body),
		Mentions:      &event.Mentions{UserIDs: []id.UserID{bot}},
	}
}

func body(evt *event.Event) string {
	c := evt.Content.AsMessage()
	if c.NewContent != nil {
		return c.NewContent.Body
	}
	return c.Body
}

// seeds lists the bot's reaction keys on target, as the server has them.
func (h *human) seeds(ctx context.Context, room id.RoomID, target id.EventID) []string {
	resp, err := h.GetRelations(ctx, room, target, &mautrix.ReqGetRelations{RelationType: event.RelAnnotation, Limit: 100})
	if err != nil {
		return nil
	}
	var keys []string
	for _, evt := range resp.Chunk {
		if evt.Sender != h.bot || evt.Type != event.EventReaction {
			continue
		}
		if evt.Content.Parsed == nil {
			_ = evt.Content.ParseRaw(evt.Type)
		}
		keys = append(keys, evt.Content.AsReaction().RelatesTo.Key)
	}
	slices.Sort(keys)
	return keys
}

// ask waits for an ask in room (a bot message the bot seeds with
// reactions) and returns it with its seed keys.
func (h *human) ask(ctx context.Context, from int, room id.RoomID, within time.Duration) (*event.Event, []string, bool) {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		evt, ok := h.reply(ctx, from, room, time.Until(deadline))
		if !ok {
			return nil, nil, false
		}
		for range 20 {
			if keys := h.seeds(ctx, room, evt.ID); len(keys) > 0 {
				return evt, keys, true
			}
			time.Sleep(250 * time.Millisecond)
		}
		from = h.indexOf(evt.ID) + 1
	}
	return nil, nil, false
}

func (h *human) indexOf(evtID id.EventID) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.IndexFunc(h.msgs, func(e *event.Event) bool { return e.ID == evtID })
}

// outcome waits for the edit the host makes into an ask when it closes.
func (h *human) outcome(ctx context.Context, from int, askMsg id.EventID, within time.Duration) (string, bool) {
	evt, ok := h.next(ctx, from, "", within, func(_ *event.MessageEventContent, evt *event.Event) bool {
		return evt.Content.AsMessage().RelatesTo.GetReplaceID() == askMsg
	})
	if !ok {
		return "", false
	}
	return body(evt), true
}

func (h *human) waitMember(ctx context.Context, room id.RoomID, user id.UserID, want event.Membership, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		m, err := h.StateStore.GetMember(ctx, room, user)
		if err == nil && m != nil && m.Membership == want {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func (h *human) room(ctx context.Context, name string, encrypted, direct bool, invite ...id.UserID) (id.RoomID, error) {
	req := &mautrix.ReqCreateRoom{Name: name, Invite: invite, IsDirect: direct, Preset: "private_chat"}
	if direct {
		req.Preset = "trusted_private_chat"
	}
	if encrypted {
		req.InitialState = []*event.Event{{Type: event.StateEncryption,
			Content: event.Content{Parsed: &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}}}}
	}
	resp, err := h.CreateRoom(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.RoomID, nil
}

func colorPNG(c color.RGBA) []byte {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for x := range 64 {
		for y := range 64 {
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// bot is the launched terva process, when -launch is given.
type botProc struct {
	cmd     *exec.Cmd
	command string
	logf    *os.File
}

func startBot(command, logPath string) (*botProc, error) {
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &botProc{cmd: cmd, command: command, logf: logf}, nil
}

// stop interrupts the whole process group, as Ctrl-C would.
func (b *botProc) stop() {
	if b == nil || b.cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-b.cmd.Process.Pid, syscall.SIGINT)
	done := make(chan struct{})
	go func() { _ = b.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = syscall.Kill(-b.cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
	b.logf.Close()
}

// connectorPID finds the terva-rihma process under the launched bot.
func (b *botProc) connectorPID() int {
	out, err := exec.Command("pgrep", "-g", fmt.Sprint(b.cmd.Process.Pid), "-f", "terva-rihma run").Output()
	if err != nil {
		return 0
	}
	var pid int
	fmt.Sscan(strings.Fields(string(out))[0], &pid)
	return pid
}
