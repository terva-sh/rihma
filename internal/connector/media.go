package connector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"maunium.net/go/mautrix/event"
	"terva.sh/terva/packages/agent/connsdk"

	"terva.sh/rihma"
)

// Attachments both ways through the host's data_dir, as
// terva-conn-matrix's src/matrix/media.rs does them.

const defaultMaxAttachmentMB = 64

// ceiling is max_attachment_mb in bytes; 0 means the default.
func (c fileConfig) ceiling() int64 {
	mb := c.MaxAttachmentMB
	if mb <= 0 {
		mb = defaultMaxAttachmentMB
	}
	return int64(mb) << 20
}

// attachmentPlan is what an inbound media event becomes, before the
// download.
type attachmentPlan struct {
	kind     string
	name     string
	caption  string
	mime     string
	duration time.Duration
}

// planAttachment maps a media message to its attachment. ok is false for
// message types that are not media.
func planAttachment(msg *event.MessageEventContent, sticker bool) (attachmentPlan, bool) {
	var p attachmentPlan
	switch {
	case sticker:
		p.kind = "sticker"
	case msg.MsgType == event.MsgImage:
		p.kind = "image"
	case msg.MsgType == event.MsgAudio && msg.MSC3245Voice != nil:
		p.kind = "voice"
	case msg.MsgType == event.MsgAudio:
		p.kind = "audio"
	case msg.MsgType == event.MsgVideo:
		p.kind = "video"
	case msg.MsgType == event.MsgFile:
		p.kind = "document"
	default:
		return p, false
	}
	// Matrix v1.10 captions: with a distinct filename, body is the caption.
	switch {
	case sticker:
		p.name = msg.Body
	case msg.FileName != "" && msg.FileName != msg.Body:
		p.name, p.caption = msg.FileName, msg.Body
	case msg.FileName != "":
		p.name = msg.FileName
	default:
		p.name = msg.Body
	}
	if msg.Info != nil {
		p.mime = msg.Info.MimeType
		if p.kind == "voice" || p.kind == "audio" || p.kind == "video" {
			p.duration = time.Duration(msg.Info.Duration) * time.Millisecond
		}
	}
	if p.mime == "" {
		p.mime = guessMime(p.name)
	}
	return p, true
}

// guessMime is terva-conn-matrix's table, kept fixed rather than read
// from the system's mime files so a name maps the same everywhere.
func guessMime(name string) string {
	switch strings.ToLower(strings.TrimPrefix(filepath.Ext(name), ".")) {
	case "png":
		return "image/png"
	case "jpg", "jpeg":
		return "image/jpeg"
	case "gif":
		return "image/gif"
	case "webp":
		return "image/webp"
	case "svg":
		return "image/svg+xml"
	case "bmp":
		return "image/bmp"
	case "pdf":
		return "application/pdf"
	case "txt", "log":
		return "text/plain"
	case "md":
		return "text/markdown"
	case "html", "htm":
		return "text/html"
	case "json":
		return "application/json"
	case "csv":
		return "text/csv"
	case "zip":
		return "application/zip"
	case "gz":
		return "application/gzip"
	case "tar":
		return "application/x-tar"
	case "mp3":
		return "audio/mpeg"
	case "ogg", "oga":
		return "audio/ogg"
	case "opus":
		return "audio/opus"
	case "wav":
		return "audio/wav"
	case "m4a", "aac":
		return "audio/aac"
	case "flac":
		return "audio/flac"
	case "mp4", "m4v":
		return "video/mp4"
	case "webm":
		return "video/webm"
	case "mov":
		return "video/quicktime"
	case "mkv":
		return "video/x-matroska"
	}
	return "application/octet-stream"
}

// fileName is the name an attachment gets in data_dir: the event id
// without its "$", a dash, and the name keeping its last 80 characters,
// each with every character outside [A-Za-z0-9._-] replaced by "_".
func fileName(evtID, name string) string {
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
				return r
			}
			return '_'
		}, s)
	}
	n := clean(name)
	if n == "" {
		n = "attachment"
	}
	if r := []rune(n); len(r) > 80 {
		n = string(r[len(r)-80:])
	}
	return clean(strings.TrimPrefix(evtID, "$")) + "-" + n
}

// ingest downloads a media event's file into data_dir and returns its
// attachment. The file appears under its final name only once complete,
// because the host reads the path as soon as the frame arrives.
func (t *transport) ingest(ctx context.Context, evt *event.Event, msg *event.MessageEventContent, p attachmentPlan) (connsdk.Attachment, error) {
	if t.dataDir == "" {
		return connsdk.Attachment{}, errors.New("the host assigned no data_dir")
	}
	if err := os.MkdirAll(t.dataDir, 0o700); err != nil {
		return connsdk.Attachment{}, fmt.Errorf("cannot create data_dir: %w", err)
	}
	tmp, err := os.CreateTemp(t.dataDir, ".rihma-*")
	if err != nil {
		return connsdk.Attachment{}, fmt.Errorf("cannot write into data_dir: %w", err)
	}
	defer os.Remove(tmp.Name()) // a no-op after the rename
	n, err := t.client.DownloadMedia(ctx, msg, t.cfg.ceiling(), tmp)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return connsdk.Attachment{}, err
	}
	final, err := filepath.Abs(filepath.Join(t.dataDir, fileName(evt.ID.String(), p.name)))
	if err != nil {
		return connsdk.Attachment{}, err
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		return connsdk.Attachment{}, fmt.Errorf("cannot write %s: %w", final, err)
	}
	return connsdk.Attachment{
		MimeType: p.mime, Path: final, Kind: p.kind, Name: p.name,
		Size: n, Duration: p.duration, Caption: p.caption,
	}, nil
}

// translateMedia turns a media message or sticker into a host message
// with one attachment and no text. A failure drops the whole message and
// is logged for the operator (a warn frame would be better; see
// docs/connsdk-proposals.md §1).
func (t *transport) translateMedia(ctx context.Context, evt *event.Event, sticker bool) (connsdk.Message, bool) {
	msg := evt.Content.AsMessage()
	p, ok := planAttachment(msg, sticker)
	if !ok {
		return connsdk.Message{}, false
	}
	att, err := t.ingest(ctx, evt, msg, p)
	if err != nil {
		what := "attachment"
		if sticker {
			what = "sticker"
		}
		t.log.Warn().Err(err).Stringer("event_id", evt.ID).Stringer("room_id", evt.RoomID).Msg("dropping " + what)
		return connsdk.Message{}, false
	}
	// Stickers are room-scoped even inside a thread, as in
	// terva-conn-matrix; the rest route like text.
	var rel *event.RelatesTo
	if !sticker {
		rel = msg.RelatesTo
	}
	chatID, kind, title, replyTo := t.inboundShape(ctx, evt, rel)
	parentID, parentKind := t.parentContext(ctx, evt.RoomID, kind)
	m := connsdk.Message{
		ID: evt.ID.String(), TS: evt.Timestamp, ChatID: chatID,
		ChatKind: kind, ChatTitle: title,
		ParentChatID: parentID, ParentChatKind: parentKind,
		UserID: evt.Sender.String(), Username: localpart(evt.Sender),
		Attachments: []connsdk.Attachment{att},
	}
	if !sticker {
		m.ReplyTo = replyTo.String()
		m.Entities = extractEntities(mentionInput{mentions: msg.Mentions, repliedToBot: t.sent.has(replyTo.String())},
			botIdentity{userID: t.self, displayName: t.displayName(ctx)})
	}
	return m, true
}

func (t *transport) SendImage(ctx context.Context, chatID, path, caption string) error {
	return t.sendPath(ctx, chatID, path, caption)
}

func (t *transport) SendFile(ctx context.Context, chatID, path, caption string) error {
	return t.sendPath(ctx, chatID, path, caption)
}

// sendPath sends a local file. The message type follows the file's
// type, not the command: an image sent with send_file is still m.image.
func (t *transport) sendPath(ctx context.Context, chatID, path, caption string) error {
	if err := t.ready(ctx); err != nil {
		return err
	}
	target, err := t.resolveTarget(ctx, chatID)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", path, err)
	}
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		name = "attachment"
	}
	mime := guessMime(name)
	m := rihma.Media{Data: data, Name: name, MimeType: mime, MsgType: msgTypeFor(mime), Caption: caption}
	if target.root != "" {
		// The fallback is the root, not the newest event, as in
		// terva-conn-matrix's attachments.
		m.RelatesTo = (&event.RelatesTo{}).SetThread(target.root, target.root)
	}
	evtID, err := t.client.SendMedia(ctx, target.room, m)
	if err != nil {
		return fmt.Errorf("attachment send failed: %w", err)
	}
	t.note(target, evtID)
	return nil
}

func msgTypeFor(mime string) event.MessageType {
	switch {
	case strings.HasPrefix(mime, "image/"):
		return event.MsgImage
	case strings.HasPrefix(mime, "audio/"):
		return event.MsgAudio
	case strings.HasPrefix(mime, "video/"):
		return event.MsgVideo
	}
	return event.MsgFile
}
