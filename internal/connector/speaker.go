package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"
)

// Speaker profiles, as terva-conn-matrix's src/matrix/outbound.rs sends
// them: an MSC4144 per-message profile, under the unstable
// com.beeper.per_message_profile key that bridges emit and clients render
// today. They are off by default. Without the feature declared the host
// writes its "**Name:** text" prefix instead, which every client shows.

const (
	speakerOff      = "off"
	speakerNameOnly = "name_only"
	speakerFull     = "full"

	avatarTimeout   = 10 * time.Second
	avatarCacheSize = 64
)

// speakerFeature is the feature string the speaker key declares, or "".
func speakerFeature(mode string) string {
	switch mode {
	case speakerNameOnly:
		return "speaker:name_only"
	case speakerFull:
		return "speaker:full"
	}
	return ""
}

// configuredSpeakerFeature reads the speaker key for the hello. It is not
// a secret, so the file is read as it lies rather than opened, which
// would decrypt every secret to read one setting. An unreadable config
// declares nothing, as in terva-conn-matrix.
func configuredSpeakerFeature(path string, warn io.Writer) string {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	var c struct {
		Speaker string `json:"speaker"`
	}
	if err == nil {
		err = json.Unmarshal(raw, &c)
	}
	if err != nil {
		fmt.Fprintf(warn, "rihma: ignoring an unreadable config for capabilities: %v\n", err)
		return ""
	}
	switch c.Speaker {
	case "", speakerOff, speakerNameOnly, speakerFull:
	default:
		fmt.Fprintf(warn, "rihma: speaker %q is not off, name_only, or full; declaring no speaker profiles\n", c.Speaker)
	}
	return speakerFeature(c.Speaker)
}

type avatarKey struct{ key, path string }

// SendAsSpeaker sends as SendWithID does, with the speaker's profile. A
// speaker with no name, or one sent while the config declares no
// profiles (a host that ignores the declaration), goes as plain text, as
// in terva-conn-matrix; connsdk's fallback would use the key instead.
func (t *transport) SendAsSpeaker(ctx context.Context, out connsdk.Outgoing) (string, error) {
	return t.sendText(ctx, out, t.speakerProfile(ctx, out.Speaker))
}

func (t *transport) speakerProfile(ctx context.Context, sp *connsdk.Speaker) *event.BeeperPerMessageProfile {
	mode := t.cfg.Speaker
	if sp == nil || sp.Name == "" || speakerFeature(mode) == "" {
		return nil
	}
	p := &event.BeeperPerMessageProfile{ID: sp.Key, Displayname: sp.Name}
	if mode == speakerFull && sp.AvatarPath != "" {
		if uri, ok := t.avatarURI(ctx, sp.Key, sp.AvatarPath); ok {
			p.AvatarURL = &uri
		}
	}
	return p
}

// avatarURI uploads a speaker's avatar once per (key, path), so a changed
// file uploads again and a stable cast uploads once. Any failure is a
// warning and the profile goes without an avatar: rendering a speaker
// must never fail the send. The path is not logged.
func (t *transport) avatarURI(ctx context.Context, key, path string) (id.ContentURIString, bool) {
	ck := avatarKey{key, path}
	if uri, ok := t.avatars.get(ck); ok {
		return uri, true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.log.Warn().Str("speaker", key).Msg("cannot read the speaker's avatar; sending without it")
		return "", false
	}
	ctx, cancel := context.WithTimeout(ctx, avatarTimeout)
	defer cancel()
	resp, err := t.client.UploadMedia(ctx, mautrix.ReqUploadMedia{ContentBytes: data, ContentType: guessMime(path)})
	if err != nil {
		t.log.Warn().Err(err).Str("speaker", key).Msg("speaker avatar upload failed; sending without it")
		return "", false
	}
	uri := resp.ContentURI.CUString()
	t.avatars.put(ck, uri)
	return uri, true
}
