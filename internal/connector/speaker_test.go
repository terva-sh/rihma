package connector

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"
)

func TestConfiguredSpeakerFeature(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		name, file, want string
		warns            bool
	}{
		{"no config", "", "", false},
		{"unset", `{}`, "", false},
		{"off", `{"speaker":"off"}`, "", false},
		{"name only", `{"speaker":"name_only"}`, "speaker:name_only", false},
		{"full", `{"speaker":"full"}`, "speaker:full", false},
		{"unknown", `{"speaker":"loud"}`, "", true},
		{"unreadable", `{"speaker":`, "", true},
	} {
		path := filepath.Join(dir, c.name+".json")
		if c.file != "" {
			if err := os.WriteFile(path, []byte(c.file), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		var warn bytes.Buffer
		if got := configuredSpeakerFeature(path, &warn); got != c.want || (warn.Len() > 0) != c.warns {
			t.Errorf("%s: %q, warned %q", c.name, got, warn.String())
		}
	}
}

func TestSpeakerProfile(t *testing.T) {
	ctx := context.Background()
	tr := newTestTransport()
	tr.avatars = newBoundedMap[avatarKey, id.ContentURIString](avatarCacheSize)
	kaiku := &connsdk.Speaker{Key: "kaiku", Name: "Kaiku", AvatarPath: "/nonexistent/kaiku.png"}

	for _, mode := range []string{"", speakerOff, "loud"} {
		tr.cfg.Speaker = mode
		if p := tr.speakerProfile(ctx, kaiku); p != nil {
			t.Errorf("mode %q sent a profile: %+v", mode, p)
		}
	}

	tr.cfg.Speaker = speakerNameOnly
	if p := tr.speakerProfile(ctx, nil); p != nil {
		t.Fatalf("no speaker: %+v", p)
	}
	if p := tr.speakerProfile(ctx, &connsdk.Speaker{Key: "kaiku"}); p != nil {
		t.Fatalf("a speaker with no name: %+v", p)
	}
	p := tr.speakerProfile(ctx, kaiku)
	if p == nil || p.ID != "kaiku" || p.Displayname != "Kaiku" || p.AvatarURL != nil {
		t.Fatalf("name_only = %+v", p)
	}

	// full: an unreadable avatar degrades to the name, without a client.
	tr.cfg.Speaker = speakerFull
	if p := tr.speakerProfile(ctx, kaiku); p == nil || p.Displayname != "Kaiku" || p.AvatarURL != nil {
		t.Fatalf("full with an unreadable avatar = %+v", p)
	}
	// A cached upload is reused per (key, path).
	tr.avatars.put(avatarKey{"kaiku", kaiku.AvatarPath}, "mxc://hs/kaiku")
	if p := tr.speakerProfile(ctx, kaiku); p == nil || p.AvatarURL == nil || *p.AvatarURL != "mxc://hs/kaiku" {
		t.Fatalf("full with a cached avatar = %+v", p)
	}
	other := *kaiku
	other.Key = "aino"
	if p := tr.speakerProfile(ctx, &other); p.AvatarURL != nil {
		t.Fatalf("another key reused kaiku's avatar: %+v", p)
	}
}

func TestSpeakerStatus(t *testing.T) {
	for mode, want := range map[string]string{"": "off", "off": "off", "name_only": "name_only", "full": "full", "loud": `"loud" is not`} {
		if got := speakerStatus(mode); !strings.HasPrefix(got, want) {
			t.Errorf("speakerStatus(%q) = %q", mode, got)
		}
	}
}
