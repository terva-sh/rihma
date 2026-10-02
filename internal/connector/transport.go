package connector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"

	"terva.sh/rihma"
	"terva.sh/rihma/internal/version"
)

// minProtocol is 2: v2 message identity carries the whole mapping, and
// v1 puts a message's own id in reply_to. connsdk always advertises
// protocol_min 1, so the floor is enforced here (docs/connsdk-proposals.md).
const minProtocol = 2

// Capabilities are declared only for what is implemented. Each later
// phase adds its own feature strings with its code.
var Capabilities = connsdk.Capabilities{
	MaxTextLen:    24000, // body and formatted_body share a 65535-byte event
	TypingRefresh: 20 * time.Second,
	Features: []string{"message_ids", "chat_kinds", "chat_parents", "typing_stop", "entities", "chat_membership",
		"edits_in", "edits_out", "deletes_in", "deletes_out", "reactions_in", "reactions_out", "attachment_kinds", "asks", "threads_out"},
	SendsImages:     true,
	SendsFiles:      true,
	MinEditInterval: time.Second, // declared, as terva-conn-matrix does; 429s are mautrix's
}

// Config is the connsdk configuration main runs. Speaker profiles are
// declared only when config.json opts in, as terva-conn-matrix does.
func Config() connsdk.Config {
	caps := Capabilities
	caps.Features = slices.Clone(Capabilities.Features)
	if f := configuredSpeakerFeature(State.Path(), os.Stderr); f != "" {
		caps.Features = append(caps.Features, f)
	}
	return connsdk.Config{
		Name:         Name,
		Version:      version.Version,
		Capabilities: caps,
		NewTransport: NewTransport,
		Setup:        Setup,
		Status:       Status,
		Reset:        Reset,
		Configured:   Configured,
		Secrets:      &State,
	}
}

type transport struct {
	cfg     fileConfig
	client  *rihma.Client
	self    id.UserID
	dms     dms
	titles  titles
	members *membership
	events  *chatEvents
	asks    *asks
	threads *threads
	avatars *boundedMap[avatarKey, id.ContentURIString]
	dataDir string // the host's, for inbound attachments
	sent    sentCache
	log     zerolog.Logger

	nameMu     sync.Mutex
	name       string
	nameLoaded bool
}

var (
	_ connsdk.Transport        = (*transport)(nil)
	_ connsdk.MessageIDSender  = (*transport)(nil)
	_ connsdk.TypingStopper    = (*transport)(nil)
	_ connsdk.MembershipSource = (*transport)(nil)
	_ connsdk.ChatEventSource  = (*transport)(nil)
	_ connsdk.MessageEditor    = (*transport)(nil)
	_ connsdk.MessageReactor   = (*transport)(nil)
	_ connsdk.MessageDeleter   = (*transport)(nil)
	_ connsdk.Asker            = (*transport)(nil)
	_ connsdk.Threader         = (*transport)(nil)
	_ connsdk.SpeakerSender    = (*transport)(nil)
)

// NewTransport refuses what can never work, which connsdk reports as a
// permanent connect_error: a protocol-1 host, and no configuration.
func NewTransport(s connsdk.Session) (connsdk.Transport, error) {
	if s.Protocol < minProtocol {
		return nil, fmt.Errorf("rihma needs connector protocol %d or newer; this host speaks %d", minProtocol, s.Protocol)
	}
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	if !cfg.configured() {
		return nil, errors.New("not configured — run `terva bot setup --connector rihma` first")
	}
	t := &transport{cfg: cfg, members: newMembership(), events: newChatEvents(), asks: newAsks(), threads: newThreads(), avatars: newBoundedMap[avatarKey, id.ContentURIString](avatarCacheSize), dataDir: s.DataDir, log: logger()}
	t.asks.refuse = t.redactRefused
	t.threads.fetchRoot, t.threads.fetchTitle = t.fetchScope, t.readTitle
	return t, nil
}

// Connect restores the stored session. It makes no network request, so
// a homeserver outage at startup is retried by Sync rather than reported
// as a permanent connect_error.
func (t *transport) Connect(ctx context.Context) (connsdk.Identity, error) {
	client, err := rihma.Open(ctx, clientOptions(t.cfg, nil))
	if err != nil {
		return connsdk.Identity{}, err
	}
	t.client, t.self = client, client.UserID
	return connsdk.Identity{ID: client.UserID.String(), Username: localpart(client.UserID)}, nil
}

// Receive syncs until ctx ends. An invalid access token ends it with an
// error, which exits the process non-zero so the host's restart budget
// applies; transient trouble is retried inside rihma.
func (t *transport) Receive(ctx context.Context, deliver func(connsdk.Message)) error {
	t.registerHandlers(deliver)
	err := t.client.Sync(ctx)
	t.asks.shutdown()
	t.client.Close()
	if ctx.Err() != nil {
		return nil
	}
	return err
}
