package connector

import (
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"

	"terva.sh/rihma"
)

const noticeWindow = time.Minute

// operatorNotices keeps host notices independent of diagnostic error text.
// Sync and media notices have separate, constant-memory limits. Decryption
// reports arrive through rihma's per-room UTD limiter instead.
type operatorNotices struct {
	warn func(string)
	log  zerolog.Logger
	now  func() time.Time

	mu        sync.Mutex
	nextSync  time.Time
	nextMedia time.Time
}

func newOperatorNotices(warn func(string), log zerolog.Logger) *operatorNotices {
	return &operatorNotices{warn: warn, log: log, now: time.Now}
}

func (n *operatorNotices) allow(next *time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	if now.Before(*next) {
		return false
	}
	*next = now.Add(noticeWindow)
	return true
}

func (n *operatorNotices) syncRetry() {
	if n == nil || !n.allow(&n.nextSync) {
		return
	}
	n.warn("Matrix connection or sync failed; retrying automatically. Check the connector log if this persists.")
}

func (n *operatorNotices) undecryptable(room id.RoomID, count int) {
	if n == nil {
		return
	}
	n.log.Warn().Stringer("room_id", room).Int("count", count).Msg("unable to decrypt messages")
	n.warn(fmt.Sprintf("Matrix room %q: unable to decrypt %d message(s). Verify the bot's device or restore its recovery key.", room, count))
}

func (n *operatorNotices) droppedMedia(room id.RoomID, evt id.EventID, kind string, limit int64) {
	if n == nil || !n.allow(&n.nextMedia) {
		return
	}
	n.warn(fmt.Sprintf("Matrix room %q, event %q: dropped %s. Check the connector log for download, integrity or size failures (limit %d bytes).", room, evt, kind, limit))
}

// clientOptions adds host reporting only during run. Interactive setup and
// verify keep their own terminal output and never use the protocol writer.
func (t *transport) clientOptions() rihma.Options {
	opts := clientOptions(t.cfg, nil)
	opts.OnUTD = t.notices.undecryptable
	opts.OnSyncRetry = t.notices.syncRetry
	return opts
}
