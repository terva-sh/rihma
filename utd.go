package rihma

import (
	"sync"
	"time"

	"maunium.net/go/mautrix/id"
)

// utdLimiter bounds unable-to-decrypt reports per room. The first
// failure in a quiet room is reported at once with count 1. Failures
// during the following window are counted and reported once when it
// closes, and a report opens a new window, so a room in a storm is
// reported at most once per window.
type utdLimiter struct {
	window time.Duration
	notify func(id.RoomID, int)
	// afterFunc is time.AfterFunc, replaced in tests.
	afterFunc func(time.Duration, func()) stopper

	mu      sync.Mutex
	rooms   map[id.RoomID]*utdRoom
	stopped bool
}

type utdRoom struct {
	pending int
	timer   stopper
}

type stopper interface{ Stop() bool }

func newUTDLimiter(window time.Duration, notify func(id.RoomID, int)) *utdLimiter {
	return &utdLimiter{
		window: window,
		notify: notify,
		afterFunc: func(d time.Duration, f func()) stopper {
			return time.AfterFunc(d, f)
		},
		rooms: make(map[id.RoomID]*utdRoom),
	}
}

func (l *utdLimiter) report(room id.RoomID) {
	if l.notify == nil {
		return
	}
	l.mu.Lock()
	if l.stopped {
		l.mu.Unlock()
		return
	}
	if r, ok := l.rooms[room]; ok {
		r.pending++
		l.mu.Unlock()
		return
	}
	r := &utdRoom{}
	l.rooms[room] = r
	r.timer = l.afterFunc(l.window, func() { l.flush(room) })
	l.mu.Unlock()
	l.notify(room, 1)
}

// flush closes a room's window. If failures arrived during it, they are
// reported and a new window opens; otherwise the room goes quiet and the
// entry is dropped, which keeps the map bounded by rooms in a storm.
func (l *utdLimiter) flush(room id.RoomID) {
	l.mu.Lock()
	r, ok := l.rooms[room]
	if !ok || l.stopped {
		l.mu.Unlock()
		return
	}
	n := r.pending
	if n == 0 {
		delete(l.rooms, room)
		l.mu.Unlock()
		return
	}
	r.pending = 0
	r.timer = l.afterFunc(l.window, func() { l.flush(room) })
	l.mu.Unlock()
	l.notify(room, n)
}

// stop cancels pending windows; failures still being counted are dropped.
func (l *utdLimiter) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopped = true
	for room, r := range l.rooms {
		r.timer.Stop()
		delete(l.rooms, room)
	}
}
