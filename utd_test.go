package rihma

import (
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"maunium.net/go/mautrix/id"
)

// fakeTimers collects the limiter's timers so a test fires them by hand.
type fakeTimers struct{ pending []*fakeTimer }

type fakeTimer struct {
	f       func()
	stopped bool
}

func (t *fakeTimer) Stop() bool { t.stopped = true; return true }

func (ft *fakeTimers) afterFunc(_ time.Duration, f func()) stopper {
	t := &fakeTimer{f: f}
	ft.pending = append(ft.pending, t)
	return t
}

// fire runs every timer pending now; timers they start wait for the next call.
func (ft *fakeTimers) fire() {
	due := ft.pending
	ft.pending = nil
	for _, t := range due {
		if !t.stopped {
			t.f()
		}
	}
}

type utdReport struct {
	room  id.RoomID
	count int
}

func newTestLimiter() (*utdLimiter, *fakeTimers, *[]utdReport) {
	var got []utdReport
	ft := &fakeTimers{}
	l := newUTDLimiter(time.Minute, func(r id.RoomID, n int) { got = append(got, utdReport{r, n}) })
	l.afterFunc = ft.afterFunc
	return l, ft, &got
}

func TestUTDLimiterBurst(t *testing.T) {
	l, ft, got := newTestLimiter()
	for range 5 {
		l.report("!a")
	}
	l.report("!b")
	want := []utdReport{{"!a", 1}, {"!b", 1}}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("immediate reports = %v, want %v", *got, want)
	}

	ft.fire() // window closes: !a had 4 more, !b none
	want = append(want, utdReport{"!a", 4})
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("after one window = %v, want %v", *got, want)
	}

	l.report("!a") // inside !a's second window, so counted, not reported
	ft.fire()
	want = append(want, utdReport{"!a", 1})
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("after two windows = %v, want %v", *got, want)
	}

	ft.fire() // a quiet window: !a goes idle and its entry is dropped
	if len(l.rooms) != 0 {
		t.Fatalf("%d rooms still tracked after quiet windows", len(l.rooms))
	}
	l.report("!a")
	want = append(want, utdReport{"!a", 1})
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("after going quiet = %v, want %v", *got, want)
	}
}

func TestUTDLimiterStop(t *testing.T) {
	l, ft, got := newTestLimiter()
	l.report("!a")
	l.report("!a")
	l.stop()
	ft.fire()
	l.report("!a")
	if want := []utdReport{{"!a", 1}}; !reflect.DeepEqual(*got, want) {
		t.Fatalf("reports = %v, want %v", *got, want)
	}
}

func TestUTDLimiterNilNotify(t *testing.T) {
	l := newUTDLimiter(time.Minute, nil)
	l.report("!a") // must not panic or start timers
	if len(l.rooms) != 0 {
		t.Fatal("nil notify still tracks rooms")
	}
}

func TestBackoff(t *testing.T) {
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60}
	for i, w := range want {
		if got := backoff(i + 1); got != w*time.Second {
			t.Errorf("backoff(%d) = %v, want %v", i+1, got, w*time.Second)
		}
	}
}

func TestUTDLimiterStopJoinsActiveNotifications(t *testing.T) {
	for _, kind := range []string{"immediate", "timer"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			blockAt := int32(1)
			if kind == "timer" {
				blockAt = 2
			}
			l := newUTDLimiter(time.Minute, func(id.RoomID, int) {
				if calls.Add(1) == blockAt {
					close(entered)
					<-release
				}
			})
			timers := &fakeTimers{}
			l.afterFunc = timers.afterFunc
			if kind == "timer" {
				l.report("!a")
				l.report("!a")
				go timers.fire()
			} else {
				go l.report("!a")
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("notification did not start")
			}
			stopped := make(chan struct{})
			go func() { l.stopAndWait(); close(stopped) }()
			select {
			case <-stopped:
				t.Fatal("shutdown passed live notification")
			case <-time.After(20 * time.Millisecond):
			}
			unblock()
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("notification was not joined")
			}
			// Model a callback whose timer fired just before Stop. Its callback must
			// refuse notification even when Stop could not prevent its invocation.
			for _, timer := range timers.pending {
				timer.f()
			}
			l.report("!b")
			if calls.Load() != blockAt {
				t.Fatal("late notification reached closed account")
			}
			l.stopAndWait()
		})
	}
}
