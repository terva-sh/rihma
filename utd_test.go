package rihma

import (
	"reflect"
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
