package rihma

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func sasTestClient(t *testing.T, intercept ...func(http.ResponseWriter, *http.Request) bool) (*Client, *SASController, *testHS, func()) {
	t.Helper()
	h := newTestHS(t)
	// Commands require only acknowledgement, not mock device delivery.
	inner := h.ms.Server.Config.Handler
	h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sendToDevice/") {
			h.requests.Add(1)
			if len(intercept) > 0 && intercept[0](w, r) {
				return
			}
			w.Write([]byte(`{}`))
			return
		}
		inner.ServeHTTP(w, r)
	})
	opts := testOptions(t, h, t.TempDir())
	opts.Logger = zerolog.Nop()
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal("test client preparation failed")
	}
	controller, err := c.EnableSAS()
	if err != nil {
		t.Fatal("enable failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Sync(ctx) }()
	sasWait(t, func() bool { controller.mu.Lock(); defer controller.mu.Unlock(); return controller.started })
	stop := func() {
		cancel()
		<-done
		if err := c.Close(); err != nil {
			t.Error("close failed")
		}
	}
	return c, controller, h, stop
}
func sasWait(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("verification stage timed out")
}
func sasRequest(c *Client, txn id.VerificationTransactionID, from id.UserID, device id.DeviceID, expires time.Time) {
	c.Handlers().Dispatch(context.Background(), &event.Event{Type: event.ToDeviceVerificationRequest, Sender: from, Content: event.Content{Parsed: &event.VerificationRequestEventContent{ToDeviceVerificationEvent: event.ToDeviceVerificationEvent{TransactionID: txn}, FromDevice: device, Methods: []event.VerificationMethod{event.VerificationMethodSAS}, Timestamp: jsontime.UnixMilli{Time: expires.Add(-10 * time.Minute)}}}})
}
func TestSASNormalSyncRepeatedCancelAndScope(t *testing.T) {
	c, s, h, stop := sasTestClient(t)
	defer stop()
	if same, err := c.EnableSAS(); err != nil || same != s {
		t.Fatal("duplicate controller")
	}
	sasRequest(c, "foreign", "@stranger:localhost", "OTHER", time.Now().Add(time.Minute))
	sasRequest(c, "self", c.UserID, c.DeviceID, time.Now().Add(time.Minute))
	if all, _ := s.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
		t.Fatal("unsupported request entered helper")
	}
	for _, txn := range []id.VerificationTransactionID{"first", "second"} {
		sasRequest(c, txn, c.UserID, "OTHER", time.Now().Add(time.Minute))
		sasWait(t, func() bool { return s.Snapshot().State == SASRequested && s.Snapshot().TransactionID == txn })
		if err := s.Confirm(context.Background(), txn, true); !errors.Is(err, ErrSASStale) {
			t.Fatal("early confirm accepted")
		}
		if err := s.Accept(context.Background(), txn); err != nil {
			t.Fatal("accept failed")
		}
		if err := s.Cancel(context.Background(), txn); err != nil {
			t.Fatal("cancel failed")
		}
		if s.Snapshot().State != SASCancelled {
			t.Fatal("missing cancellation")
		}
		if err := s.Accept(context.Background(), txn); !errors.Is(err, ErrSASStale) {
			t.Fatal("stale command accepted")
		}
	}
	if len(h.seenSinces()) != 1 {
		t.Fatal("verification spawned additional sync")
	}
}
func TestSASTimeoutReasonAndShutdown(t *testing.T) {
	c, s, h, stop := sasTestClient(t)
	sasRequest(c, "expires", c.UserID, "OTHER", time.Now().Add(100*time.Millisecond))
	sasWait(t, func() bool { return s.Snapshot().State == SASRequested })
	sasWait(t, func() bool { return s.Snapshot().State == SASCancelled })
	if s.Snapshot().Reason != "timeout" {
		t.Fatal("timeout not exposed safely")
	}
	sasRequest(c, "cancelled", c.UserID, "OTHER", time.Now().Add(time.Minute))
	sasWait(t, func() bool { return s.Snapshot().State == SASRequested })
	c.Handlers().Dispatch(context.Background(), &event.Event{Type: event.ToDeviceVerificationCancel, Sender: c.UserID, Content: event.Content{Parsed: &event.VerificationCancelEventContent{ToDeviceVerificationEvent: event.ToDeviceVerificationEvent{TransactionID: "cancelled"}, Code: event.VerificationCancelCodeUser, Reason: "untrusted remote secret"}}})
	sasWait(t, func() bool { return s.Snapshot().State == SASCancelled })
	if s.Snapshot().Reason != "rejected" {
		t.Fatal("remote reason escaped")
	}
	// Sleeping helper expiry must do no network or crypto work after shutdown.
	sasRequest(c, "post-stop", c.UserID, "OTHER", time.Now().Add(200*time.Millisecond))
	sasWait(t, func() bool { return s.Snapshot().State == SASRequested })
	stop()
	n := h.requests.Load()
	time.Sleep(250 * time.Millisecond)
	if h.requests.Load() != n {
		t.Fatal("expiry used network after close")
	}
	if s.Snapshot().State != SASStopped {
		t.Fatal("controller did not stop")
	}
	if err := s.Cancel(context.Background(), "post-stop"); !errors.Is(err, ErrSASUnavailable) {
		t.Fatal("command accepted after stop")
	}
}
func TestSASShutdownJoinsDispatchedHandler(t *testing.T) {
	c, s, _, stop := sasTestClient(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	proxy := &sasHandlerSyncer{DefaultSyncer: c.Handlers(), underlying: c.Handlers(), gate: s.gate, user: c.UserID, device: c.DeviceID}
	proxy.OnEventType(event.ToDeviceDummy, func(context.Context, *event.Event) { calls.Add(1); close(entered); <-release })
	done := make(chan struct{})
	go func() {
		c.Handlers().Dispatch(context.Background(), &event.Event{Type: event.ToDeviceDummy, Sender: c.UserID})
		close(done)
	}()
	<-entered
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("close passed active handler")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-done
	<-stopped
	c.Handlers().Dispatch(context.Background(), &event.Event{Type: event.ToDeviceDummy, Sender: c.UserID})
	if calls.Load() != 1 {
		t.Fatal("handler reached closed state")
	}
}
func TestSASStoreRevocationAndCapacity(t *testing.T) {
	s := newSASStore()
	ctx := context.Background()
	if err := s.SaveVerificationTransaction(ctx, verificationhelper.VerificationTransaction{TransactionID: "one"}); err != nil {
		t.Fatal("save failed")
	}
	if err := s.SaveVerificationTransaction(ctx, verificationhelper.VerificationTransaction{TransactionID: "two"}); err == nil {
		t.Fatal("unbounded transaction store")
	}
	s.close()
	if _, err := s.GetVerificationTransaction(ctx, "one"); !errors.Is(err, verificationhelper.ErrUnknownVerificationTransaction) {
		t.Fatal("revoked transaction readable")
	}
	if err := s.SaveVerificationTransaction(ctx, verificationhelper.VerificationTransaction{TransactionID: "one"}); err == nil {
		t.Fatal("revoked store writable")
	}
}

func TestSASShutdownJoinsInflightExpiry(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	c, s, _, stop := sasTestClient(t, func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "verification.cancel") {
			return false
		}
		close(entered)
		<-release
		w.Write([]byte(`{}`))
		return true
	})
	sasRequest(c, "expires-inflight", c.UserID, "OTHER", time.Now().Add(50*time.Millisecond))
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("expiry did not start")
	}
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("closed stores during expiry request")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("expiry shutdown did not join")
	}
	if s.Snapshot().State != SASStopped {
		t.Fatal("expiry shutdown did not stop")
	}
}
func TestSASRejectsBusyReusedAndFutureRequests(t *testing.T) {
	c, s, _, stop := sasTestClient(t)
	defer stop()
	sasRequest(c, "first", c.UserID, "OTHER", time.Now().Add(time.Minute))
	sasWait(t, func() bool { return s.Snapshot().State == SASRequested })
	sasRequest(c, "busy", c.UserID, "THIRD", time.Now().Add(time.Minute))
	all, _ := s.store.GetAllVerificationTransactions(context.Background())
	if len(all) != 1 || all[0].TransactionID != "first" {
		t.Fatal("busy request replaced attempt")
	}
	if err := s.Cancel(context.Background(), "first"); err != nil {
		t.Fatal("cancel failed")
	}
	sasRequest(c, "first", c.UserID, "OTHER", time.Now().Add(time.Minute))
	sasRequest(c, "future", c.UserID, "OTHER", time.Now().Add(time.Hour))
	all, _ = s.store.GetAllVerificationTransactions(context.Background())
	if len(all) != 0 {
		t.Fatal("reused/future request entered helper")
	}
	if err := c.AwaitSAS(context.Background(), func([]SASEmoji) bool { return true }); !errors.Is(err, ErrSyncInProgress) {
		t.Fatal("bot wrapper permitted competing sync")
	}
}

type failingSASInitStore struct{ *sasStore }

func (f failingSASInitStore) GetAllVerificationTransactions(context.Context) ([]verificationhelper.VerificationTransaction, error) {
	return nil, errors.New("synthetic initialization failure")
}
func TestSASFailedInitRegistersNoHandlersAndRetries(t *testing.T) {
	h := newTestHS(t)
	opts := testOptions(t, h, t.TempDir())
	opts.Logger = zerolog.Nop()
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal("open failed")
	}
	defer c.Close()
	s := newSASController(c)
	if err := s.initWithStore(context.Background(), failingSASInitStore{s.store}); err == nil {
		t.Fatal("failed initialization reported success")
	}
	if s.helper != nil {
		t.Fatal("failed helper marked ready")
	}
	// Failed initialization may have attempted registration, but dispatch through
	// the real syncer must still have no SAS handler and must not create a timer.
	s.gate.active = true
	sasRequest(c, "unregistered", c.UserID, "OTHER", time.Now().Add(time.Minute))
	if all, _ := s.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
		t.Fatal("partially initialized handlers were installed")
	}
	if err := s.init(context.Background()); err != nil || s.helper == nil {
		t.Fatal("initialization retry failed")
	}
	if err := s.init(context.Background()); err != nil {
		t.Fatal("successful initialization not idempotent")
	}
	sasRequest(c, "registered-once", c.UserID, "OTHER", time.Now().Add(time.Minute))
	if all, _ := s.store.GetAllVerificationTransactions(context.Background()); len(all) != 1 {
		t.Fatal("successful retry did not register handler exactly once")
	}
	s.stop()
}

func TestSASRejectsReuseAfterDeadlineWhileOldTimerSleeps(t *testing.T) {
	c, s, _, stop := sasTestClient(t)
	defer stop()
	// The helper's old timer remains asleep after local cancellation. Move the
	// gate's recorded deadline into the past to model a timer delayed past expiry;
	// the old implementation deleted this entry and admitted the reused ID.
	sasRequest(c, "delayed-timer", c.UserID, "OTHER", time.Now().Add(time.Minute))
	sasWait(t, func() bool { return s.Snapshot().State == SASRequested })
	if err := s.Cancel(context.Background(), "delayed-timer"); err != nil {
		t.Fatal("cancel failed")
	}
	s.gate.mu.Lock()
	s.gate.recent["delayed-timer"] = time.Now().Add(-time.Minute)
	s.gate.mu.Unlock()
	sasRequest(c, "delayed-timer", c.UserID, "OTHER", time.Now().Add(time.Minute))
	if all, _ := s.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
		t.Fatal("expired-deadline ID reused while old worker might still run")
	}
	if s.Snapshot().State != SASCancelled {
		t.Fatal("reused request changed the cancelled attempt")
	}
}

func TestAwaitSASRetainsFirstTerminalOutcomeAcrossCoalescedRequests(t *testing.T) {
	for _, terminal := range []SASState{SASDone, SASCancelled, SASFailed} {
		t.Run(string(terminal), func(t *testing.T) {
			s := newSASController(&Client{})
			if err := s.prepareAwait(); err != nil {
				t.Fatal("prepare failed")
			}
			s.set(SASRequested, "first", "OTHER", nil, "")
			s.set(terminal, "first", "OTHER", nil, "")
			s.set(SASRequested, "second", "THIRD", nil, "")
			if s.Snapshot().TransactionID != "second" {
				t.Fatal("public snapshots stopped supporting repeated attempts")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := awaitSAS(ctx, s, make(chan error, 1), func([]SASEmoji) bool { t.Fatal("confirmed a later transaction"); return false })
			switch terminal {
			case SASDone:
				if err != nil {
					t.Fatal("lost first success")
				}
			case SASCancelled:
				if !errors.Is(err, ErrSASCancelled) {
					t.Fatal("lost first cancellation")
				}
			case SASFailed:
				if !errors.Is(err, ErrSASOperation) {
					t.Fatal("lost first failure")
				}
			}
		})
	}
}

func TestAwaitSASRetainsRequestCancelledBeforeCallbackConsumption(t *testing.T) {
	s := newSASController(&Client{Client: &mautrix.Client{UserID: "@fixture:example.invalid", DeviceID: "DEVICE"}})
	if err := s.prepareAwait(); err != nil {
		t.Fatal("prepare failed")
	}
	s.runCtx = context.Background()
	// No helper transaction remains, as when cancellation was delivered in the
	// same sync batch before the controller consumed its request callback.
	s.handle(sasEvent{txn: "first", requested: true, from: s.client.UserID, fromDevice: "OTHER"})
	s.set(SASRequested, "second", "THIRD", nil, "")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := awaitSAS(ctx, s, make(chan error, 1), func([]SASEmoji) bool { return true }); !errors.Is(err, ErrSASCancelled) {
		t.Fatal("skipped already-cancelled first request")
	}
}
