package rihma

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func sasDevices(t *testing.T, c *Client, peers ...id.DeviceID) {
	t.Helper()
	devices := map[id.DeviceID]*id.Device{c.DeviceID: c.OlmMachine().OwnIdentity()}
	for _, peer := range peers {
		device := *c.OlmMachine().OwnIdentity()
		device.DeviceID = peer
		devices[peer] = &device
	}
	if err := c.OlmMachine().CryptoStore.PutDevices(context.Background(), c.UserID, devices); err != nil {
		t.Fatal("fixture devices failed")
	}
}

func sasReady(c *Client, txn id.VerificationTransactionID, from id.UserID, device id.DeviceID, methods ...event.VerificationMethod) {
	c.Handlers().Dispatch(context.Background(), &event.Event{Type: event.ToDeviceVerificationReady, Sender: from, Content: event.Content{Parsed: &event.VerificationReadyEventContent{ToDeviceVerificationEvent: event.ToDeviceVerificationEvent{TransactionID: txn}, FromDevice: device, Methods: methods}}})
}

func TestSASOutgoingScopeSelectionAndRepeat(t *testing.T) {
	var mu sync.Mutex
	var requests []mautrix.ReqSendToDevice
	c, s, h, stop := sasTestClient(t, func(w http.ResponseWriter, r *http.Request) bool {
		var req mautrix.ReqSendToDevice
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("request decoding failed")
		}
		mu.Lock()
		requests = append(requests, req)
		mu.Unlock()
		w.Write([]byte(`{}`))
		return true
	})
	defer stop()
	sasDevices(t, c, "OTHER", "THIRD")
	txn, err := s.Start(context.Background())
	if err != nil || txn == "" {
		t.Fatal("start failed")
	}
	if current := s.Snapshot(); current.State != SASSent || current.TransactionID != txn || current.OtherDevice != "" || len(current.Emoji) != 0 {
		t.Fatal("missing safe outgoing snapshot")
	}
	mu.Lock()
	req := requests[0]
	mu.Unlock()
	if len(req.Messages) != 1 || len(req.Messages[c.UserID]) != 2 || req.Messages[c.UserID][c.DeviceID] != nil || req.Messages[c.UserID]["OTHER"] == nil || req.Messages[c.UserID]["THIRD"] == nil {
		t.Fatal("outgoing request escaped eligible own-account devices")
	}
	if _, err := s.Start(context.Background()); !errors.Is(err, ErrSASStale) {
		t.Fatal("concurrent attempt accepted")
	}
	if err := s.Accept(context.Background(), txn); !errors.Is(err, ErrSASStale) {
		t.Fatal("outgoing request treated as incoming")
	}
	sasRequest(c, "busy", c.UserID, "THIRD", time.Now().Add(time.Minute))
	for _, device := range []id.DeviceID{"", c.DeviceID, "UNREQUESTED", id.DeviceID(strings.Repeat("x", 257))} {
		sasReady(c, txn, c.UserID, device, event.VerificationMethodSAS)
	}
	sasReady(c, txn, "@stranger:example.invalid", "OTHER", event.VerificationMethodSAS)
	if s.Snapshot().State != SASSent {
		t.Fatal("invalid readiness changed attempt")
	}
	sasReady(c, txn, c.UserID, "OTHER", event.VerificationMethodSAS)
	sasWait(t, func() bool { return s.Snapshot().State == SASAccepted })
	if s.Snapshot().OtherDevice != "OTHER" {
		t.Fatal("wrong selected peer")
	}
	// A late accepting device or duplicate readiness cannot cancel the selected flow.
	sasReady(c, txn, c.UserID, "THIRD", event.VerificationMethodSAS)
	sasReady(c, txn, c.UserID, "OTHER", event.VerificationMethodSAS)
	if err := s.Cancel(context.Background(), txn); err != nil {
		t.Fatal("outgoing cancellation failed")
	}
	mu.Lock()
	last := requests[len(requests)-1]
	mu.Unlock()
	if len(last.Messages[c.UserID]) != 1 || last.Messages[c.UserID]["OTHER"] == nil {
		t.Fatal("selected cancellation escaped peer")
	}
	next, err := s.Start(context.Background())
	if err != nil || next == txn || next == "" {
		t.Fatal("repeat start failed")
	}
	if err := s.Cancel(context.Background(), txn); !errors.Is(err, ErrSASStale) {
		t.Fatal("stale receipt cancelled new attempt")
	}
	if err := s.Cancel(context.Background(), next); err != nil {
		t.Fatal("pending cancellation failed")
	}
	mu.Lock()
	last = requests[len(requests)-1]
	mu.Unlock()
	if len(last.Messages[c.UserID]) != 2 || last.Messages[c.UserID][c.DeviceID] != nil {
		t.Fatal("pending cancellation did not reach requested peers")
	}
	if len(h.seenSinces()) != 1 {
		t.Fatal("outgoing verification started another sync")
	}
}

func TestSASOutgoingFastReplyAndIncomingAdmission(t *testing.T) {
	var c *Client
	dispatched := make(chan struct{})
	c, s, _, stop := sasTestClient(t, func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "verification.request") {
			return false
		}
		var req mautrix.ReqSendToDevice
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("request decoding failed")
		}
		content := req.Messages[c.UserID]["OTHER"]
		txn, ok := content.Raw["transaction_id"].(string)
		if !ok {
			t.Error("missing outgoing transaction")
		}
		entered := make(chan struct{})
		go func() {
			close(entered)
			sasRequest(c, "competing", c.UserID, "THIRD", time.Now().Add(time.Minute))
			sasReady(c, id.VerificationTransactionID(txn), c.UserID, "OTHER", event.VerificationMethodSAS)
			close(dispatched)
		}()
		<-entered // Dispatch begins while the request has not yet been acknowledged.
		w.Write([]byte(`{}`))
		return true
	})
	defer stop()
	sasDevices(t, c, "OTHER")
	txn, err := s.Start(context.Background())
	if err != nil {
		t.Fatal("fast outgoing request failed")
	}
	<-dispatched
	sasWait(t, func() bool { return s.Snapshot().State == SASAccepted })
	if s.Snapshot().TransactionID != txn {
		t.Fatal("fast reply or competing request replaced receipt")
	}
}

func TestSASOutgoingFailedSendsShareLifetimeBudget(t *testing.T) {
	c, s, h, stop := sasTestClient(t, func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"untrusted remote secret"}`))
		return true
	})
	defer stop()
	sasDevices(t, c, "OTHER")
	for range 64 {
		if txn, err := s.Start(context.Background()); txn != "" || !errors.Is(err, ErrSASOperation) {
			t.Fatal("failed send escaped safe error")
		}
	}
	n := h.requests.Load()
	if _, err := s.Start(context.Background()); !errors.Is(err, ErrSASLimit) {
		t.Fatal("failed-send timer budget not bounded")
	}
	sasRequest(c, "after-budget", c.UserID, "OTHER", time.Now().Add(time.Minute))
	if h.requests.Load() != n {
		t.Fatal("budget exhausted start sent a request")
	}
	if all, _ := s.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
		t.Fatal("incoming request bypassed shared budget")
	}
}

func TestSASOutgoingNoPeerAndCancelledCaller(t *testing.T) {
	c, s, h, stop := sasTestClient(t)
	defer stop()
	sasDevices(t, c)
	n := h.requests.Load()
	if _, err := s.Start(context.Background()); !errors.Is(err, ErrSASOperation) {
		t.Fatal("empty recipient set accepted")
	}
	if h.requests.Load() != n || s.gate.attempts != 0 {
		t.Fatal("no-peer preflight created network work or timer")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled caller started verification")
	}
	unstarted := newSASController(c)
	if _, err := unstarted.Start(context.Background()); !errors.Is(err, ErrSASUnavailable) {
		t.Fatal("start before sync accepted")
	}
}

func TestSASOutgoingStartFailureAndShutdown(t *testing.T) {
	for _, mode := range []string{"start-failure", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			defer close(release)
			c, s, _, stop := sasTestClient(t, func(w http.ResponseWriter, r *http.Request) bool {
				if mode == "start-failure" && strings.Contains(r.URL.Path, "verification.start") {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"untrusted remote secret"}`))
					return true
				}
				if mode == "shutdown" && strings.Contains(r.URL.Path, "verification.request") {
					close(entered)
					select {
					case <-r.Context().Done():
					case <-release:
					}
					return true
				}
				return false
			})
			sasDevices(t, c, "OTHER")
			if mode == "start-failure" {
				defer stop()
				txn, err := s.Start(context.Background())
				if err != nil {
					t.Fatal("request failed")
				}
				sasReady(c, txn, c.UserID, "OTHER", event.VerificationMethodSAS)
				sasWait(t, func() bool { return s.Snapshot().State == SASFailed })
				if s.Snapshot().Reason != "operation_failed" {
					t.Fatal("unsafe start failure")
				}
				if all, _ := s.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
					t.Fatal("failed start retained transaction")
				}
			} else {
				result := make(chan error, 1)
				go func() { _, err := s.Start(context.Background()); result <- err }()
				<-entered
				stopped := make(chan struct{})
				go func() { stop(); close(stopped) }()
				select {
				case <-stopped:
				case <-time.After(3 * time.Second):
					t.Fatal("shutdown did not cancel outgoing command")
				}
				if err := <-result; err == nil {
					t.Fatal("shutdown reported a successful start")
				}
				if _, err := s.Start(context.Background()); !errors.Is(err, ErrSASUnavailable) {
					t.Fatal("start after shutdown accepted")
				}
			}
		})
	}
}

func TestSASOutgoingExpirySurvivesCancellationSendFailure(t *testing.T) {
	c, s, _, stop := sasTestClient(t, func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "verification.cancel") {
			return false
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"untrusted remote secret"}`))
		return true
	})
	defer stop()
	sasDevices(t, c, "OTHER")
	txn, err := s.Start(context.Background())
	if err != nil {
		t.Fatal("start failed")
	}
	// Deliver the owner's expiry wakeup without waiting ten minutes. A failed
	// cancellation send must still clear the local attempt and permit a retry.
	s.callbacks.post(sasEvent{txn: txn, expired: true})
	sasWait(t, func() bool { return s.Snapshot().State == SASCancelled })
	if s.Snapshot().Reason != "timeout" {
		t.Fatal("outgoing timeout lost")
	}
	next, err := s.Start(context.Background())
	if err != nil || next == txn {
		t.Fatal("timeout prevented repeat attempt")
	}
	s.callbacks.post(sasEvent{txn: txn, expired: true})
	if err := s.Cancel(context.Background(), next); !errors.Is(err, ErrSASOperation) {
		t.Fatal("stale expiry affected next attempt or failed cancel escaped")
	}
}

func TestSASOutgoingUnsupportedReadyFailsSafely(t *testing.T) {
	c, s, _, stop := sasTestClient(t)
	defer stop()
	sasDevices(t, c, "OTHER")
	txn, err := s.Start(context.Background())
	if err != nil {
		t.Fatal("start failed")
	}
	sasReady(c, txn, c.UserID, "OTHER", event.VerificationMethodQRCodeScan)
	sasWait(t, func() bool { return s.Snapshot().State == SASFailed })
	if all, _ := s.store.GetAllVerificationTransactions(context.Background()); len(all) != 0 {
		t.Fatal("unsupported method retained transaction")
	}
}
