package rihma

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// roomSends adds the media upload and room send endpoints to a testHS.
// Like a homeserver, it answers a transaction id it has seen with the
// event it first created, and records every send it receives.
type roomSends struct {
	mu      sync.Mutex
	uploads int
	byTxn   map[string]id.EventID
	sends   []roomSend // every PUT, repeats included
	events  []roomSend // the events it created
}

type roomSend struct {
	evtType string
	txn     string
}

func newRoomSends(h *testHS) *roomSends {
	s := &roomSends{byTxn: map[string]id.EventID{}}
	h.ms.Router.HandleFunc("POST /_matrix/media/v3/upload", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		s.uploads++
		n := s.uploads
		s.mu.Unlock()
		fmt.Fprintf(w, `{"content_uri":"mxc://localhost/upload%d"}`, n)
	})
	h.ms.Router.HandleFunc("PUT /_matrix/client/v3/rooms/{roomID}/send/{type}/{txn}", func(w http.ResponseWriter, r *http.Request) {
		send := roomSend{r.PathValue("type"), r.PathValue("txn")}
		s.mu.Lock()
		s.sends = append(s.sends, send)
		evt, seen := s.byTxn[send.txn]
		if !seen {
			s.events = append(s.events, send)
			evt = id.EventID(fmt.Sprintf("$event%d", len(s.events)))
			s.byTxn[send.txn] = evt
		}
		s.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]id.EventID{"event_id": evt})
	})
	return s
}

func (s *roomSends) snapshot() (uploads int, sends, events []roomSend) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uploads, append([]roomSend(nil), s.sends...), append([]roomSend(nil), s.events...)
}

// TestSendMediaTransactionID: a TransactionID reaches the wire as the
// send's transaction id, so a repeat returns the first event and posts
// no second one, in an unencrypted and an encrypted room; the upload
// repeats. An empty id sends twice under two fresh ids.
func TestSendMediaTransactionID(t *testing.T) {
	for _, tc := range []struct {
		name      string
		encrypted bool
		wantType  string
	}{
		{"unencrypted", false, event.EventMessage.Type},
		{"encrypted", true, event.EventEncrypted.Type},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			h := newTestHS(t)
			sends := newRoomSends(h)
			c, err := Open(ctx, testOptions(t, h, t.TempDir()))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := c.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			room := id.RoomID("!media:localhost")
			if err := c.StateStore.SetMembership(ctx, room, c.UserID, event.MembershipJoin); err != nil {
				t.Fatal(err)
			}
			if tc.encrypted {
				if err := c.StateStore.SetEncryptionEvent(ctx, room, &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}); err != nil {
					t.Fatal(err)
				}
			}
			m := Media{Data: []byte("a file"), Name: "a.txt", MimeType: "text/plain", MsgType: event.MsgFile}

			keyed := m
			keyed.TransactionID = "airut-key-1"
			first, err := c.SendMedia(ctx, room, keyed)
			if err != nil {
				t.Fatal(err)
			}
			again, err := c.SendMedia(ctx, room, keyed)
			if err != nil {
				t.Fatal(err)
			}
			if first != again {
				t.Fatalf("a repeated transaction id returned %s, then %s", first, again)
			}
			uploads, wire, events := sends.snapshot()
			if uploads != 2 {
				t.Fatalf("%d uploads for two sends, want 2: the upload is not idempotent", uploads)
			}
			want := roomSend{tc.wantType, "airut-key-1"}
			if len(wire) != 2 || wire[0] != want || wire[1] != want {
				t.Fatalf("sends on the wire = %+v, want two of %+v", wire, want)
			}
			if len(events) != 1 {
				t.Fatalf("a repeated transaction id created %d events, want 1", len(events))
			}

			a, err := c.SendMedia(ctx, room, m)
			if err != nil {
				t.Fatal(err)
			}
			b, err := c.SendMedia(ctx, room, m)
			if err != nil {
				t.Fatal(err)
			}
			_, wire, events = sends.snapshot()
			if a == b || len(events) != 3 {
				t.Fatalf("without a transaction id: events %s and %s, %d created in all, want distinct and 3", a, b, len(events))
			}
			if fresh := wire[2:]; fresh[0].txn == "" || fresh[0].txn == fresh[1].txn || fresh[0].txn == want.txn {
				t.Fatalf("without a transaction id the sends used %+v, want two fresh ids", fresh)
			}
			for _, s := range wire {
				if s.evtType != tc.wantType {
					t.Fatalf("sent %s, want %s", s.evtType, tc.wantType)
				}
			}
		})
	}
}
