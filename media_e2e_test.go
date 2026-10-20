//go:build e2e

package rihma

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// TestE2ESendMediaTransactionID: against the throwaway Synapse, two
// SendMedia calls with one TransactionID return one event id and leave
// one event in the room, in an unencrypted and an encrypted room, while
// two calls without one post twice.
func TestE2ESendMediaTransactionID(t *testing.T) {
	hs := e2eHomeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tag := e2eTag()
	name := "media-txn-" + tag
	register(t, ctx, hs, name, "pw-media")
	c := openAndSync(t, ctx, e2eOptions(t, hs, name, "pw-media", t.TempDir()), nil)
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		encrypted bool
		wantType  string
	}{
		{"unencrypted", false, event.EventMessage.Type},
		{"encrypted", true, event.EventEncrypted.Type},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &mautrix.ReqCreateRoom{Preset: "private_chat"}
			if tc.encrypted {
				req.InitialState = []*event.Event{{
					Type:    event.StateEncryption,
					Content: event.Content{Parsed: &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}},
				}}
			}
			resp, err := c.CreateRoom(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			room := resp.RoomID
			waitJoined(t, ctx, c.Client, room, c.UserID)
			for tc.encrypted {
				if ok, err := c.StateStore.IsEncrypted(ctx, room); err == nil && ok {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("the room's encryption never reached the state store")
				case <-time.After(200 * time.Millisecond):
				}
			}

			m := Media{Data: []byte("a file " + tag), Name: "a.txt", MimeType: "text/plain", MsgType: event.MsgFile}
			keyed := m
			keyed.TransactionID = "rihma-e2e-" + tc.name + "-" + tag
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
			if got := roomEventsFrom(t, ctx, hs, c.AccessToken, room, c.UserID, tc.wantType); len(got) != 1 || got[0] != first {
				t.Fatalf("after two keyed sends the room holds %v, want only %s", got, first)
			}

			a, err := c.SendMedia(ctx, room, m)
			if err != nil {
				t.Fatal(err)
			}
			b, err := c.SendMedia(ctx, room, m)
			if err != nil {
				t.Fatal(err)
			}
			if a == b || a == first || b == first {
				t.Fatalf("without a transaction id: %s and %s after %s, want three distinct", a, b, first)
			}
			if got := roomEventsFrom(t, ctx, hs, c.AccessToken, room, c.UserID, tc.wantType); len(got) != 3 {
				t.Fatalf("the room holds %d media events, want 3: %v", len(got), got)
			}
			if tc.encrypted {
				if got := roomEventsFrom(t, ctx, hs, c.AccessToken, room, c.UserID, event.EventMessage.Type); len(got) != 0 {
					t.Fatalf("cleartext m.room.message in an encrypted room: %v", got)
				}
			}
		})
	}
}

// roomEventsFrom reads the room's timeline straight from the homeserver,
// bypassing mautrix, and returns the ids of sender's events of evtType,
// newest first.
func roomEventsFrom(t *testing.T, ctx context.Context, hs, token string, room id.RoomID, sender id.UserID, evtType string) []id.EventID {
	t.Helper()
	u := fmt.Sprintf("%s/_matrix/client/v3/rooms/%s/messages?dir=b&limit=50", strings.TrimRight(hs, "/"), url.PathEscape(room.String()))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("messages: %d %v", resp.StatusCode, err)
	}
	var page struct {
		Chunk []struct {
			Type    string     `json:"type"`
			Sender  id.UserID  `json:"sender"`
			EventID id.EventID `json:"event_id"`
		} `json:"chunk"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatal(err)
	}
	var ids []id.EventID
	for _, e := range page.Chunk {
		if e.Type == evtType && e.Sender == sender {
			ids = append(ids, e.EventID)
		}
	}
	return ids
}
