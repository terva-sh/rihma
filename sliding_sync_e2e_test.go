//go:build e2e

package rihma

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Test-only experimental Synapse dialect, not a production sync transport.
// Retain raw sections: translating only the timeline would lose list and crypto data.
type slidingProbeResponse struct {
	Pos        string                        `json:"pos"`
	Lists      map[string]json.RawMessage    `json:"lists"`
	Rooms      map[id.RoomID]json.RawMessage `json:"rooms"`
	Extensions map[string]json.RawMessage    `json:"extensions"`
}

func requestSlidingProbe(ctx context.Context, cli *mautrix.Client, pos string, timeout int) (*slidingProbeResponse, error) {
	query := map[string]string{"timeout": strconv.Itoa(timeout)}
	if pos != "" {
		query["pos"] = pos
	}
	body := map[string]any{
		"conn_id": "rihma-test",
		"lists": map[string]any{"recent": map[string]any{
			"ranges": [][2]int{{0, 9}}, "timeline_limit": 10,
			"required_state": [][2]string{{"m.room.create", ""}, {"m.room.member", "$ME"}},
		}},
		"extensions": map[string]any{
			"to_device": map[string]any{"enabled": true},
			"e2ee":      map[string]any{"enabled": true},
		},
	}
	var response slidingProbeResponse
	log := zerolog.Nop()
	_, err := cli.MakeFullRequest(ctx, mautrix.FullRequest{
		Method:      http.MethodPost,
		URL:         cli.BuildURLWithQuery(mautrix.ClientURLPath{"unstable", "org.matrix.simplified_msc3575", "sync"}, query),
		RequestJSON: body, ResponseJSON: &response, MaxAttempts: 1,
		SensitiveContent: true, Logger: &log, ResponseSizeLimit: 1 << 20,
	})
	// A cancelled exchange never supplies a cursor, even if HTTP completed concurrently.
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if response.Pos == "" {
		return nil, errors.New("missing sliding position")
	}
	return &response, nil
}

func TestSlidingProbeCancelsInflightHTTP(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	shutdown := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Consume the body before waiting, allowing net/http to detect disconnect.
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			return
		}
		close(entered)
		select {
		case <-r.Context().Done():
		case <-shutdown:
		}
		close(exited)
	}))
	defer func() {
		close(shutdown)
		server.Close()
	}()
	cli, err := mautrix.NewClient(server.URL, "", "")
	if err != nil {
		t.Fatal("client preparation failed")
	}
	cli.Log = zerolog.Nop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		response, err := requestSlidingProbe(ctx, cli, "processed-position", 30000)
		if response != nil {
			done <- errors.New("cancelled response admitted")
			return
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not arrive")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation was not preserved")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not stop")
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP request was not cancelled")
	}
}

func TestE2ESimplifiedSlidingSyncWire(t *testing.T) {
	hs := e2eHomeserver(t)
	u, err := url.Parse(hs)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || os.Getenv("RIHMA_E2E_DISPOSABLE") != "1" {
		t.Skip("owned loopback fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cli, err := mautrix.NewClient(hs, "", "")
	if err != nil {
		t.Fatal("client preparation failed")
	}
	cli.Log = zerolog.Nop()
	versions, err := cli.Versions(ctx)
	if err != nil {
		t.Fatal("version discovery failed")
	}
	if !versions.UnstableFeatures["org.matrix.simplified_msc3575"] {
		t.Skip("simplified sliding capability absent")
	}
	account := "sliding-" + e2eTag()
	login, err := cli.RegisterDummy(ctx, &mautrix.ReqRegister[any]{Username: account, Password: "disposable-test-password"})
	if err != nil {
		t.Fatal("registration failed")
	}
	cli.UserID, cli.DeviceID, cli.AccessToken = login.UserID, login.DeviceID, login.AccessToken
	room, err := cli.CreateRoom(ctx, &mautrix.ReqCreateRoom{Preset: "private_chat"})
	if err != nil {
		t.Fatal("room creation failed")
	}
	initial, err := requestSlidingProbe(ctx, cli, "", 0)
	if err != nil {
		t.Fatal("initial sliding request failed")
	}
	var list struct {
		Count int `json:"count"`
		Ops   []struct {
			Op      string      `json:"op"`
			RoomIDs []id.RoomID `json:"room_ids"`
		} `json:"ops"`
	}
	if json.Unmarshal(initial.Lists["recent"], &list) != nil || list.Count != 1 || len(list.Ops) != 1 || list.Ops[0].Op != "SYNC" || len(list.Ops[0].RoomIDs) != 1 || list.Ops[0].RoomIDs[0] != room.RoomID {
		t.Fatal("experimental list operation shape did not match")
	}
	var roomData struct {
		Initial       bool              `json:"initial"`
		RequiredState []json.RawMessage `json:"required_state"`
	}
	if json.Unmarshal(initial.Rooms[room.RoomID], &roomData) != nil || !roomData.Initial || len(roomData.RequiredState) < 2 {
		t.Fatal("initial room state absent")
	}
	var toDevice struct {
		NextBatch string `json:"next_batch"`
	}
	var e2ee map[string]json.RawMessage
	if json.Unmarshal(initial.Extensions["to_device"], &toDevice) != nil || toDevice.NextBatch == "" || json.Unmarshal(initial.Extensions["e2ee"], &e2ee) != nil || e2ee["device_one_time_keys_count"] == nil {
		t.Fatal("required extension shapes absent")
	}
	// This only proves plaintext wire delivery. No encryption/decryption is claimed.
	sent, err := cli.SendMessageEvent(ctx, room.RoomID, event.EventMessage, &event.MessageEventContent{MsgType: event.MsgText, Body: "synthetic fixture message"})
	if err != nil {
		t.Fatal("fixture event send failed")
	}
	continued, err := requestSlidingProbe(ctx, cli, initial.Pos, 0)
	if err != nil {
		t.Fatal("continuation failed")
	}
	var delta struct {
		Timeline []*event.Event `json:"timeline"`
	}
	if json.Unmarshal(continued.Rooms[room.RoomID], &delta) != nil {
		t.Fatal("room delta absent")
	}
	found := false
	for _, ev := range delta.Timeline {
		if ev.ID == sent.EventID {
			found = true
		}
	}
	if !found || continued.Pos == initial.Pos {
		t.Fatal("event delta or position advancement absent")
	}
	// A malformed position is refused. Never print error bodies or positions.
	_, err = requestSlidingProbe(ctx, cli, "invalid-test-position", 0)
	var refusal mautrix.HTTPError
	if !errors.As(err, &refusal) || !refusal.IsStatus(http.StatusBadRequest) || refusal.RespError == nil || refusal.RespError.ErrCode != "M_UNKNOWN" {
		t.Fatal("invalid position did not receive the observed Matrix 400/M_UNKNOWN refusal")
	}
	// Sequential long polls drain pending updates before cancellation. No second
	// request is started until the preceding exchange has stopped.
	pollCtx, stopPoll := context.WithTimeout(ctx, 100*time.Millisecond)
	defer stopPoll()
	pos := continued.Pos
	for {
		response, err := requestSlidingProbe(pollCtx, cli, pos, 30000)
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) || response != nil {
				t.Fatal("poll cancellation failed")
			}
			break
		}
		pos = response.Pos
	}
	if _, err := requestSlidingProbe(ctx, cli, pos, 0); err != nil {
		t.Fatal("resume from last processed position failed")
	}
}
