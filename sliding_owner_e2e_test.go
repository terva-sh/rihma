//go:build e2e

package rihma

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func requireSlidingFixture(t *testing.T, hs string) {
	t.Helper()
	u, err := url.Parse(hs)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || os.Getenv("RIHMA_E2E_DISPOSABLE") != "1" {
		t.Skip("owned loopback fixture required")
	}
}

func TestE2ESlidingListsAndMembership(t *testing.T) {
	hs := e2eHomeserver(t)
	requireSlidingFixture(t, hs)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	password := "disposable-test-password"
	inviterName, memberName := "sliding-inviter-"+e2eTag(), "sliding-member-"+e2eTag()
	register(t, ctx, hs, inviterName, password)
	register(t, ctx, hs, memberName, password)
	inviterOpts := e2eOptions(t, hs, inviterName, password, t.TempDir())
	inviterOpts.Logger = zerolog.Nop()
	inviter := openAndSync(t, ctx, inviterOpts, nil)
	opts := e2eOptions(t, hs, memberName, password, t.TempDir())
	opts.Logger, opts.SyncPolicy, opts.SlidingSync = zerolog.Nop(), SyncPolicyFullClient, slidingTestOptions()
	member, err := Open(ctx, opts)
	if err != nil {
		t.Fatal("member open failed")
	}
	defer member.Close()
	var mu sync.Mutex
	observed := make(map[id.RoomID]event.Membership)
	member.Handlers().OnEventType(event.StateMember, func(_ context.Context, ev *event.Event) {
		if ev.StateKey == nil || *ev.StateKey != string(member.UserID) {
			return
		}
		mu.Lock()
		observed[ev.RoomID] = ev.Content.AsMember().Membership
		mu.Unlock()
	})
	stop := runPolicySync(t, member)
	defer stop()
	waitMember := func(room id.RoomID, value event.Membership) {
		waitFor(t, "sliding membership", func() bool { mu.Lock(); defer mu.Unlock(); return observed[room] == value })
	}
	create := func() id.RoomID {
		result, err := inviter.CreateRoom(ctx, &mautrix.ReqCreateRoom{Preset: "private_chat", Invite: []id.UserID{member.UserID}})
		if err != nil {
			t.Fatal("invited room creation failed")
		}
		waitMember(result.RoomID, event.MembershipInvite)
		if _, err = member.JoinRoomByID(ctx, result.RoomID); err != nil {
			t.Fatal("join failed")
		}
		waitMember(result.RoomID, event.MembershipJoin)
		return result.RoomID
	}
	first, second := create(), create()
	waitFor(t, "two-room list", func() bool {
		v := member.SlidingSyncSnapshot()
		return v != nil && v.Counts["recent"] == 2 && len(v.Lists["recent"]) == 2
	})
	if _, err = inviter.SendMessageEvent(ctx, first, event.EventMessage, &event.MessageEventContent{MsgType: event.MsgText, Body: "synthetic list bump"}); err != nil {
		t.Fatal("list bump failed")
	}
	waitFor(t, "reordered list", func() bool {
		v := member.SlidingSyncSnapshot()
		return v != nil && len(v.Lists["recent"]) >= 2 && v.Lists["recent"][0] == first && v.Lists["recent"][1] == second
	})
	if _, err = member.LeaveRoom(ctx, first); err != nil {
		t.Fatal("leave failed")
	}
	waitMember(first, event.MembershipLeave)
	if _, err = inviter.SendMessageEvent(ctx, second, event.EventMessage, &event.MessageEventContent{MsgType: event.MsgText, Body: "synthetic post-leave update"}); err != nil {
		t.Fatal("post-leave update failed")
	}
	waitFor(t, "shrunk list", func() bool {
		v := member.SlidingSyncSnapshot()
		return v != nil && v.Counts["recent"] == 1 && len(v.Lists["recent"]) == 1 && v.Lists["recent"][0] == second
	})
	stop()
}

func TestE2ESlidingLateResponseCancellation(t *testing.T) {
	hs := e2eHomeserver(t)
	requireSlidingFixture(t, hs)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	name, password := "sliding-cancel-"+e2eTag(), "disposable-test-password"
	register(t, ctx, hs, name, password)
	opts := e2eOptions(t, hs, name, password, t.TempDir())
	opts.Logger, opts.SlidingSync = zerolog.Nop(), slidingTestOptions()
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal("open failed")
	}
	defer c.Close()
	syncCtx, stop := context.WithCancel(ctx)
	defer stop()
	original := c.Client.Client.Transport
	if original == nil {
		original = http.DefaultTransport
	}
	var abandoned bool
	c.Client.Client.Transport = slidingRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := original.RoundTrip(r)
		if err == nil && strings.HasSuffix(r.URL.Path, "simplified_msc3575/sync") {
			// Let the pinned server finish successfully, then cancel the owner before
			// it can accept that response. Returning success must not acknowledge it.
			abandoned = resp.StatusCode == http.StatusOK
			stop()
		}
		return resp, err
	})
	if err = c.Sync(syncCtx); !errors.Is(err, context.Canceled) || !abandoned {
		t.Fatal("late server success was not cancelled")
	}
	identity := slidingFingerprint([]string{c.HomeserverURL.String(), string(c.UserID), string(c.DeviceID), string(opts.SlidingSync.Dialect)})
	disk, err := openSlidingDisk(ctx, filepath.Join(opts.StateDir, "sliding.db"), c.session.PickleKey, identity)
	if err != nil {
		t.Fatal("recovery open failed")
	}
	defer disk.db.Close()
	record, err := disk.load(ctx)
	if err != nil || record.Cursor != (SlidingSyncCursor{}) || len(record.Pending) != 0 {
		t.Fatal("abandoned server response staged or acknowledged")
	}
}
