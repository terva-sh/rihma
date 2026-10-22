//go:build e2e

package rihma

import (
	"context"
	"errors"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// After a cross-signing reset on Synapse, the old backup is out of reach of
// the new recovery key. Carry brings it back: a new device restores it with
// the new recovery key, trusts it through the new master key's signature,
// and decrypts history sent before the reset. Replace then swaps in a new
// backup: the old version is gone, the device refills the new one, and a
// further new device reads the same history from it. The account is
// disposable; assertions print no keys or message bodies.
func TestE2EKeyBackupAfterReset(t *testing.T) {
	hs := e2eHomeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	name, pw := "bkreset-"+e2eTag(), "pw-bkreset"
	register(t, ctx, hs, name, pw)
	opts := func() Options {
		o := e2eOptions(t, hs, name, pw, t.TempDir())
		o.SyncPolicy = SyncPolicyFullClient
		return o
	}

	a := openAndSync(t, ctx, opts(), nil)
	oldKey, err := a.CreateRecoveryKey(ctx, "")
	if err != nil {
		t.Fatalf("first identity: %v", err)
	}
	if err := a.EnableKeyBackup(ctx, oldKey); err != nil {
		t.Fatalf("enable backup: %v", err)
	}
	version := a.KeyBackupVersion()
	created, err := a.CreateRoom(ctx, &mautrix.ReqCreateRoom{Preset: "private_chat", InitialState: []*event.Event{{Type: event.StateEncryption, Content: event.Content{Parsed: &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}}}}})
	if err != nil {
		t.Fatal("encrypted room failed")
	}
	room := created.RoomID
	liveSASWait(t, ctx, func() bool { ok, err := a.StateStore.IsEncrypted(ctx, room); return err == nil && ok })
	history := sendText(t, ctx, a.Client, room, "before the reset")
	waitBackupCount(t, ctx, a.Client, 1)

	newKey, err := a.ResetCrossSigningIdentity(ctx, CrossSigningAuth{Password: pw})
	if err != nil {
		t.Fatalf("reset: %v", err)
	}

	// restored opens a device and restores the identity with the new key.
	restored := func() *Client {
		t.Helper()
		c, err := Open(ctx, opts())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		if err := c.RestoreFromRecoveryKey(ctx, newKey); err != nil {
			t.Fatalf("restore identity with the new recovery key: %v", err)
		}
		return c
	}
	// readsHistory: the device restores the backup with the new recovery
	// key, trusting it by signature, and decrypts the message sent before
	// the reset.
	readsHistory := func(c *Client, want id.KeyBackupVersion) {
		t.Helper()
		if _, err := c.OlmMachine().GetAndVerifyLatestKeyBackupVersion(ctx, nil); err != nil {
			t.Fatalf("a device of the new identity does not trust the backup by signature: %v", err)
		}
		if err := c.RestoreKeyBackup(ctx, newKey); err != nil {
			t.Fatalf("restore backup with the new recovery key: %v", err)
		}
		if c.KeyBackupVersion() != want {
			t.Fatalf("restored backup %q, want %q", c.KeyBackupVersion(), want)
		}
		evt, err := c.GetEvent(ctx, room, history)
		if err != nil {
			t.Fatal("history fetch failed")
		}
		if evt.Content.Parsed == nil {
			if err := evt.Content.ParseRaw(evt.Type); err != nil {
				t.Fatal("history parse failed")
			}
		}
		dec, err := c.OlmMachine().DecryptMegolmEvent(ctx, evt)
		if err != nil || dec.Content.AsMessage().Body != "before the reset" {
			t.Fatal("cannot read history from the backup with the new recovery key")
		}
	}

	stranded := restored()
	if err := stranded.RestoreKeyBackup(ctx, newKey); err == nil {
		t.Fatal("the new recovery key restored the backup before any repair")
	}

	if err := a.CarryKeyBackup(ctx, newKey); err != nil {
		t.Fatalf("carry: %v", err)
	}
	latest, err := a.GetKeyBackupLatestVersion(ctx)
	if err != nil || latest.Version != version {
		t.Fatalf("latest backup after carry %v, %v; want %q", latest, err, version)
	}
	master := a.OlmMachine().CrossSigningKeys.MasterKey.PublicKey()
	if ok, err := signatures.VerifySignatureJSON(latest.AuthData, a.UserID, master.String(), master); err != nil || !ok {
		t.Fatalf("carried backup not signed by the new master key: %v", err)
	}
	readsHistory(restored(), version)

	if err := a.ReplaceKeyBackup(ctx, newKey); err != nil {
		t.Fatalf("replace: %v", err)
	}
	fresh := a.KeyBackupVersion()
	if fresh == "" || fresh == version {
		t.Fatalf("device on backup %q after replace; want a new one", fresh)
	}
	if _, err := a.GetKeyBackupVersion(ctx, version); !errors.Is(err, mautrix.MNotFound) {
		t.Fatalf("old backup after replace: %v, want M_NOT_FOUND", err)
	}
	waitBackupCount(t, ctx, a.Client, 1) // the sync loop refills it
	readsHistory(restored(), fresh)
}
