package rihma

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

// TestBackupSessionDataRoundTrip: what the uploader sends decrypts with
// the backup key and imports with mautrix's own backup reader, as the
// same session.
func TestBackupSessionDataRoundTrip(t *testing.T) {
	out, err := olm.NewOutboundGroupSession()
	if err != nil {
		t.Fatal(err)
	}
	igs, err := crypto.NewInboundGroupSession("sender-curve", "sender-ed", "!r:hs", out.Key(), 0, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	key, err := backup.NewMegolmBackupKey()
	if err != nil {
		t.Fatal(err)
	}

	data, err := backupSessionData(key, igs)
	if err != nil {
		t.Fatal(err)
	}
	if data.FirstMessageIndex != 0 || data.ForwardedCount != 0 {
		t.Fatalf("index %d, forwarded %d", data.FirstMessageIndex, data.ForwardedCount)
	}
	var enc backup.EncryptedSessionData[backup.MegolmSessionData]
	if err := json.Unmarshal(data.SessionData, &enc); err != nil {
		t.Fatal(err)
	}
	plain, err := enc.Decrypt(key)
	if err != nil {
		t.Fatal(err)
	}
	if plain.SenderKey != "sender-curve" || plain.SenderClaimedKeys.Ed25519 != "sender-ed" || plain.ForwardingKeyChain == nil {
		t.Fatalf("session data = %+v", plain)
	}
	var mach crypto.OlmMachine
	got, err := mach.ImportRoomKeyFromBackupWithoutSaving(t.Context(), "1", "!r:hs", nil, igs.ID(), plain)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID() != igs.ID() || got.RoomID != id.RoomID("!r:hs") {
		t.Fatalf("imported %s in %s, want %s", got.ID(), got.RoomID, igs.ID())
	}

	other, _ := backup.NewMegolmBackupKey()
	if _, err := enc.Decrypt(other); err == nil {
		t.Fatal("another backup key decrypted the session")
	}
}

// Other clients send the backup key as unpadded base64; tolerate padding and
// surrounding space, and refuse anything that is not a 32-byte key.
func TestParseBackupSecret(t *testing.T) {
	key, err := backup.NewMegolmBackupKey()
	if err != nil {
		t.Fatal(err)
	}
	raw := base64.RawStdEncoding.EncodeToString(key.Bytes())
	for _, secret := range []string{raw, base64.StdEncoding.EncodeToString(key.Bytes()), " " + raw + "\n"} {
		got, ok := parseBackupSecret(secret)
		if !ok || backupPublicKey(got) != backupPublicKey(key) {
			t.Fatal("a well-formed backup key was refused")
		}
	}
	for _, secret := range []string{"", "not base64!", base64.RawStdEncoding.EncodeToString([]byte("short"))} {
		if _, ok := parseBackupSecret(secret); ok {
			t.Fatal("a malformed backup key was accepted")
		}
	}
}
