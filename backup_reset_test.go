package rihma

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/crypto/ssss"
	"maunium.net/go/mautrix/id"
)

// backupHS adds the server-side key backup endpoints mautrix's mockserver
// lacks to uiaHS, answering the way Synapse does: only the latest version
// takes uploads, an unknown version is M_NOT_FOUND, and an auth data update
// must name the same version and algorithm.
type backupHS struct {
	*uiaHS

	bmu      sync.Mutex
	versions map[id.KeyBackupVersion]*fakeBackup
	next     int
	fails    map[string]int // "METHOD version" or "METHOD keys" -> remaining 400s
	// lostWrites commits the next writes of the backup key's secret but
	// answers 504, as a write whose answer was lost; failedReads answers
	// the next reads of it with 504.
	lostWrites, failedReads int
}

type fakeBackup struct {
	algorithm id.KeyBackupAlgorithm
	auth      json.RawMessage
	keys      map[id.RoomID]map[id.SessionID]json.RawMessage
}

func newBackupHS(t *testing.T) *backupHS {
	b := &backupHS{uiaHS: newUIAHS(t, "password"), versions: map[id.KeyBackupVersion]*fakeBackup{}, fails: map[string]int{}}
	r := b.ms.Router
	r.HandleFunc("GET /_matrix/client/v3/room_keys/version", b.guard("GET version", b.getLatest))
	r.HandleFunc("POST /_matrix/client/v3/room_keys/version", b.guard("POST version", b.create))
	r.HandleFunc("GET /_matrix/client/v3/room_keys/version/{version}", b.guard("GET version", b.getVersion))
	r.HandleFunc("PUT /_matrix/client/v3/room_keys/version/{version}", b.guard("PUT version", b.update))
	r.HandleFunc("DELETE /_matrix/client/v3/room_keys/version/{version}", b.guard("DELETE version", b.delete))
	r.HandleFunc("PUT /_matrix/client/v3/room_keys/keys", b.guard("PUT keys", b.putKeys))
	r.HandleFunc("GET /_matrix/client/v3/room_keys/keys", b.guard("GET keys", b.getKeys))
	inner := b.ms.Server.Config.Handler
	b.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/account_data/m.megolm_backup.v1") {
			inner.ServeHTTP(w, r)
			return
		}
		b.bmu.Lock()
		lose := r.Method == http.MethodPut && b.lostWrites > 0
		fail := r.Method == http.MethodGet && b.failedReads > 0
		if lose {
			b.lostWrites--
		}
		if fail {
			b.failedReads--
		}
		b.bmu.Unlock()
		switch {
		case fail:
			w.WriteHeader(http.StatusGatewayTimeout)
		case lose:
			inner.ServeHTTP(httptest.NewRecorder(), r)
			w.WriteHeader(http.StatusGatewayTimeout)
		default:
			inner.ServeHTTP(w, r)
		}
	})
	return b
}

func (b *backupHS) set(f func(b *backupHS)) {
	b.bmu.Lock()
	f(b)
	b.bmu.Unlock()
}

func (b *backupHS) failNextBackup(op string, n int) {
	b.bmu.Lock()
	b.fails[op] = n
	b.bmu.Unlock()
}

func (b *backupHS) guard(op string, h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b.bmu.Lock()
		defer b.bmu.Unlock()
		if b.fails[op] > 0 {
			b.fails[op]--
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"injected"}`))
			return
		}
		h(w, r)
	}
}

func notFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"errcode":"M_NOT_FOUND","error":"Unknown backup version"}`))
}

// latest runs under bmu.
func (b *backupHS) latest() id.KeyBackupVersion {
	best := -1
	for v := range b.versions {
		if n, _ := strconv.Atoi(string(v)); n > best {
			best = n
		}
	}
	if best < 0 {
		return ""
	}
	return id.KeyBackupVersion(strconv.Itoa(best))
}

func (b *backupHS) writeVersion(w http.ResponseWriter, v id.KeyBackupVersion) {
	fb := b.versions[v]
	if fb == nil {
		notFound(w)
		return
	}
	count := 0
	for _, room := range fb.keys {
		count += len(room)
	}
	json.NewEncoder(w).Encode(map[string]any{
		"algorithm": fb.algorithm, "auth_data": fb.auth, "count": count, "etag": strconv.Itoa(count), "version": v,
	})
}

func (b *backupHS) getLatest(w http.ResponseWriter, _ *http.Request) {
	b.writeVersion(w, b.latest())
}

func (b *backupHS) getVersion(w http.ResponseWriter, r *http.Request) {
	b.writeVersion(w, id.KeyBackupVersion(r.PathValue("version")))
}

func (b *backupHS) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Algorithm id.KeyBackupAlgorithm `json:"algorithm"`
		AuthData  json.RawMessage       `json:"auth_data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.AuthData) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	b.next++
	v := id.KeyBackupVersion(strconv.Itoa(b.next))
	b.versions[v] = &fakeBackup{algorithm: req.Algorithm, auth: req.AuthData, keys: map[id.RoomID]map[id.SessionID]json.RawMessage{}}
	json.NewEncoder(w).Encode(map[string]any{"version": v})
}

func (b *backupHS) update(w http.ResponseWriter, r *http.Request) {
	v := id.KeyBackupVersion(r.PathValue("version"))
	fb := b.versions[v]
	if fb == nil {
		notFound(w)
		return
	}
	var req struct {
		Algorithm id.KeyBackupAlgorithm `json:"algorithm"`
		AuthData  json.RawMessage       `json:"auth_data"`
		Version   id.KeyBackupVersion   `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.AuthData) == 0 ||
		(req.Version != "" && req.Version != v) || req.Algorithm != fb.algorithm {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"errcode":"M_INVALID_PARAM","error":"bad update"}`))
		return
	}
	fb.auth = req.AuthData
	w.Write([]byte(`{}`))
}

func (b *backupHS) delete(w http.ResponseWriter, r *http.Request) {
	v := id.KeyBackupVersion(r.PathValue("version"))
	if b.versions[v] == nil {
		notFound(w)
		return
	}
	delete(b.versions, v)
	w.Write([]byte(`{}`))
}

func (b *backupHS) putKeys(w http.ResponseWriter, r *http.Request) {
	v, latest := id.KeyBackupVersion(r.URL.Query().Get("version")), b.latest()
	if latest == "" {
		notFound(w)
		return
	}
	if v != latest {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"errcode": "M_WRONG_ROOM_KEYS_VERSION", "error": "wrong version", "current_version": latest})
		return
	}
	var req struct {
		Rooms map[id.RoomID]struct {
			Sessions map[id.SessionID]json.RawMessage `json:"sessions"`
		} `json:"rooms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	fb := b.versions[v]
	for room, sessions := range req.Rooms {
		if fb.keys[room] == nil {
			fb.keys[room] = map[id.SessionID]json.RawMessage{}
		}
		for sid, data := range sessions.Sessions {
			fb.keys[room][sid] = data
		}
	}
	w.Write([]byte(`{"etag":"1","count":1}`))
}

func (b *backupHS) getKeys(w http.ResponseWriter, r *http.Request) {
	fb := b.versions[id.KeyBackupVersion(r.URL.Query().Get("version"))]
	if fb == nil {
		notFound(w)
		return
	}
	rooms := map[id.RoomID]map[string]any{}
	for room, sessions := range fb.keys {
		rooms[room] = map[string]any{"sessions": sessions}
	}
	json.NewEncoder(w).Encode(map[string]any{"rooms": rooms})
}

// backupSnapshot is the server's backups plus the account data, for
// asserting that a refused or rolled-back call changed nothing.
type backupSnapshot struct {
	versions map[id.KeyBackupVersion]string
	account  accountState
}

func (b *backupHS) snapshot(t *testing.T, c *Client) backupSnapshot {
	t.Helper()
	s := backupSnapshot{versions: map[id.KeyBackupVersion]string{}, account: b.state(t, c)}
	b.bmu.Lock()
	defer b.bmu.Unlock()
	for v, fb := range b.versions {
		keys, _ := json.Marshal(fb.keys)
		s.versions[v] = string(fb.algorithm) + "|" + string(fb.auth) + "|" + string(keys)
	}
	return s
}

func (b *backupHS) assertSame(t *testing.T, c *Client, before backupSnapshot) {
	t.Helper()
	if after := b.snapshot(t, c); !reflect.DeepEqual(before, after) {
		t.Fatal("the call changed the server's key backups or the account data")
	}
}

func (b *backupHS) versionList() []id.KeyBackupVersion {
	b.bmu.Lock()
	defer b.bmu.Unlock()
	var vs []id.KeyBackupVersion
	for v := range b.versions {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i] < vs[j] })
	return vs
}

func (b *backupHS) authOf(v id.KeyBackupVersion) json.RawMessage {
	b.bmu.Lock()
	defer b.bmu.Unlock()
	if fb := b.versions[v]; fb != nil {
		return append(json.RawMessage(nil), fb.auth...)
	}
	return nil
}

// addRoomKey puts a new inbound room key in c's crypto store, as receiving
// one would.
func addRoomKey(t *testing.T, c *Client, room id.RoomID) id.SessionID {
	t.Helper()
	out, err := olm.NewOutboundGroupSession()
	if err != nil {
		t.Fatal(err)
	}
	igs, err := crypto.NewInboundGroupSession("sender-curve", "sender-ed", room, out.Key(), 0, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.OlmMachine().CryptoStore.PutGroupSession(context.Background(), igs); err != nil {
		t.Fatal(err)
	}
	return igs.ID()
}

const backupRoom = id.RoomID("!backup:localhost")

// failingSaves refuses the next n session saves, as a full disk would.
type failingSaves struct {
	SessionStore
	n int
}

func (f *failingSaves) Save(ctx context.Context, s *Session) error {
	if f.n > 0 {
		f.n--
		return errors.New("injected session save failure")
	}
	return f.SessionStore.Save(ctx, s)
}

// failSessionSaves makes c's next n session saves fail.
func failSessionSaves(c *Client, n int) {
	c.opts.Sessions = &failingSaves{SessionStore: c.opts.Sessions, n: n}
}

// resetWithBackup gives the account an identity, a key backup holding one
// room key, and then a new identity. It returns the uploading device, the
// backup's version, the room key, and the new recovery key.
func resetWithBackup(t *testing.T, b *backupHS) (*Client, id.KeyBackupVersion, id.SessionID, string) {
	t.Helper()
	ctx := context.Background()
	c, oldKey := withIdentity(t, b.uiaHS)
	c.DefaultHTTPRetries = 0
	if err := c.EnableKeyBackup(ctx, oldKey); err != nil {
		t.Fatalf("enable backup: %v", err)
	}
	version := c.KeyBackupVersion()
	sid := addRoomKey(t, c, backupRoom)
	if err := c.uploadBackup(ctx); err != nil {
		t.Fatalf("upload: %v", err)
	}
	newKey, err := c.ResetCrossSigningIdentity(ctx, CrossSigningAuth{Password: testXSPassword})
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	return c, version, sid, newKey
}

// openDevice opens another device of the account. With a recovery key it
// restores the identity from it.
func openDevice(t *testing.T, b *backupHS, recoveryKey string) *Client {
	t.Helper()
	ctx := context.Background()
	c, err := Open(ctx, testOptions(t, b.testHS, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.DefaultHTTPRetries = 0
	if recoveryKey != "" {
		if err := c.RestoreFromRecoveryKey(ctx, recoveryKey); err != nil {
			t.Fatalf("restore identity: %v", err)
		}
	}
	return c
}

// trustsBySignature: a device holding the current identity but not the
// backup key trusts the latest backup's auth data, as a client checking the
// master key's signature does.
func trustsBySignature(t *testing.T, c *Client) bool {
	t.Helper()
	_, err := c.OlmMachine().GetAndVerifyLatestKeyBackupVersion(context.Background(), nil)
	return err == nil
}

// assertBackupWorks: a new device restores the identity and the backup
// with recoveryKey, adopts version, and holds the room key; and the backup
// is trusted through the current master key's signature alone.
func assertBackupWorks(t *testing.T, b *backupHS, recoveryKey string, version id.KeyBackupVersion, sid id.SessionID) {
	t.Helper()
	other := assertRestoresBackup(t, b, recoveryKey, version, sid)
	if !trustsBySignature(t, other) {
		t.Fatal("a client holding only the current identity does not trust the backup")
	}
}

// assertRestoresBackup: a new device restores the identity and the backup
// with recoveryKey, adopts version, and holds the room key; and the only
// signature of this user on the auth data is the current master key's,
// checked over the auth data exactly as the server holds it.
func assertRestoresBackup(t *testing.T, b *backupHS, recoveryKey string, version id.KeyBackupVersion, sid id.SessionID) *Client {
	t.Helper()
	ctx := context.Background()
	other := openDevice(t, b, recoveryKey)
	if err := other.RestoreKeyBackup(ctx, recoveryKey); err != nil {
		t.Fatalf("restore backup with the new recovery key: %v", err)
	}
	if other.KeyBackupVersion() != version {
		t.Fatalf("restored backup %q, want %q", other.KeyBackupVersion(), version)
	}
	if s, err := other.OlmMachine().CryptoStore.GetGroupSession(ctx, backupRoom, sid); err != nil || s == nil {
		t.Fatal("the room key did not come back from the backup")
	}
	master := other.OlmMachine().CrossSigningKeys.MasterKey.PublicKey()
	raw := b.authOf(version)
	var auth struct {
		Signatures signatures.Signatures `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &auth); err != nil {
		t.Fatal(err)
	}
	if mine := auth.Signatures[testUser]; len(mine) != 1 {
		t.Fatalf("this user has %d backup signatures, want only the current master key's", len(mine))
	}
	if ok, err := signatures.VerifySignatureJSON(raw, testUser, master.String(), master); err != nil || !ok {
		t.Fatalf("the backup's auth data is not signed by the current master key: %v", err)
	}
	return other
}

// Before the repair the new recovery key cannot read the backup, and a
// client holding only the new identity does not trust it.
func assertStranded(t *testing.T, b *backupHS, recoveryKey string) {
	t.Helper()
	other := openDevice(t, b, recoveryKey)
	if err := other.RestoreKeyBackup(context.Background(), recoveryKey); err == nil {
		t.Fatal("the new recovery key restored the backup before any repair")
	}
	if trustsBySignature(t, other) {
		t.Fatal("the new identity trusted the old backup's signature")
	}
}

func TestCarryKeyBackupAfterReset(t *testing.T) {
	ctx := context.Background()
	b := newBackupHS(t)
	c, version, sid, newKey := resetWithBackup(t, b)
	assertStranded(t, b, newKey)

	if err := c.CarryKeyBackup(ctx, newKey); err != nil {
		t.Fatalf("carry: %v", err)
	}
	if got := b.versionList(); !reflect.DeepEqual(got, []id.KeyBackupVersion{version}) || c.KeyBackupVersion() != version {
		t.Fatalf("versions %v, device on %q; want only %q", got, c.KeyBackupVersion(), version)
	}
	assertBackupWorks(t, b, newKey, version, sid)
	// Repeating it changes nothing.
	before := b.snapshot(t, c)
	if err := c.CarryKeyBackup(ctx, newKey); err != nil {
		t.Fatalf("second carry: %v", err)
	}
	if got := b.versionList(); !reflect.DeepEqual(got, []id.KeyBackupVersion{version}) {
		t.Fatalf("second carry left versions %v", got)
	}
	// The secret is encrypted afresh, but the ed25519 signature is the same.
	if after := b.snapshot(t, c); !reflect.DeepEqual(before.versions, after.versions) {
		t.Fatal("a repeated carry changed the backup")
	}
}

func TestReplaceKeyBackupAfterReset(t *testing.T) {
	ctx := context.Background()
	b := newBackupHS(t)
	c, version, sid, newKey := resetWithBackup(t, b)
	assertStranded(t, b, newKey)

	if err := c.ReplaceKeyBackup(ctx, newKey); err != nil {
		t.Fatalf("replace: %v", err)
	}
	fresh := c.KeyBackupVersion()
	if got := b.versionList(); fresh == "" || fresh == version || !reflect.DeepEqual(got, []id.KeyBackupVersion{fresh}) {
		t.Fatalf("versions %v, device on %q; want only a new one", got, fresh)
	}
	// This device holds the room key, so it goes into the new backup.
	if err := c.uploadBackup(ctx); err != nil {
		t.Fatal(err)
	}
	assertBackupWorks(t, b, newKey, fresh, sid)
}

// On an account with no backup, replace creates one; carry refuses.
func TestBackupRepairWithoutBackup(t *testing.T) {
	ctx := context.Background()
	b := newBackupHS(t)
	c, key := withIdentity(t, b.uiaHS)
	before := b.snapshot(t, c)
	if err := c.CarryKeyBackup(ctx, key); !errors.Is(err, ErrNoKeyBackup) {
		t.Fatalf("carry without a backup = %v, want ErrNoKeyBackup", err)
	}
	b.assertSame(t, c, before)
	if err := c.ReplaceKeyBackup(ctx, key); err != nil {
		t.Fatalf("replace without a backup: %v", err)
	}
	if got := b.versionList(); len(got) != 1 || c.KeyBackupVersion() != got[0] {
		t.Fatalf("versions %v, device on %q", got, c.KeyBackupVersion())
	}
	sid := addRoomKey(t, c, backupRoom)
	if err := c.uploadBackup(ctx); err != nil {
		t.Fatal(err)
	}
	assertBackupWorks(t, b, key, c.KeyBackupVersion(), sid)
}

func TestBackupRepairPreconditions(t *testing.T) {
	ctx := context.Background()
	b := newBackupHS(t)
	c, version, _, newKey := resetWithBackup(t, b)
	before := b.snapshot(t, c)

	// A device of the new identity that never had the backup key.
	other := openDevice(t, b, newKey)
	if err := other.CarryKeyBackup(ctx, newKey); !errors.Is(err, ErrBackupKeyUnavailable) {
		t.Fatalf("carry without the key = %v, want ErrBackupKeyUnavailable", err)
	}
	// A device without the cross-signing keys.
	bare := openDevice(t, b, "")
	for name, call := range map[string]func(context.Context, string) error{"carry": bare.CarryKeyBackup, "replace": bare.ReplaceKeyBackup} {
		if err := call(ctx, newKey); !errors.Is(err, ErrNoCrossSigningKeys) {
			t.Fatalf("%s without cross-signing keys = %v, want ErrNoCrossSigningKeys", name, err)
		}
	}
	// A well-formed recovery key of some other secret storage key.
	wrong, err := ssss.NewKey("")
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func(context.Context, string) error{"carry": c.CarryKeyBackup, "replace": c.ReplaceKeyBackup} {
		if err := call(ctx, wrong.RecoveryKey()); err == nil {
			t.Fatalf("%s with a wrong recovery key succeeded", name)
		}
	}
	b.assertSame(t, c, before)
	if c.KeyBackupVersion() != version {
		t.Fatal("a refused call moved the device off its backup")
	}

	// Another device resets the identity again: this one's keys are stale.
	newerKey, err := other.ResetCrossSigningIdentity(ctx, CrossSigningAuth{Password: testXSPassword})
	if err != nil {
		t.Fatal(err)
	}
	before = b.snapshot(t, c)
	for name, call := range map[string]func(context.Context, string) error{"carry": c.CarryKeyBackup, "replace": c.ReplaceKeyBackup} {
		if err := call(ctx, newerKey); !errors.Is(err, ErrNoCrossSigningKeys) {
			t.Fatalf("%s with a replaced identity = %v, want ErrNoCrossSigningKeys", name, err)
		}
	}
	b.assertSame(t, c, before)
}

// Carry keeps every auth data field and other users' signatures, and
// replaces this user's with the new master key's.
func TestCarryKeepsAuthDataFields(t *testing.T) {
	ctx := context.Background()
	b := newBackupHS(t)
	c, version, sid, newKey := resetWithBackup(t, b)
	b.bmu.Lock()
	var auth map[string]any
	json.Unmarshal(b.versions[version].auth, &auth)
	auth["private_key_salt"] = "synthetic-salt"
	sigs := auth["signatures"].(map[string]any)
	sigs[string(testUser)].(map[string]any)["ed25519:OLDDEVICE"] = "c3ludGhldGlj"
	sigs["@someone:localhost"] = map[string]any{"ed25519:THEIRS": "c3ludGhldGlj"}
	b.versions[version].auth, _ = json.Marshal(auth)
	b.bmu.Unlock()

	if err := c.CarryKeyBackup(ctx, newKey); err != nil {
		t.Fatalf("carry: %v", err)
	}
	var got map[string]any
	json.Unmarshal(b.authOf(version), &got)
	if got["private_key_salt"] != "synthetic-salt" {
		t.Fatal("carry dropped an auth data field")
	}
	if theirs, _ := got["signatures"].(map[string]any)["@someone:localhost"].(map[string]any); theirs["ed25519:THEIRS"] != "c3ludGhldGlj" {
		t.Fatal("carry dropped another user's signature")
	}
	// mautrix checks a backup signature over the fields it models, so a
	// mautrix client cannot trust this backup through it whoever signed it.
	// The signature covers the whole auth data, as the spec says and as
	// other clients check it.
	assertRestoresBackup(t, b, newKey, version, sid)
}

// Interruption at each step of carry leaves the backup readable, and
// running carry again, from any device of the new identity, finishes it.
func TestCarryKeyBackupInterrupted(t *testing.T) {
	ctx := context.Background()
	t.Run("storing the key", func(t *testing.T) {
		b := newBackupHS(t)
		c, version, sid, newKey := resetWithBackup(t, b)
		before := b.snapshot(t, c)
		b.failAccountData("m.megolm_backup.v1", 1)
		if err := c.CarryKeyBackup(ctx, newKey); err == nil {
			t.Fatal("carry succeeded with a failing secret storage write")
		}
		// Nothing changed: this device still holds the key and uploads.
		b.assertSame(t, c, before)
		if c.KeyBackupVersion() != version {
			t.Fatal("the device left its backup")
		}
		if err := c.CarryKeyBackup(ctx, newKey); err != nil {
			t.Fatalf("carry again: %v", err)
		}
		assertBackupWorks(t, b, newKey, version, sid)
	})
	t.Run("signing", func(t *testing.T) {
		b := newBackupHS(t)
		c, version, sid, newKey := resetWithBackup(t, b)
		b.failNextBackup("PUT version", 1)
		if err := c.CarryKeyBackup(ctx, newKey); err == nil {
			t.Fatal("carry succeeded with a failing auth data update")
		}
		// The new recovery key already restores the backup; only the
		// signature is the old identity's.
		reader := openDevice(t, b, newKey)
		if trustsBySignature(t, reader) {
			t.Fatal("the signature changed although its update failed")
		}
		if err := reader.RestoreKeyBackup(ctx, newKey); err != nil || reader.KeyBackupVersion() != version {
			t.Fatalf("the new recovery key cannot restore the half-carried backup: %v", err)
		}
		// A device that never had the key finishes it from secret storage.
		finisher := openDevice(t, b, newKey)
		if err := finisher.CarryKeyBackup(ctx, newKey); err != nil {
			t.Fatalf("finish the carry from another device: %v", err)
		}
		if finisher.KeyBackupVersion() != version {
			t.Fatal("the finishing device did not adopt the backup")
		}
		assertBackupWorks(t, b, newKey, version, sid)
	})
	t.Run("adopting", func(t *testing.T) {
		// The server's part is done; only this device's session save fails.
		b := newBackupHS(t)
		c, version, sid, newKey := resetWithBackup(t, b)
		failSessionSaves(c, 1)
		if err := c.CarryKeyBackup(ctx, newKey); err == nil {
			t.Fatal("carry succeeded with a failing session save")
		}
		assertBackupWorks(t, b, newKey, version, sid)
		if c.KeyBackupVersion() != version {
			t.Fatal("the device left its backup")
		}
		if err := c.CarryKeyBackup(ctx, newKey); err != nil {
			t.Fatalf("carry again: %v", err)
		}
	})
}

// Interruption at each step of replace leaves a backup some recovery key
// can read, never uploads a room key to a backup none can, and running
// replace again leaves exactly one backup.
func TestReplaceKeyBackupInterrupted(t *testing.T) {
	ctx := context.Background()
	t.Run("creating the version", func(t *testing.T) {
		b := newBackupHS(t)
		c, version, _, newKey := resetWithBackup(t, b)
		before := b.snapshot(t, c)
		b.failNextBackup("POST version", 1)
		if err := c.ReplaceKeyBackup(ctx, newKey); err == nil {
			t.Fatal("replace succeeded with a failing create")
		}
		b.assertSame(t, c, before)
		if c.KeyBackupVersion() != version {
			t.Fatal("the device left its backup")
		}
	})
	t.Run("storing the key", func(t *testing.T) {
		b := newBackupHS(t)
		c, version, sid, newKey := resetWithBackup(t, b)
		before := b.snapshot(t, c)
		b.failAccountData("m.megolm_backup.v1", 1)
		if err := c.ReplaceKeyBackup(ctx, newKey); err == nil {
			t.Fatal("replace succeeded with a failing secret storage write")
		}
		// Rolled back: the old backup is the latest again, untouched, and
		// this device uploads to it.
		b.assertSame(t, c, before)
		if c.KeyBackupVersion() != version {
			t.Fatal("the device left its backup")
		}
		another := addRoomKey(t, c, backupRoom)
		if err := c.uploadBackup(ctx); err != nil {
			t.Fatal(err)
		}
		b.bmu.Lock()
		_, uploaded := b.versions[version].keys[backupRoom][another]
		b.bmu.Unlock()
		if !uploaded {
			t.Fatal("uploads to the old backup did not resume after the rollback")
		}
		if err := c.ReplaceKeyBackup(ctx, newKey); err != nil {
			t.Fatalf("replace again: %v", err)
		}
		if got := b.versionList(); len(got) != 1 || got[0] == version {
			t.Fatalf("versions after the second replace: %v", got)
		}
		if err := c.uploadBackup(ctx); err != nil {
			t.Fatal(err)
		}
		assertBackupWorks(t, b, newKey, c.KeyBackupVersion(), sid)
	})
	t.Run("storing the key, rollback lost", func(t *testing.T) {
		// What a crash between creating the version and storing its key
		// leaves: an empty new version as the latest, the old one beside
		// it, and the old key still in secret storage.
		b := newBackupHS(t)
		c, version, sid, newKey := resetWithBackup(t, b)
		b.failAccountData("m.megolm_backup.v1", 1)
		b.failNextBackup("DELETE version", 1)
		if err := c.ReplaceKeyBackup(ctx, newKey); err == nil {
			t.Fatal("replace succeeded with a failing secret storage write")
		}
		got := b.versionList()
		if len(got) != 2 || c.KeyBackupVersion() != version {
			t.Fatalf("versions %v, device on %q", got, c.KeyBackupVersion())
		}
		// Nothing was uploaded to the version no recovery key can read.
		if err := c.uploadBackup(ctx); err != nil {
			t.Fatal(err)
		}
		b.bmu.Lock()
		orphanKeys := len(b.versions[b.latest()].keys)
		b.bmu.Unlock()
		if orphanKeys != 0 {
			t.Fatal("room keys went into a backup whose key is in no secret storage")
		}
		if err := c.ReplaceKeyBackup(ctx, newKey); err != nil {
			t.Fatalf("replace again: %v", err)
		}
		if got := b.versionList(); len(got) != 1 || got[0] == version || got[0] != c.KeyBackupVersion() {
			t.Fatalf("versions after the second replace: %v", got)
		}
		if err := c.uploadBackup(ctx); err != nil {
			t.Fatal(err)
		}
		assertBackupWorks(t, b, newKey, c.KeyBackupVersion(), sid)
	})
	t.Run("storing the key, answer lost", func(t *testing.T) {
		// The write lands but its answer does not: the old key is gone
		// from secret storage, so the new backup must stay, and replace
		// carries on.
		b := newBackupHS(t)
		c, version, sid, newKey := resetWithBackup(t, b)
		b.set(func(b *backupHS) { b.lostWrites = 1 })
		if err := c.ReplaceKeyBackup(ctx, newKey); err != nil {
			t.Fatalf("replace with a lost write answer: %v", err)
		}
		if got := b.versionList(); len(got) != 1 || got[0] == version || got[0] != c.KeyBackupVersion() {
			t.Fatalf("versions %v, device on %q", got, c.KeyBackupVersion())
		}
		if err := c.uploadBackup(ctx); err != nil {
			t.Fatal(err)
		}
		assertBackupWorks(t, b, newKey, c.KeyBackupVersion(), sid)
	})
	t.Run("storing the key, outcome unknown", func(t *testing.T) {
		// The write lands, its answer is lost, and reading it back fails:
		// nothing is deleted, and the next run converges.
		b := newBackupHS(t)
		c, version, sid, newKey := resetWithBackup(t, b)
		b.set(func(b *backupHS) { b.lostWrites, b.failedReads = 1, 1 })
		if err := c.ReplaceKeyBackup(ctx, newKey); err == nil {
			t.Fatal("replace succeeded although it could not tell whether the key was stored")
		}
		got := b.versionList()
		if len(got) != 2 || got[0] != version || c.KeyBackupVersion() != version {
			t.Fatalf("versions %v, device on %q; want both backups kept", got, c.KeyBackupVersion())
		}
		// The write did land, so the new recovery key reads the new backup.
		reader := openDevice(t, b, newKey)
		if err := reader.RestoreKeyBackup(ctx, newKey); err != nil || reader.KeyBackupVersion() != got[1] {
			t.Fatalf("the new recovery key cannot restore the new backup: %v", err)
		}
		if err := c.ReplaceKeyBackup(ctx, newKey); err != nil {
			t.Fatalf("replace again: %v", err)
		}
		if got := b.versionList(); len(got) != 1 || got[0] != c.KeyBackupVersion() {
			t.Fatalf("versions after the second replace: %v", got)
		}
		if err := c.uploadBackup(ctx); err != nil {
			t.Fatal(err)
		}
		assertBackupWorks(t, b, newKey, c.KeyBackupVersion(), sid)
	})
	t.Run("adopting", func(t *testing.T) {
		// The server holds only the new backup, readable with the new
		// recovery key; this device still points at the deleted one.
		b := newBackupHS(t)
		c, version, sid, newKey := resetWithBackup(t, b)
		failSessionSaves(c, 1)
		if err := c.ReplaceKeyBackup(ctx, newKey); err == nil {
			t.Fatal("replace succeeded with a failing session save")
		}
		got := b.versionList()
		if len(got) != 1 || got[0] == version || c.KeyBackupVersion() != version {
			t.Fatalf("versions %v, device on %q", got, c.KeyBackupVersion())
		}
		reader := openDevice(t, b, newKey)
		if err := reader.RestoreKeyBackup(ctx, newKey); err != nil || reader.KeyBackupVersion() != got[0] {
			t.Fatalf("the new recovery key cannot restore the new backup: %v", err)
		}
		if err := c.ReplaceKeyBackup(ctx, newKey); err != nil {
			t.Fatalf("replace again: %v", err)
		}
		if got := b.versionList(); len(got) != 1 || got[0] != c.KeyBackupVersion() {
			t.Fatalf("versions after the second replace: %v", got)
		}
		if err := c.uploadBackup(ctx); err != nil {
			t.Fatal(err)
		}
		assertBackupWorks(t, b, newKey, c.KeyBackupVersion(), sid)
	})
	t.Run("deleting the old version", func(t *testing.T) {
		b := newBackupHS(t)
		c, version, sid, newKey := resetWithBackup(t, b)
		b.failNextBackup("DELETE version", 1)
		if err := c.ReplaceKeyBackup(ctx, newKey); err == nil {
			t.Fatal("replace succeeded with a failing delete")
		}
		got := b.versionList()
		if len(got) != 2 {
			t.Fatalf("versions %v", got)
		}
		// The new backup is complete and the new recovery key restores it.
		fresh := got[1]
		reader := openDevice(t, b, newKey)
		if err := reader.RestoreKeyBackup(ctx, newKey); err != nil || reader.KeyBackupVersion() != fresh {
			t.Fatalf("the new recovery key cannot restore the new backup: %v", err)
		}
		if err := c.ReplaceKeyBackup(ctx, newKey); err != nil {
			t.Fatalf("replace again: %v", err)
		}
		if got := b.versionList(); len(got) != 1 || got[0] == version || got[0] == fresh {
			t.Fatalf("versions after the second replace: %v", got)
		}
		if err := c.uploadBackup(ctx); err != nil {
			t.Fatal(err)
		}
		assertBackupWorks(t, b, newKey, c.KeyBackupVersion(), sid)
	})
}

// Only synthetic secrets are used. Never print captured logs on failure.
func TestBackupRepairLogsOmitSecrets(t *testing.T) {
	ctx := context.Background()
	b := newBackupHS(t)
	opts := testOptions(t, b.testHS, t.TempDir())
	var logs bytes.Buffer
	var mu sync.Mutex
	opts.Logger = zerolog.New(&lockedWriter{w: &logs, mu: &mu}).Level(zerolog.TraceLevel)
	c, err := Open(ctx, opts)
	if err != nil {
		t.Fatal("mock Open failed")
	}
	defer c.Close()
	c.DefaultHTTPRetries = 0
	oldKey, err := c.CreateRecoveryKey(ctx, "")
	if err != nil {
		t.Fatal("first identity failed")
	}
	if err := c.EnableKeyBackup(ctx, oldKey); err != nil {
		t.Fatal("enable backup failed")
	}
	secrets := []string{oldKey}
	backupKey := func() {
		c.backup.mu.Lock()
		raw := c.session.BackupKey
		c.backup.mu.Unlock()
		secrets = append(secrets, base64.RawStdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw))
	}
	backupKey()
	newKey, err := c.ResetCrossSigningIdentity(ctx, CrossSigningAuth{Password: testXSPassword})
	if err != nil {
		t.Fatal("reset failed")
	}
	secrets = append(secrets, newKey)
	var errs []string
	b.failNextBackup("PUT version", 1)
	if err := c.CarryKeyBackup(ctx, newKey); err == nil {
		t.Fatal("interrupted carry succeeded")
	} else {
		errs = append(errs, err.Error())
	}
	if err := c.CarryKeyBackup(ctx, newKey); err != nil {
		t.Fatal("carry failed")
	}
	b.failAccountData("m.megolm_backup.v1", 1)
	if err := c.ReplaceKeyBackup(ctx, newKey); err == nil {
		t.Fatal("interrupted replace succeeded")
	} else {
		errs = append(errs, err.Error())
	}
	if err := c.ReplaceKeyBackup(ctx, newKey); err != nil {
		t.Fatal("replace failed")
	}
	backupKey()
	mu.Lock()
	data := logs.String()
	mu.Unlock()
	for _, secret := range secrets {
		if secret == "" || strings.Contains(data, secret) || strings.Contains(strings.Join(errs, "\n"), secret) {
			t.Fatal("a recovery key or backup key reached a log or an error")
		}
	}
	if !strings.Contains(data, "key backup carried over") || !strings.Contains(data, "key backup replaced") {
		t.Fatal("the safe backup diagnostics were lost")
	}
}
