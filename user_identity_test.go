package rihma

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/id"
)

const peerUser = id.UserID("@peer:localhost")

// keepSignatures makes the mock keep uploaded signatures on master and
// device keys, as a real server does, and counts the uploads.
func keepSignatures(h *testHS) *atomic.Int32 {
	uploads := new(atomic.Int32)
	inner := h.ms.Server.Config.Handler
	h.ms.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/keys/signatures/upload") {
			inner.ServeHTTP(w, r)
			return
		}
		var req mautrix.ReqUploadSignatures
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		uploads.Add(1)
		h.mu.Lock()
		for user, objects := range req {
			for name, obj := range objects {
				if master, ok := h.ms.MasterKeys[user]; ok && master.FirstKey().String() == name {
					master.Signatures = mergeSignatures(master.Signatures, obj.Signatures)
					h.ms.MasterKeys[user] = master
				} else if dev, ok := h.ms.DeviceKeys[user][id.DeviceID(name)]; ok {
					dev.Signatures = mergeSignatures(dev.Signatures, obj.Signatures)
					h.ms.DeviceKeys[user][id.DeviceID(name)] = dev
				}
			}
		}
		h.mu.Unlock()
		w.Write([]byte(`{"failures":{}}`))
	})
	return uploads
}

func mergeSignatures(into, from signatures.Signatures) signatures.Signatures {
	if into == nil {
		into = signatures.Signatures{}
	}
	for user, sigs := range from {
		if into[user] == nil {
			into[user] = map[id.KeyID]string{}
		}
		for key, sig := range sigs {
			into[user][key] = sig
		}
	}
	return into
}

// publishIdentity replaces user's cross-signing identity on the mock with a
// new one, as an identity reset on another client would, and returns its
// master key.
func publishIdentity(t *testing.T, h *testHS, user id.UserID) id.Ed25519 {
	t.Helper()
	master, self, usk := newSigningKey(t), newSigningKey(t), newSigningKey(t)
	object := func(usage id.CrossSigningUsage, key olm.PKSigning) mautrix.CrossSigningKeys {
		pub := key.PublicKey()
		obj := mautrix.CrossSigningKeys{UserID: user, Usage: []id.CrossSigningUsage{usage}, Keys: map[id.KeyID]id.Ed25519{id.NewKeyID(id.KeyAlgorithmEd25519, pub.String()): pub}}
		if usage != id.XSUsageMaster {
			sig, err := master.SignJSON(obj)
			if err != nil {
				t.Fatal(err)
			}
			obj.Signatures = signatures.NewSingleSignature(user, id.KeyAlgorithmEd25519, master.PublicKey().String(), sig)
		}
		return obj
	}
	h.mu.Lock()
	h.ms.MasterKeys[user] = object(id.XSUsageMaster, master)
	h.ms.SelfSigningKeys[user] = object(id.XSUsageSelfSigning, self)
	h.ms.UserSigningKeys[user] = object(id.XSUsageUserSigning, usk)
	h.mu.Unlock()
	return master.PublicKey()
}

func newSigningKey(t *testing.T) olm.PKSigning {
	t.Helper()
	key, err := olm.NewPKSigning()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func openAs(t *testing.T, h *testHS, user id.UserID, dir string, edit func(*Options)) *Client {
	t.Helper()
	opts := testOptions(t, h, dir)
	opts.Login.Identifier.User = user.String()
	if edit != nil {
		edit(&opts)
	}
	c, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func createIdentity(t *testing.T, c *Client) id.Ed25519 {
	t.Helper()
	if _, err := c.CreateRecoveryKey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	key, err := c.OwnMasterKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A bot signs another user's master key only when it is the one expected,
// signs it once, and then trusts that user's cross-signed devices. Every
// refusal has its own error, and no signature reaches the logs.
func TestSignUserIdentity(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	uploads := keepSignatures(h)
	var logs bytes.Buffer
	bot := openAs(t, h, testUser, t.TempDir(), func(o *Options) { o.Logger = zerolog.New(&logs).Level(zerolog.TraceLevel) })
	peer := openAs(t, h, peerUser, t.TempDir(), nil)
	botKey, peerKey := createIdentity(t, bot), createIdentity(t, peer)
	if botKey != bot.OlmMachine().CrossSigningKeys.MasterKey.PublicKey() {
		t.Fatal("OwnMasterKey is not the key the device holds")
	}

	ident, err := bot.UserIdentity(ctx, peerUser)
	if err != nil {
		t.Fatal(err)
	}
	if ident.MasterKey != peerKey || ident.SignedByUs {
		t.Fatalf("unsigned identity = %+v", ident)
	}

	before := uploads.Load()
	if err := bot.SignUserIdentity(ctx, peerUser, botKey); !errors.Is(err, ErrMasterKeyMismatch) || !strings.Contains(err.Error(), peerKey.String()) || !strings.Contains(err.Error(), botKey.String()) {
		t.Fatalf("sign with the wrong key = %v, want ErrMasterKeyMismatch naming both keys", err)
	}
	if uploads.Load() != before {
		t.Fatal("a refused signature was uploaded")
	}
	if err := bot.SignUserIdentity(ctx, peerUser, peerKey); err != nil {
		t.Fatal(err)
	}
	if uploads.Load() != before+1 {
		t.Fatal("the signature was not uploaded once")
	}
	signature := h.ms.MasterKeys[peerUser].Signatures[testUser][id.NewKeyID(id.KeyAlgorithmEd25519, bot.OlmMachine().CrossSigningKeys.UserSigningKey.PublicKey().String())]
	if signature == "" {
		t.Fatal("the server holds no signature by the user-signing key")
	}
	if err := bot.SignUserIdentity(ctx, peerUser, peerKey); err != nil || uploads.Load() != before+1 {
		t.Fatalf("signing a signed key again = %v, uploads %d; want nil and no upload", err, uploads.Load()-before)
	}
	if ident, err := bot.UserIdentity(ctx, peerUser); err != nil || !ident.SignedByUs {
		t.Fatalf("identity after signing = %+v, %v", ident, err)
	}
	mach := bot.OlmMachine()
	dev, err := mach.CryptoStore.GetDevice(ctx, peerUser, peer.DeviceID)
	if err != nil || dev == nil {
		t.Fatal("the peer's device is not stored")
	}
	if trust, err := mach.ResolveTrustContext(ctx, dev); err != nil || trust != id.TrustStateCrossSignedVerified {
		t.Fatalf("peer device trust = %v, %v; want cross-signed verified", trust, err)
	}

	if err := peer.SignUserIdentity(ctx, testUser, botKey); err != nil {
		t.Fatal(err)
	}
	if ident, err := peer.UserIdentity(ctx, testUser); err != nil || !ident.SignedByUs {
		t.Fatalf("the peer's view after signing back = %+v, %v", ident, err)
	}

	if err := bot.SignUserIdentity(ctx, testUser, botKey); !errors.Is(err, ErrOwnUser) {
		t.Fatalf("signing this account = %v, want ErrOwnUser", err)
	}
	if _, err := bot.UserIdentity(ctx, testUser); !errors.Is(err, ErrOwnUser) {
		t.Fatalf("reading this account = %v, want ErrOwnUser", err)
	}
	const nobody = id.UserID("@nobody:localhost")
	if err := bot.SignUserIdentity(ctx, nobody, peerKey); !errors.Is(err, ErrNoUserIdentity) {
		t.Fatalf("signing a user without an identity = %v, want ErrNoUserIdentity", err)
	}
	if _, err := bot.UserIdentity(ctx, nobody); !errors.Is(err, ErrNoUserIdentity) {
		t.Fatalf("reading a user without an identity = %v, want ErrNoUserIdentity", err)
	}
	keyless := openAs(t, h, testUser, t.TempDir(), nil)
	if err := keyless.SignUserIdentity(ctx, peerUser, peerKey); !errors.Is(err, ErrNoCrossSigningKeys) {
		t.Fatalf("signing without the keys = %v, want ErrNoCrossSigningKeys", err)
	}
	if _, err := keyless.OwnMasterKey(ctx); !errors.Is(err, ErrNoCrossSigningKeys) {
		t.Fatalf("own key without the keys = %v, want ErrNoCrossSigningKeys", err)
	}
	if ident, err := keyless.UserIdentity(ctx, peerUser); err != nil || !ident.SignedByUs {
		t.Fatalf("identity read by a device without the keys = %+v, %v", ident, err)
	}

	// Another client resets this account's identity: the held keys no
	// longer speak for it.
	publishIdentity(t, h, testUser)
	if _, err := bot.OwnMasterKey(ctx); !errors.Is(err, ErrMasterKeyMismatch) {
		t.Fatalf("own key after a reset elsewhere = %v, want ErrMasterKeyMismatch", err)
	}
	if err := bot.SignUserIdentity(ctx, peerUser, peerKey); !errors.Is(err, ErrNoCrossSigningKeys) {
		t.Fatalf("signing after a reset elsewhere = %v, want ErrNoCrossSigningKeys", err)
	}

	if bytes.Contains(logs.Bytes(), []byte(signature)) {
		t.Fatal("a signature reached the logs")
	}
}

// A change to a signed user's master key is reported once per new key,
// across restarts, whether a read, a refused signing or sync notices it.
// Signing the new key makes it the remembered one.
func TestIdentityChangeIsReportedOnce(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	keepSignatures(h)
	changes := make(chan IdentityChange, 8)
	report := func(o *Options) { o.OnIdentityChange = func(c IdentityChange) { changes <- c } }
	botDir := t.TempDir()
	bot := openAs(t, h, testUser, botDir, report)
	peer := openAs(t, h, peerUser, t.TempDir(), nil)
	createIdentity(t, bot)
	first := createIdentity(t, peer)
	if err := bot.SignUserIdentity(ctx, peerUser, first); err != nil {
		t.Fatal(err)
	}
	none := func(when string) {
		t.Helper()
		select {
		case c := <-changes:
			t.Fatalf("%s reported %+v", when, c)
		default:
		}
	}
	want := func(when string, published id.Ed25519) {
		t.Helper()
		select {
		case c := <-changes:
			if c.UserID != peerUser || c.Signed != first || c.Published != published {
				t.Fatalf("%s reported %+v", when, c)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s reported nothing", when)
		}
	}
	none("signing")

	second := publishIdentity(t, h, peerUser)
	if err := bot.SignUserIdentity(ctx, peerUser, first); !errors.Is(err, ErrMasterKeyMismatch) {
		t.Fatalf("signing the swapped key = %v, want ErrMasterKeyMismatch", err)
	}
	want("a refused signing", second)
	if ident, err := bot.UserIdentity(ctx, peerUser); err != nil || ident.MasterKey != second || ident.SignedByUs {
		t.Fatalf("identity after the swap = %+v, %v", ident, err)
	}
	none("a second read of the same key")

	bot.Close()
	bot = openAs(t, h, testUser, botDir, report)
	if _, err := bot.UserIdentity(ctx, peerUser); err != nil {
		t.Fatal(err)
	}
	none("a read after a restart")

	third := publishIdentity(t, h, peerUser)
	changed := func(batch string) func(string) *mautrix.RespSync {
		return func(string) *mautrix.RespSync {
			resp := &mautrix.RespSync{NextBatch: batch}
			resp.DeviceLists.Changed = []id.UserID{peerUser}
			return resp
		}
	}
	h.script(changed("s1"))
	stop := runSync(t, bot)
	want("sync", third)
	// Wait for the long poll after s1 to reach the server and find the
	// script empty. Stopped while still in flight, it could reach the
	// handler after the s2 script below and consume it.
	waitFor(t, "the long poll after s1", func() bool { return slices.Contains(h.seenSinces(), "s1") })
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sync = %v", err)
	}

	if err := bot.SignUserIdentity(ctx, peerUser, third); err != nil {
		t.Fatal(err)
	}
	h.script(changed("s2"))
	stop = runSync(t, bot)
	waitFor(t, "the second sync", func() bool { return slices.Contains(h.seenSinces(), "s2") })
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sync = %v", err)
	}
	none("sync after signing the new key")
}

// The filter drops whole lines carrying a signature and keeps the rest.
func TestSignatureLogFilter(t *testing.T) {
	var logs bytes.Buffer
	log := zerolog.New(&logs).Level(zerolog.TraceLevel).Hook(signatureLogFilter{})
	for msg := range signatureLogMessages {
		log.Debug().Str("signature", "synthetic-signature").Msg(msg)
	}
	log.Debug().Str("user_id", "@peer:localhost").Msg("an ordinary line")
	if bytes.Contains(logs.Bytes(), []byte("synthetic-signature")) {
		t.Fatal("a signature line was written")
	}
	if !bytes.Contains(logs.Bytes(), []byte("an ordinary line")) {
		t.Fatal("an ordinary line was dropped")
	}
}

// Every mautrix log line that carries a signature is one the filter drops,
// so an upgrade that adds or renames one fails here rather than leaking.
func TestSignatureLogFilterCoversMautrix(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go command")
	}
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "maunium.net/go/mautrix")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	field := regexp.MustCompile(`Str\("signature",`)
	message := regexp.MustCompile(`\bMsg\("([^"]*)"\)`)
	found := 0
	err = filepath.WalkDir(filepath.Join(dir, "crypto"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, loc := range field.FindAllIndex(src, -1) {
			found++
			m := message.FindSubmatch(src[loc[1]:])
			if m == nil || !signatureLogMessages[string(m[1])] {
				rel, _ := filepath.Rel(dir, path)
				t.Errorf("%s logs a signature under a message the filter does not drop", rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("found no signature log lines; the scan is broken")
	}
}

// identityOnMock is a user's published cross-signing keys on the mock, so a
// test can publish an earlier identity again.
type identityOnMock struct{ master, self, user mautrix.CrossSigningKeys }

func savedIdentity(h *testHS, user id.UserID) identityOnMock {
	h.mu.Lock()
	defer h.mu.Unlock()
	return identityOnMock{h.ms.MasterKeys[user], h.ms.SelfSigningKeys[user], h.ms.UserSigningKeys[user]}
}

func (i identityOnMock) publish(h *testHS, user id.UserID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ms.MasterKeys[user], h.ms.SelfSigningKeys[user], h.ms.UserSigningKeys[user] = i.master, i.self, i.user
}

// A server alternating between identities, including the signed one,
// gets each other key reported once, even across a restart.
func TestAlternatingIdentitiesAreReportedOncePerKey(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	keepSignatures(h)
	var reports []id.Ed25519
	report := func(o *Options) {
		o.OnIdentityChange = func(c IdentityChange) { reports = append(reports, c.Published) }
	}
	botDir := t.TempDir()
	bot := openAs(t, h, testUser, botDir, report)
	peer := openAs(t, h, peerUser, t.TempDir(), nil)
	createIdentity(t, bot)
	a := createIdentity(t, peer)
	if err := bot.SignUserIdentity(ctx, peerUser, a); err != nil {
		t.Fatal(err)
	}
	idA := savedIdentity(h, peerUser)
	b := publishIdentity(t, h, peerUser)
	idB := savedIdentity(h, peerUser)
	c := publishIdentity(t, h, peerUser)
	idC := savedIdentity(h, peerUser)
	read := func() {
		t.Helper()
		if _, err := bot.UserIdentity(ctx, peerUser); err != nil {
			t.Fatal(err)
		}
	}
	for _, next := range []identityOnMock{idB, idC, idB, idA, idB, idC} {
		next.publish(h, peerUser)
		read()
	}
	bot.Close()
	bot = openAs(t, h, testUser, botDir, report)
	idB.publish(h, peerUser)
	read()
	if !slices.Equal(reports, []id.Ed25519{b, c}) {
		t.Fatalf("reported %d changes, want B then C once each", len(reports))
	}
	// Signing another key starts the reports afresh.
	if err := bot.SignUserIdentity(ctx, peerUser, b); err != nil {
		t.Fatal(err)
	}
	idC.publish(h, peerUser)
	read()
	if len(reports) != 3 || reports[2] != c {
		t.Fatal("a change from the newly signed key was not reported")
	}
}

// A signature uploaded but not recorded is an error, not a silent loss of
// change reports; a retry records it without signing again.
func TestUnrecordedSignatureIsAnError(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	uploads := keepSignatures(h)
	changes := make(chan IdentityChange, 4)
	bot := openAs(t, h, testUser, t.TempDir(), func(o *Options) { o.OnIdentityChange = func(c IdentityChange) { changes <- c } })
	peer := openAs(t, h, peerUser, t.TempDir(), nil)
	createIdentity(t, bot)
	key := createIdentity(t, peer)
	if _, err := bot.UserIdentity(ctx, peerUser); err != nil { // creates the tables
		t.Fatal(err)
	}
	if _, err := bot.db.Exec(ctx, "CREATE TRIGGER refuse BEFORE INSERT ON rihma_signed_identity BEGIN SELECT RAISE(FAIL, 'injected'); END"); err != nil {
		t.Fatal(err)
	}
	before := uploads.Load()
	err := bot.SignUserIdentity(ctx, peerUser, key)
	if err == nil || errors.Is(err, ErrMasterKeyMismatch) || uploads.Load() != before+1 {
		t.Fatalf("signing with a failing store = %v after %d uploads; want a record error after one", err, uploads.Load()-before)
	}
	if _, err := bot.db.Exec(ctx, "DROP TRIGGER refuse"); err != nil {
		t.Fatal(err)
	}
	if err := bot.SignUserIdentity(ctx, peerUser, key); err != nil || uploads.Load() != before+1 {
		t.Fatalf("retry = %v, uploads %d; want nil and no second upload", err, uploads.Load()-before)
	}
	swapped := publishIdentity(t, h, peerUser)
	if _, err := bot.UserIdentity(ctx, peerUser); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-changes:
		if c.Signed != key || c.Published != swapped {
			t.Fatalf("reported %+v", c)
		}
	default:
		t.Fatal("the change after a recorded retry was not reported")
	}
}

// A change the store cannot record is still delivered, once in this
// process; a restart may deliver it once more.
func TestUnrecordedChangeIsStillReportedOnce(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)
	keepSignatures(h)
	var reports []id.Ed25519
	report := func(o *Options) {
		o.OnIdentityChange = func(c IdentityChange) { reports = append(reports, c.Published) }
	}
	botDir := t.TempDir()
	bot := openAs(t, h, testUser, botDir, report)
	peer := openAs(t, h, peerUser, t.TempDir(), nil)
	createIdentity(t, bot)
	if err := bot.SignUserIdentity(ctx, peerUser, createIdentity(t, peer)); err != nil {
		t.Fatal(err)
	}
	if _, err := bot.db.Exec(ctx, "CREATE TRIGGER refuse BEFORE INSERT ON rihma_reported_identity BEGIN SELECT RAISE(FAIL, 'injected'); END"); err != nil {
		t.Fatal(err)
	}
	swapped := publishIdentity(t, h, peerUser)
	for range 3 {
		if _, err := bot.UserIdentity(ctx, peerUser); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(reports, []id.Ed25519{swapped}) {
		t.Fatalf("an unrecorded change was reported %d times in one process, want once", len(reports))
	}
	if _, err := bot.db.Exec(ctx, "DROP TRIGGER refuse"); err != nil {
		t.Fatal(err)
	}
	bot.Close()
	bot = openAs(t, h, testUser, botDir, report)
	for range 2 {
		if _, err := bot.UserIdentity(ctx, peerUser); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(reports, []id.Ed25519{swapped, swapped}) {
		t.Fatalf("after a restart the unrecorded change was reported %d times in all, want twice", len(reports))
	}
}
