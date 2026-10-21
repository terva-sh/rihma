//go:build e2e

package rihma

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

// Two accounts on Synapse: the signer vouches for the signee's master key,
// then trusts the signee's device. The signee resets its identity; the
// signer hears of it over sync, once, and refuses to sign the old key for
// the new one. Logs are captured at trace and never printed; no signature
// or recovery key may appear in them.
func TestE2ESignUserIdentity(t *testing.T) {
	hs := e2eHomeserver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tag := e2eTag()
	signerName, signeeName, pw := "signer-"+tag, "signee-"+tag, "pw-sign"
	register(t, ctx, hs, signerName, pw)
	register(t, ctx, hs, signeeName, pw)

	logs := &lockedBuffer{}
	changes := make(chan IdentityChange, 8)
	signerOpts := e2eOptions(t, hs, signerName, pw, t.TempDir())
	signerOpts.Logger = zerolog.New(logs).Level(zerolog.TraceLevel)
	signerOpts.OnIdentityChange = func(c IdentityChange) { changes <- c }
	signer, err := Open(ctx, signerOpts)
	if err != nil {
		t.Fatal("signer open failed")
	}
	t.Cleanup(func() { signer.Close() })
	signeeOpts := e2eOptions(t, hs, signeeName, pw, t.TempDir())
	signeeOpts.Logger = zerolog.Nop()
	signee, err := Open(ctx, signeeOpts)
	if err != nil {
		t.Fatal("signee open failed")
	}
	t.Cleanup(func() { signee.Close() })

	recovery, err := signer.CreateRecoveryKey(ctx, pw)
	if err != nil {
		t.Fatal("signer identity creation failed")
	}
	if _, err := signee.CreateRecoveryKey(ctx, pw); err != nil {
		t.Fatal("signee identity creation failed")
	}
	signerKey, err := signer.OwnMasterKey(ctx)
	if err != nil {
		t.Fatalf("signer own key: %v", err)
	}
	signeeKey, err := signee.OwnMasterKey(ctx)
	if err != nil {
		t.Fatalf("signee own key: %v", err)
	}

	autoJoin(signee)
	runPolicySync(t, signer)
	runPolicySync(t, signee)
	room := createEncryptedDM(t, ctx, signer, signee.UserID)
	waitJoined(t, ctx, signer, room, signee.UserID)

	ident, err := signer.UserIdentity(ctx, signee.UserID)
	if err != nil || ident.MasterKey != signeeKey || ident.SignedByUs {
		t.Fatalf("identity before signing = %+v, %v", ident, err)
	}
	if err := signer.SignUserIdentity(ctx, signee.UserID, signerKey); !errors.Is(err, ErrMasterKeyMismatch) {
		t.Fatalf("signing with the wrong expected key = %v, want ErrMasterKeyMismatch", err)
	}
	if err := signer.SignUserIdentity(ctx, signee.UserID, signeeKey); err != nil {
		t.Fatalf("signing: %v", err)
	}
	if ident, err := signer.UserIdentity(ctx, signee.UserID); err != nil || !ident.SignedByUs {
		t.Fatalf("identity after signing = %+v, %v", ident, err)
	}
	trust := func() id.TrustState {
		t.Helper()
		dev, err := signer.OlmMachine().CryptoStore.GetDevice(ctx, signee.UserID, signee.DeviceID)
		if err != nil || dev == nil {
			t.Fatal("the signee's device is not stored")
		}
		state, err := signer.OlmMachine().ResolveTrustContext(ctx, dev)
		if err != nil {
			t.Fatal("trust resolution failed")
		}
		return state
	}
	if state := trust(); state != id.TrustStateCrossSignedVerified {
		t.Fatalf("signee device trust = %v, want cross-signed verified", state)
	}
	if err := signee.SignUserIdentity(ctx, signer.UserID, signerKey); err != nil {
		t.Fatalf("signing back: %v", err)
	}
	// Only the signee sees its signature; the server hides it from the signer.
	if ident, err := signee.UserIdentity(ctx, signer.UserID); err != nil || !ident.SignedByUs {
		t.Fatalf("the signee's view after signing back = %+v, %v", ident, err)
	}

	resp, err := signer.QueryKeys(ctx, &mautrix.ReqQueryKeys{DeviceKeys: mautrix.DeviceKeysRequest{signer.UserID: {}, signee.UserID: {}}})
	if err != nil {
		t.Fatal("key query failed")
	}
	signerUSK := resp.UserSigningKeys[signer.UserID]
	usk := id.NewKeyID(id.KeyAlgorithmEd25519, signerUSK.FirstKey().String())
	signature := resp.MasterKeys[signee.UserID].Signatures[signer.UserID][usk]
	if signature == "" {
		t.Fatal("the server holds no signature by the signer's user-signing key")
	}

	// The swap: the signee replaces its identity. The signer shares a room
	// with it, so its sync carries the device-list change.
	if _, err := signee.ResetCrossSigningIdentity(ctx, CrossSigningAuth{Password: pw}); err != nil {
		t.Fatalf("signee reset: %v", err)
	}
	swapped, err := signee.OwnMasterKey(ctx)
	if err != nil || swapped == signeeKey {
		t.Fatalf("signee key after reset = %v, %v", swapped == signeeKey, err)
	}
	select {
	case c := <-changes:
		if c.UserID != signee.UserID || c.Signed != signeeKey || c.Published != swapped {
			t.Fatalf("reported change = %+v", c)
		}
	case <-ctx.Done():
		t.Fatal("the identity change was not reported")
	}
	if err := signer.SignUserIdentity(ctx, signee.UserID, signeeKey); !errors.Is(err, ErrMasterKeyMismatch) {
		t.Fatalf("signing the old key after the swap = %v, want ErrMasterKeyMismatch", err)
	}
	if ident, err := signer.UserIdentity(ctx, signee.UserID); err != nil || ident.MasterKey != swapped || ident.SignedByUs {
		t.Fatalf("identity after the swap = %+v, %v", ident, err)
	}
	if state := trust(); state == id.TrustStateCrossSignedVerified {
		t.Fatal("the signee's device is still verified after the swap")
	}
	select {
	case c := <-changes:
		t.Fatalf("the same change was reported twice: %+v", c)
	case <-time.After(2 * time.Second):
	}
	resp, err = signer.QueryKeys(ctx, &mautrix.ReqQueryKeys{DeviceKeys: mautrix.DeviceKeysRequest{signee.UserID: {}}})
	if err != nil {
		t.Fatal("key query failed")
	}
	if _, ok := resp.MasterKeys[signee.UserID].Signatures[signer.UserID]; ok {
		t.Fatal("the swapped key carries a signature by the signer")
	}

	if logs.contains(signature) || logs.contains(recovery) {
		t.Fatal("a signature or recovery key reached the logs")
	}
}
