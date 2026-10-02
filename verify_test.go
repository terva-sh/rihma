package rihma

import (
	"context"
	"errors"
	"testing"
)

// TestRecoveryKeyCreateRefuseRestore creates an identity on one device,
// refuses to replace it, and restores it on a second device of the same
// account. Whether the second device then counts as cross-signed needs a
// server that keeps signatures, which mockserver does not; the live
// suite checks that against Synapse.
func TestRecoveryKeyCreateRefuseRestore(t *testing.T) {
	ctx := context.Background()
	h := newTestHS(t)

	first, err := Open(ctx, testOptions(t, h, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if has, err := first.HasCrossSigningIdentity(ctx); err != nil || has {
		t.Fatalf("fresh account identity = %v, %v; want none", has, err)
	}
	key, err := first.CreateRecoveryKey(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if key == "" {
		t.Fatal("empty recovery key")
	}
	if has, err := first.HasCrossSigningIdentity(ctx); err != nil || !has {
		t.Fatalf("identity after create = %v, %v; want one", has, err)
	}
	if _, err := first.CreateRecoveryKey(ctx, ""); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("second create = %v, want ErrIdentityExists", err)
	}

	secondDir := t.TempDir()
	second, err := Open(ctx, testOptions(t, h, secondDir))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.DeviceID == first.DeviceID {
		t.Fatal("second login reused the first device")
	}
	if err := second.RestoreFromRecoveryKey(ctx, "EsTj 3yST y93F SLpB jJsz eAXc 2XzA ygD3 w69H fPaD sfEm 4hEk"); err == nil {
		t.Fatal("restore with the wrong key succeeded")
	}
	if err := second.RestoreFromRecoveryKey(ctx, key); err != nil {
		t.Fatalf("restore with the right key: %v", err)
	}
}
