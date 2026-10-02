package rihma

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestFileSessionStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := FileSessionStore{Path: filepath.Join(t.TempDir(), "nested", "session.json")}

	got, err := store.Load(ctx)
	if err != nil || got != nil {
		t.Fatalf("Load before Save = %v, %v; want nil, nil", got, err)
	}

	want := &Session{UserID: "@bot:example.org", DeviceID: "DEV", AccessToken: "token", PickleKey: []byte{1, 2, 3}}
	if err := store.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err = store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load = %+v, want %+v", got, want)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(store.Path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("session file mode = %o, want 600", perm)
		}
	}

	if err := store.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Load(ctx); err != nil || got != nil {
		t.Fatalf("Load after Clear = %v, %v; want nil, nil", got, err)
	}
	if err := store.Clear(ctx); err != nil {
		t.Fatalf("second Clear: %v", err)
	}
}

// TestFileSessionStoreReplacesAtomically checks a save replaces the old
// session whole and leaves no temporary files behind.
func TestFileSessionStoreReplacesAtomically(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := FileSessionStore{Path: filepath.Join(dir, "session.json")}
	for _, token := range []string{"first", "second"} {
		if err := store.Save(ctx, &Session{AccessToken: token}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.Load(ctx)
	if err != nil || got.AccessToken != "second" {
		t.Fatalf("Load = %+v, %v; want token second", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want only session.json", len(entries))
	}
}

// TestFileSessionStoreFailedSaveKeepsOld makes the rename fail by putting
// a directory where the file goes, and checks nothing partial is left.
func TestFileSessionStoreFailedSaveKeepsOld(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (FileSessionStore{Path: path}).Save(ctx, &Session{AccessToken: "x"}); err == nil {
		t.Fatal("Save over a non-empty directory succeeded")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries after a failed save, want 1", len(entries))
	}
}
