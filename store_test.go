package rihma

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/sqlstatestore"
)

func openTestStore(t *testing.T, path string) *dbutil.Database {
	t.Helper()
	db, err := openStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestStorePragmas holds several connections at once, so each pragma is
// checked on distinct pooled connections, not only the first.
func TestStorePragmas(t *testing.T) {
	ctx := context.Background()
	db := openTestStore(t, filepath.Join(t.TempDir(), "rihma.db"))
	db.RawDB.SetMaxOpenConns(4)

	var conns []*sql.Conn
	for range 4 {
		c, err := db.RawDB.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		conns = append(conns, c)
	}
	for i, c := range conns {
		var fk, sync, busy int
		var journal string
		for _, q := range []struct {
			pragma string
			dest   any
		}{
			{"foreign_keys", &fk},
			{"journal_mode", &journal},
			{"synchronous", &sync},
			{"busy_timeout", &busy},
		} {
			if err := c.QueryRowContext(ctx, "PRAGMA "+q.pragma).Scan(q.dest); err != nil {
				t.Fatalf("conn %d: PRAGMA %s: %v", i, q.pragma, err)
			}
		}
		// synchronous 1 is NORMAL.
		if fk != 1 || journal != "wal" || sync != 1 || busy != 5000 {
			t.Errorf("conn %d: foreign_keys=%d journal_mode=%s synchronous=%d busy_timeout=%d, want 1 wal 1 5000",
				i, fk, journal, sync, busy)
		}
	}
}

func TestStoreEnforcesForeignKeys(t *testing.T) {
	ctx := context.Background()
	db := openTestStore(t, filepath.Join(t.TempDir(), "rihma.db"))
	if _, err := db.Exec(ctx, "CREATE TABLE p (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, "CREATE TABLE c (pid INTEGER REFERENCES p(id))"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, "INSERT INTO c VALUES (42)"); err == nil {
		t.Fatal("orphan row accepted; foreign keys are off")
	}
}

// TestStoreUpgrades runs mautrix's crypto-store and state-store schema
// upgrades on the pure-Go driver, then does it again on reopen.
func TestStoreUpgrades(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rihma.db")
	for _, round := range []string{"fresh", "reopen"} {
		db, err := openStore(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		cs := crypto.NewSQLCryptoStore(db, nil, "acc", id.DeviceID("DEV"), []byte("pickle"))
		if err := cs.DB.Upgrade(ctx); err != nil {
			t.Fatalf("%s: crypto store upgrade: %v", round, err)
		}
		ss := sqlstatestore.NewSQLStateStore(db, nil, false)
		if err := ss.Upgrade(ctx); err != nil {
			t.Fatalf("%s: state store upgrade: %v", round, err)
		}
		var cv, sv int
		if err := db.QueryRow(ctx, "SELECT version FROM crypto_version").Scan(&cv); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(ctx, "SELECT version FROM mx_version").Scan(&sv); err != nil {
			t.Fatal(err)
		}
		if cv == 0 || sv == 0 {
			t.Fatalf("%s: crypto_version=%d mx_version=%d", round, cv, sv)
		}
		db.Close()
	}
}

// TestStoreConcurrentTransactions fails without _txlock=immediate: two
// deferred read-then-write transactions deadlock on the lock upgrade and
// one gets SQLITE_BUSY at once, whatever the busy timeout.
func TestStoreConcurrentTransactions(t *testing.T) {
	ctx := context.Background()
	db := openTestStore(t, filepath.Join(t.TempDir(), "rihma.db"))
	if _, err := db.Exec(ctx, "CREATE TABLE ctr (n INTEGER); INSERT INTO ctr VALUES (0)"); err != nil {
		t.Fatal(err)
	}
	const writers, each = 8, 50
	var wg sync.WaitGroup
	errs := make(chan error, writers*each)
	for range writers {
		wg.Go(func() {
			for range each {
				errs <- db.DoTxn(ctx, nil, func(ctx context.Context) error {
					var n int
					if err := db.QueryRow(ctx, "SELECT n FROM ctr").Scan(&n); err != nil {
						return err
					}
					_, err := db.Exec(ctx, "UPDATE ctr SET n=$1", n+1)
					return err
				})
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := db.QueryRow(ctx, "SELECT n FROM ctr").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != writers*each {
		t.Fatalf("counter = %d, want %d", n, writers*each)
	}
}

// TestStorePathCharacters opens stores under directory names that break
// a DSN built by string concatenation, and checks the file lands at the
// path given and the pragmas applied.
func TestStorePathCharacters(t *testing.T) {
	for _, name := range []string{"with space", "q?mark", "hash#tag", "pct%41x", "semi;colon"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), name)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Skipf("filesystem refuses %q: %v", name, err)
			}
			path := filepath.Join(dir, "rihma.db")
			db := openTestStore(t, path)
			var fk int
			if err := db.QueryRow(context.Background(), "PRAGMA foreign_keys").Scan(&fk); err != nil {
				t.Fatal(err)
			}
			if fk != 1 {
				t.Errorf("foreign_keys = %d, want 1", fk)
			}
			if _, err := os.Stat(path); err != nil {
				t.Errorf("no database at %s: %v", path, err)
			}
		})
	}
}
