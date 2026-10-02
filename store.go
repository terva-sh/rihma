package rihma

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"go.mau.fi/util/dbutil"
	// The pure-Go SQLite driver, registered as "sqlite". See
	// docs/decisions/0001-sqlite-driver.md for why modernc.
	_ "modernc.org/sqlite"
)

// storePragmas reproduces what mautrix's cgo sqlite3-fk-wal driver sets
// on every connection (go.mau.fi/util/dbutil/litestream), plus the
// immediate transactions its string-path constructor asks for. modernc
// applies each _pragma to every new connection in the pool.
var storePragmas = []string{
	"_pragma=foreign_keys(1)",
	"_pragma=journal_mode(WAL)",
	"_pragma=synchronous(NORMAL)",
	"_pragma=busy_timeout(5000)",
	"_txlock=immediate",
}

// storeDSN returns the modernc DSN for the database file at path. It is
// built as a URL because a path containing '?', '#', or '%' would
// otherwise open a different file, silently and without the pragmas.
func storeDSN(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // Windows: C:/x becomes /C:/x, as SQLite URIs expect
	}
	u := url.URL{Scheme: "file", Path: p, RawQuery: strings.Join(storePragmas, "&")}
	return u.String(), nil
}

// openStore opens the SQLite database at path on the pure-Go driver and
// wraps it for mautrix. Pass the result to cryptohelper.NewCryptoHelper;
// never pass it a path string, which needs the cgo driver.
func openStore(ctx context.Context, path string) (*dbutil.Database, error) {
	dsn, err := storeDSN(path)
	if err != nil {
		return nil, fmt.Errorf("rihma: store path: %w", err)
	}
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("rihma: open store: %w", err)
	}
	if err := raw.PingContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("rihma: open store: %w", err)
	}
	db, err := dbutil.NewWithDB(raw, "sqlite3")
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("rihma: open store: %w", err)
	}
	return db, nil
}
