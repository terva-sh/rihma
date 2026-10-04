// Package appservice_test proves a capture boundary, not a public bridge runtime.
package appservice_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/appservice"
	_ "modernc.org/sqlite"
)

const maxBody = 4096

// Raw payloads include extensions unknown to the current upstream types.
// SQLite's commit is the receipt; dispatch is a separate replayable worker.
func captureReceiver(as *appservice.AppService, db *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /_matrix/app/v1/transactions/{txnID}", func(w http.ResponseWriter, r *http.Request) {
		if !as.CheckServerToken(w, r) {
			return
		}
		id := r.PathValue("txnID")
		if len(id) == 0 || len(id) > 128 || strings.ContainsAny(id, "/\x00") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		defer r.Body.Close()
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		var txn appservice.Transaction
		if !json.Valid(raw) || len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' || json.Unmarshal(raw, &txn) != nil || len(txn.Events)+len(txn.EphemeralEvents)+len(txn.ToDeviceEvents) > 32 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, ev := range txn.Events {
			if ev == nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		if r.Context().Err() != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		// Autocommit records payload and receipt together; a durable retry finds
		// the same row after restart, even if the HTTP acknowledgement was lost.
		_, err = db.ExecContext(r.Context(), "INSERT INTO inbox(service,txn,payload) VALUES (?,?,?) ON CONFLICT(service,txn) DO NOTHING", as.Registration.ID, id, raw)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var stored []byte
		if db.QueryRowContext(r.Context(), "SELECT payload FROM inbox WHERE service=? AND txn=?", as.Registration.ID, id).Scan(&stored) != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if !bytes.Equal(stored, raw) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	})
	return mux
}

func openInbox(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal("inbox open failed")
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA synchronous=FULL"); err != nil {
		t.Fatal("durability configuration failed")
	}
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS inbox (service TEXT NOT NULL, txn TEXT NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(service,txn))"); err != nil {
		t.Fatal("inbox creation failed")
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestDurableTransactionCapture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.db")
	db := openInbox(t, path)
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatal("fixture setup failed")
	}
	as := &appservice.AppService{Registration: &appservice.Registration{ID: "fixture", ServerToken: hex.EncodeToString(token)}, Log: zerolog.Nop()}
	handler := captureReceiver(as, db)
	payload := `{"events":[{"type":"m.room.message","event_id":"$fixture","room_id":"!room:example.org","sender":"@human:example.org","content":{"body":"synthetic"}}],"future_extension":{"retained":true}}`
	request := func(ctx context.Context, id, body, auth string) int {
		r := httptest.NewRequest(http.MethodPut, "/_matrix/app/v1/transactions/"+id, strings.NewReader(body)).WithContext(ctx)
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	count := func() int {
		var n int
		if db.QueryRow("SELECT count(*) FROM inbox").Scan(&n) != nil {
			t.Fatal("receipt query failed")
		}
		return n
	}
	ctx := context.Background()
	for _, auth := range []string{"", "wrong-fixture-token"} {
		if request(ctx, "txn", payload, auth) != http.StatusUnauthorized || count() != 0 {
			t.Fatal("unauthorized transaction captured")
		}
	}
	for _, body := range []string{"{", "null", "{}{}", `{"events":[null]}`, strings.Repeat(" ", maxBody+1)} {
		status := request(ctx, "txn", body, as.Registration.ServerToken)
		if status != http.StatusBadRequest && status != http.StatusRequestEntityTooLarge {
			t.Fatal("invalid body accepted")
		}
		if count() != 0 {
			t.Fatal("invalid body captured")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if request(cancelled, "txn", payload, as.Registration.ServerToken) != http.StatusServiceUnavailable || count() != 0 {
		t.Fatal("cancelled request captured")
	}
	if request(ctx, "txn", payload, as.Registration.ServerToken) != http.StatusOK || count() != 1 {
		t.Fatal("durable capture failed")
	}
	var captured []byte
	if db.QueryRow("SELECT payload FROM inbox").Scan(&captured) != nil || string(captured) != payload {
		t.Fatal("raw extension payload not retained")
	}
	if request(ctx, "txn", payload, as.Registration.ServerToken) != http.StatusOK || count() != 1 {
		t.Fatal("duplicate receipt failed")
	}
	if request(ctx, "txn", "{}", as.Registration.ServerToken) != http.StatusConflict || count() != 1 {
		t.Fatal("transaction ID collision accepted")
	}
	if err := db.Close(); err != nil {
		t.Fatal("inbox close failed")
	}
	if request(ctx, "new", payload, as.Registration.ServerToken) != http.StatusServiceUnavailable {
		t.Fatal("storage failure acknowledged")
	}
	db = openInbox(t, path)
	handler = captureReceiver(as, db)
	if request(ctx, "txn", payload, as.Registration.ServerToken) != http.StatusOK || count() != 1 {
		t.Fatal("restart duplicate receipt failed")
	}
}
