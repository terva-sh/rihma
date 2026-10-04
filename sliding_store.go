package rihma

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"maunium.net/go/mautrix/id"
	"os"
	"strings"
)

type slidingRecord struct {
	Version       int                  `json:"version"`
	Identity      string               `json:"identity"`
	Configuration string               `json:"configuration"`
	Connection    string               `json:"connection"`
	Cursor        SlidingSyncCursor    `json:"cursor"`
	View          SlidingSyncView      `json:"view"`
	Pending       json.RawMessage      `json:"pending,omitempty"`
	Membership    map[id.RoomID]string `json:"membership"`
	Options       *SlidingSyncOptions  `json:"options,omitempty"`
}

type slidingDisk struct {
	db       *sql.DB
	seal     cipher.AEAD
	identity string
}

// Use a separate FULL-synchronous database: the crypto database intentionally
// uses NORMAL and changing its pooled connection pragmas would weaken the proof.
// Raw responses and cursors are AEAD protected using a domain-separated key.
func openSlidingDisk(ctx context.Context, path string, pickle []byte, identity string) (*slidingDisk, error) {
	if len(pickle) < 32 {
		return nil, ErrSlidingStore
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, ErrSlidingStore
	}
	if err = f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, ErrSlidingStore
	}
	_ = f.Close()
	dsn, err := storeDSN(path)
	if err != nil {
		return nil, ErrSlidingStore
	}
	dsn = strings.Replace(dsn, "synchronous(NORMAL)", "synchronous(FULL)", 1)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, ErrSlidingStore
	}
	db.SetMaxOpenConns(1)
	if _, err = db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS sliding_recovery (id INTEGER PRIMARY KEY CHECK(id=1), record BLOB NOT NULL)"); err != nil {
		_ = db.Close()
		return nil, ErrSlidingStore
	}
	h := sha256.New()
	_, _ = h.Write([]byte("rihma sliding recovery v1\x00"))
	_, _ = h.Write(pickle)
	key := h.Sum(nil)
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		_ = db.Close()
		return nil, ErrSlidingStore
	}
	seal, err := cipher.NewGCM(block)
	if err != nil {
		_ = db.Close()
		return nil, ErrSlidingStore
	}
	return &slidingDisk{db: db, seal: seal, identity: identity}, nil
}

func (d *slidingDisk) load(ctx context.Context) (*slidingRecord, error) {
	var sealed []byte
	err := d.db.QueryRowContext(ctx, "SELECT record FROM sliding_recovery WHERE id=1").Scan(&sealed)
	if err == sql.ErrNoRows {
		return &slidingRecord{Version: 1, Identity: d.identity, View: emptySlidingView(), Membership: make(map[id.RoomID]string)}, nil
	}
	if err != nil || len(sealed) < d.seal.NonceSize() || len(sealed) > slidingMaxRecord+d.seal.NonceSize()+d.seal.Overhead() {
		return nil, ErrSlidingStore
	}
	n := d.seal.NonceSize()
	raw, err := d.seal.Open(nil, sealed[:n], sealed[n:], []byte(d.identity))
	if err != nil {
		return nil, ErrSlidingStore
	}
	defer clear(raw)
	var record slidingRecord
	if json.Unmarshal(raw, &record) != nil || record.Version != 1 || record.Identity != d.identity || len(record.Pending) > slidingMaxResponse {
		return nil, ErrSlidingStore
	}
	if record.View.Lists == nil || record.View.Counts == nil || record.View.Rooms == nil || record.Membership == nil {
		return nil, ErrSlidingStore
	}
	return &record, nil
}

func (d *slidingDisk) save(ctx context.Context, record *slidingRecord) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return ErrSlidingStore
	}
	defer clear(raw)
	if len(raw) > slidingMaxRecord {
		return ErrSlidingStore
	}
	nonce := make([]byte, d.seal.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return ErrSlidingStore
	}
	sealed := d.seal.Seal(nonce, nonce, raw, []byte(d.identity))
	_, err = d.db.ExecContext(ctx, "INSERT INTO sliding_recovery(id,record) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET record=excluded.record", sealed)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrSlidingStore
	}
	return nil
}

func newSlidingConnection() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", ErrSlidingStore
	}
	return hex.EncodeToString(buf), nil
}

func emptySlidingView() SlidingSyncView {
	return SlidingSyncView{Lists: make(map[string][]id.RoomID), Counts: make(map[string]int), Rooms: make(map[id.RoomID]json.RawMessage)}
}
