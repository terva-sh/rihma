package rihma

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"maunium.net/go/mautrix/id"
)

// Session is what must survive a restart to resume as the same device.
// AccessToken and PickleKey are secret: never log them.
type Session struct {
	UserID      id.UserID   `json:"user_id"`
	DeviceID    id.DeviceID `json:"device_id"`
	AccessToken string      `json:"access_token"`
	// PickleKey encrypts the crypto store's secrets at rest.
	PickleKey []byte `json:"pickle_key"`
	// BackupKey is the private key of the account's Megolm key backup,
	// when this device has one. It reads every backed-up room key: a
	// secret like the others.
	BackupKey []byte `json:"backup_key,omitempty"`
	// BackupVersion is the server's version of that backup.
	BackupVersion id.KeyBackupVersion `json:"backup_version,omitempty"`
}

// SessionStore persists the Session. The terva connector implements it
// on connsdk.SealedState; other programs can use FileSessionStore or
// their own secret store.
type SessionStore interface {
	// Load returns nil, nil when no session has been saved.
	Load(ctx context.Context) (*Session, error)
	Save(ctx context.Context, s *Session) error
	Clear(ctx context.Context) error
}

// FileSessionStore keeps the Session as JSON in one file, mode 0600,
// replaced atomically on every save.
type FileSessionStore struct {
	Path string
}

var _ SessionStore = FileSessionStore{}

func (f FileSessionStore) Load(_ context.Context) (*Session, error) {
	data, err := os.ReadFile(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("rihma: load session: %w", err)
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("rihma: load session %s: %w", f.Path, err)
	}
	return &s, nil
}

// Save writes to a temporary file in the same directory and renames it
// over the old one, so a crash leaves either the old session or the new
// one, never a partial file.
func (f FileSessionStore) Save(_ context.Context, s *Session) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("rihma: save session: %w", err)
	}
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("rihma: save session: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".session-*")
	if err != nil {
		return fmt.Errorf("rihma: save session: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("rihma: save session: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("rihma: save session: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("rihma: save session: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("rihma: save session: %w", err)
	}
	if err := os.Rename(tmp.Name(), f.Path); err != nil {
		return fmt.Errorf("rihma: save session: %w", err)
	}
	return nil
}

func (f FileSessionStore) Clear(_ context.Context) error {
	if err := os.Remove(f.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("rihma: clear session: %w", err)
	}
	return nil
}
