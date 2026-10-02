// Package connector is the terva connector built on rihma: connsdk's
// Transport and its verbs. It is the only package that knows about terva.
package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
	"terva.sh/terva/packages/agent/connsdk"

	"terva.sh/rihma"
)

// Name is the manifest name, the state directory's name, and the sealed
// envelope's scope. Decision 0002 keeps it "rihma" for good.
const Name = "rihma"

// sealedPaths are the JSON Pointers sealed at rest. Config.Secrets must
// declare the same state, or terva can never re-seal them on rotation.
var sealedPaths = []string{"/session/access_token", "/session/pickle_key", "/session/backup_key"}

// State is the connector's config.json. Exported so main can hand it to
// connsdk.Config.Secrets.
var State = connsdk.SealedState{Name: Name, Paths: sealedPaths}

const (
	autoJoinAlways = "always"
	autoJoinNever  = "never"
)

// fileConfig is config.json. Keys mirror terva-conn-matrix so operators
// recognize them (handoff §9).
type fileConfig struct {
	HomeserverURL   string          `json:"homeserver_url,omitempty"`
	UserID          id.UserID       `json:"user_id,omitempty"`
	DeviceID        id.DeviceID     `json:"device_id,omitempty"`
	Session         *sessionSecrets `json:"session,omitempty"`
	AutoJoin        string          `json:"auto_join,omitempty"`
	Speaker         string          `json:"speaker,omitempty"`
	MaxAttachmentMB int             `json:"max_attachment_mb,omitempty"`
	// E2EE is the last verification verdict read, and E2EESource the verb
	// that read it ("setup" or "verify"). status reports them without
	// touching the network.
	E2EE       string `json:"e2ee,omitempty"`
	E2EESource string `json:"e2ee_source,omitempty"`
}

// sessionSecrets holds the sealed values, and the backup version, which
// is not a secret. Keys are base64 so every sealed value is a JSON string.
type sessionSecrets struct {
	AccessToken   string `json:"access_token,omitempty"`
	PickleKey     string `json:"pickle_key,omitempty"`
	BackupKey     string `json:"backup_key,omitempty"`
	BackupVersion string `json:"backup_version,omitempty"`
}

func (c fileConfig) autoJoin() bool { return c.AutoJoin != autoJoinNever }

func (c fileConfig) configured() bool {
	return c.HomeserverURL != "" && c.Session != nil && c.Session.AccessToken != ""
}

func loadConfig() (fileConfig, error) {
	var c fileConfig
	doc, err := State.Load()
	if err != nil {
		return c, fmt.Errorf("load %s: %w", State.Path(), err)
	}
	if err := json.Unmarshal(doc, &c); err != nil {
		return c, fmt.Errorf("parse %s: %w", State.Path(), err)
	}
	return c, nil
}

func saveConfig(c fileConfig) error {
	doc, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := State.Save(doc); err != nil {
		return fmt.Errorf("save %s: %w", State.Path(), err)
	}
	return nil
}

// deviceName is the display name every login gives the bot's device, so
// an operator can find it among the account's sessions.
const deviceName = "terva"

// storeDir is rihma's library state. It is a subdirectory because
// rihma.Client.Logout removes its StateDir whole, and the connector's
// directory also holds config.json and the host's pairing.json and data/.
func storeDir() string { return filepath.Join(State.Dir(), "store") }

// sessionStore keeps rihma's Session in config.json, sealed.
type sessionStore struct{}

var _ rihma.SessionStore = sessionStore{}

func (sessionStore) Load(context.Context) (*rihma.Session, error) {
	c, err := loadConfig()
	if err != nil {
		return nil, err
	}
	if c.Session == nil || c.Session.AccessToken == "" {
		return nil, nil
	}
	pickle, err := base64.StdEncoding.DecodeString(c.Session.PickleKey)
	if err != nil || len(pickle) == 0 {
		return nil, fmt.Errorf("%s: session.pickle_key is missing or not base64", State.Path())
	}
	backupKey, err := base64.StdEncoding.DecodeString(c.Session.BackupKey)
	if err != nil {
		return nil, fmt.Errorf("%s: session.backup_key is not base64", State.Path())
	}
	return &rihma.Session{
		UserID: c.UserID, DeviceID: c.DeviceID, AccessToken: c.Session.AccessToken, PickleKey: pickle,
		BackupKey: backupKey, BackupVersion: id.KeyBackupVersion(c.Session.BackupVersion),
	}, nil
}

func (sessionStore) Save(_ context.Context, s *rihma.Session) error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	c.UserID, c.DeviceID = s.UserID, s.DeviceID
	c.Session = &sessionSecrets{
		AccessToken: s.AccessToken, PickleKey: base64.StdEncoding.EncodeToString(s.PickleKey),
		BackupVersion: string(s.BackupVersion),
	}
	if len(s.BackupKey) > 0 {
		c.Session.BackupKey = base64.StdEncoding.EncodeToString(s.BackupKey)
	}
	return saveConfig(c)
}

func (sessionStore) Clear(context.Context) error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	c.Session, c.DeviceID = nil, ""
	return saveConfig(c)
}

// logger writes to stderr, which the host captures into the connector's
// log. Never log tokens, keys, or message content. During run, operational
// notices also reach the host through Session.Warn.
func logger() zerolog.Logger {
	return zerolog.New(os.Stderr).With().Timestamp().Str("connector", Name).Logger().Level(zerolog.InfoLevel)
}

// clientOptions builds rihma's Options for the stored config; login is
// nil except during setup.
func clientOptions(c fileConfig, login *mautrix.ReqLogin) rihma.Options {
	return rihma.Options{
		Homeserver: c.HomeserverURL,
		StateDir:   storeDir(),
		Sessions:   sessionStore{},
		Login:      login,
		DeviceName: deviceName,
		Logger:     logger(),
	}
}
