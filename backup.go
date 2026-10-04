package rihma

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/crypto/ssss"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Megolm key backup (m.megolm_backup.v1.curve25519-aes-sha2): every room
// key this device holds is uploaded, encrypted to the backup's public
// key, so a device restoring from the recovery key can read what this
// one could. mautrix downloads backups but has no uploader; this is it.

// ErrBackupExists is returned by EnableKeyBackup when the account
// already has a key backup. Replacing it would orphan every key in it, so
// rihma never does; RestoreKeyBackup with the recovery key adopts it.
var ErrBackupExists = errors.New("rihma: the account already has a key backup; restore it with the recovery key")

const (
	backupBatch    = 100
	backupInterval = 30 * time.Second
)

type backupState struct {
	mu      sync.Mutex
	key     *backup.MegolmBackupKey
	stopped bool // the server's backup changed under us
	wake    chan struct{}
}

func (c *Client) loadBackupKey() error {
	if len(c.session.BackupKey) == 0 {
		return nil
	}
	key, err := backup.MegolmBackupKeyFromBytes(c.session.BackupKey)
	if err != nil {
		return fmt.Errorf("rihma: stored backup key: %w", err)
	}
	c.backup.mu.Lock()
	c.backup.key = key
	c.backup.mu.Unlock()
	return nil
}

// KeyBackupVersion is the key backup this device uploads to, or "" when
// it has none.
func (c *Client) KeyBackupVersion() id.KeyBackupVersion {
	c.backup.mu.Lock()
	defer c.backup.mu.Unlock()
	if c.backup.key == nil {
		return ""
	}
	return c.session.BackupVersion
}

// EnableKeyBackup creates the account's key backup, stores its key in
// secret storage under the recovery key (where other clients look for
// it), and starts uploading. Call it after CreateRecoveryKey with the key
// that returned. The backup's auth data is signed by the master key, so
// other devices that trust the identity trust the backup.
func (c *Client) EnableKeyBackup(ctx context.Context, recoveryKey string) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	mach := c.OlmMachine()
	if mach.CrossSigningKeys == nil {
		return errors.New("rihma: no cross-signing keys on this device; create or restore the identity first")
	}
	ssssKey, err := c.secretStorageKey(ctx, recoveryKey)
	if err != nil {
		return err
	}
	latest, err := c.GetKeyBackupLatestVersion(ctx)
	switch {
	case err == nil && latest.Version != "":
		return ErrBackupExists
	case err != nil && !errors.Is(err, mautrix.MNotFound):
		return fmt.Errorf("rihma: read key backup version: %w", err)
	}

	key, err := backup.NewMegolmBackupKey()
	if err != nil {
		return err
	}
	auth := backup.MegolmAuthData{PublicKey: id.Ed25519(base64.RawStdEncoding.EncodeToString(key.PublicKey().Bytes()))}
	sig, err := mach.CrossSigningKeys.MasterKey.SignJSON(auth)
	if err != nil {
		return fmt.Errorf("rihma: sign key backup: %w", err)
	}
	auth.Signatures = signatures.NewSingleSignature(c.UserID, id.KeyAlgorithmEd25519, mach.CrossSigningKeys.MasterKey.PublicKey().String(), sig)
	resp, err := c.CreateKeyBackupVersion(ctx, &mautrix.ReqRoomKeysVersionCreate[backup.MegolmAuthData]{
		Algorithm: id.KeyBackupAlgorithmMegolmBackupV1, AuthData: auth,
	})
	if err != nil {
		return fmt.Errorf("rihma: create key backup: %w", err)
	}
	if err := mach.SSSS.SetEncryptedAccountData(ctx, event.AccountDataMegolmBackupKey, key.Bytes(), ssssKey); err != nil {
		return fmt.Errorf("rihma: store backup key in secret storage: %w", err)
	}
	return c.useBackup(ctx, key, resp.Version)
}

// RestoreKeyBackup reads the backup key from secret storage with the
// recovery key, imports every room key in the backup, and starts
// uploading to it. An account without a backup returns nil and leaves
// KeyBackupVersion empty. Call it after RestoreFromRecoveryKey.
func (c *Client) RestoreKeyBackup(ctx context.Context, recoveryKey string) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	ssssKey, err := c.secretStorageKey(ctx, recoveryKey)
	if err != nil {
		return err
	}
	mach := c.OlmMachine()
	raw, err := mach.SSSS.GetDecryptedAccountData(ctx, event.AccountDataMegolmBackupKey, ssssKey)
	if errors.Is(err, mautrix.MNotFound) {
		return nil
	} else if err != nil {
		return fmt.Errorf("rihma: read backup key from secret storage: %w", err)
	}
	key, err := backup.MegolmBackupKeyFromBytes(raw)
	if err != nil {
		return fmt.Errorf("rihma: backup key in secret storage: %w", err)
	}
	// Verifies the latest version against the key before importing.
	version, err := mach.DownloadAndStoreLatestKeyBackup(ctx, key)
	if err != nil {
		return fmt.Errorf("rihma: restore key backup: %w", err)
	}
	if version == "" {
		return nil
	}
	return c.useBackup(ctx, key, version)
}

func (c *Client) useBackup(ctx context.Context, key *backup.MegolmBackupKey, version id.KeyBackupVersion) error {
	// Hold the session writer lock across the save so a concurrent OAuth
	// token rotation is neither lost nor overwritten with an older pair.
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	c.backup.mu.Lock()
	next := c.session.clone()
	next.BackupKey, next.BackupVersion = key.Bytes(), version
	c.backup.mu.Unlock()
	if err := c.opts.Sessions.Save(ctx, &next); err != nil {
		return fmt.Errorf("rihma: save backup key: %w", err)
	}
	c.backup.mu.Lock()
	c.session, c.backup.key, c.backup.stopped = next, key, false
	c.backup.mu.Unlock()
	c.wakeBackup()
	return nil
}

func (c *Client) secretStorageKey(ctx context.Context, recoveryKey string) (*ssss.Key, error) {
	keyID, keyData, err := c.OlmMachine().SSSS.GetDefaultKeyData(ctx)
	if err != nil {
		return nil, fmt.Errorf("rihma: read secret storage key: %w", err)
	}
	key, err := keyData.VerifyRecoveryKey(keyID, recoveryKey)
	if err != nil && !errors.Is(err, ssss.ErrUnverifiableKey) {
		return nil, fmt.Errorf("rihma: recovery key: %w", err)
	}
	return key, nil
}

func (c *Client) wakeBackup() {
	select {
	case c.backup.wake <- struct{}{}:
	default:
	}
}

// runBackupUploads uploads after every sync response and on a timer,
// until ctx ends. Sync runs it.
func (c *Client) runBackupUploads(ctx context.Context) {
	tick := time.NewTicker(backupInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.backup.wake:
		case <-tick.C:
		}
		if err := c.uploadBackup(ctx); err != nil && ctx.Err() == nil {
			c.opts.Logger.Warn().Err(err).Msg("key backup upload failed; retrying later")
		}
	}
}

// uploadBackup sends every room key not yet in the current backup.
func (c *Client) uploadBackup(ctx context.Context) error {
	c.backup.mu.Lock()
	key, version, stopped := c.backup.key, c.session.BackupVersion, c.backup.stopped
	c.backup.mu.Unlock()
	if key == nil || stopped {
		return nil
	}
	mach := c.OlmMachine()
	pending, err := mach.CryptoStore.GetGroupSessionsWithoutKeyBackupVersion(ctx, version).AsList()
	if err != nil {
		return err
	}
	for len(pending) > 0 {
		batch := pending[:min(backupBatch, len(pending))]
		pending = pending[len(batch):]
		req := &mautrix.ReqKeyBackup{Rooms: map[id.RoomID]mautrix.ReqRoomKeyBackup{}}
		for _, s := range batch {
			data, err := backupSessionData(key, s)
			if err != nil {
				c.opts.Logger.Warn().Err(err).Stringer("session_id", s.ID()).Msg("cannot back up a room key; skipping it")
				continue
			}
			room := req.Rooms[s.RoomID]
			if room.Sessions == nil {
				room.Sessions = map[id.SessionID]mautrix.ReqKeyBackupData{}
			}
			room.Sessions[s.ID()] = data
			req.Rooms[s.RoomID] = room
		}
		_, err := c.PutKeysInBackup(ctx, version, req)
		if errors.Is(err, mautrix.MWrongRoomKeysVersion) {
			// Another client replaced the backup. Adopting or replacing it
			// is the operator's call, through setup.
			c.backup.mu.Lock()
			c.backup.stopped = true
			c.backup.mu.Unlock()
			c.opts.Logger.Warn().Stringer("version", version).Msg("the account's key backup changed; uploads stopped until setup restores it")
			return nil
		} else if err != nil {
			return err
		}
		if err := markBackedUp(ctx, mach, batch, version); err != nil {
			return err
		}
		c.opts.Logger.Debug().Int("count", len(batch)).Msg("room keys backed up")
	}
	return nil
}

// backupSessionData exports a session at its first known index and
// encrypts it to the backup key, in the shape mautrix's own importer
// reads back.
func backupSessionData(key *backup.MegolmBackupKey, s *crypto.InboundGroupSession) (mautrix.ReqKeyBackupData, error) {
	first := s.Internal.FirstKnownIndex()
	exported, err := s.Internal.Export(first)
	if err != nil {
		return mautrix.ReqKeyBackupData{}, err
	}
	chain := s.ForwardingChains
	if chain == nil {
		chain = []string{}
	}
	enc, err := backup.EncryptSessionDataWithPubkey(key.PublicKey(), backup.MegolmSessionData{
		Algorithm:          id.AlgorithmMegolmV1,
		ForwardingKeyChain: chain,
		SenderClaimedKeys:  backup.SenderClaimedKeys{Ed25519: s.SigningKey},
		SenderKey:          s.SenderKey,
		SessionKey:         string(exported),
		SharedHistory:      s.SharedHistory,
	})
	if err != nil {
		return mautrix.ReqKeyBackupData{}, err
	}
	raw, err := json.Marshal(enc)
	if err != nil {
		return mautrix.ReqKeyBackupData{}, err
	}
	return mautrix.ReqKeyBackupData{
		FirstMessageIndex: int(first),
		ForwardedCount:    len(chain),
		SessionData:       raw,
	}, nil
}

// markBackedUp records the version on each session. The SQL store can
// set the column alone, which cannot clobber a ratchet the sync loop
// moved meanwhile; rihma always runs on it.
func markBackedUp(ctx context.Context, mach *crypto.OlmMachine, batch []*crypto.InboundGroupSession, version id.KeyBackupVersion) error {
	store, ok := mach.CryptoStore.(*crypto.SQLCryptoStore)
	if !ok {
		return errors.New("rihma: key backup needs the SQL crypto store")
	}
	for _, s := range batch {
		if err := store.SetGroupSessionKeyBackupVersion(ctx, s.ID(), version); err != nil {
			return err
		}
	}
	return nil
}
