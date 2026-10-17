package rihma

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/id"
)

// Secret sharing (m.secret.request / m.secret.send) lets a device that was
// just verified ask the account's other verified devices for the key
// backup key, so verification alone unlocks history without the recovery
// key. mautrix answers requests from verified devices for any secret in
// its store; rihma keeps the backup key there so its devices answer too.

// ErrBackupKeyNotShared is returned by RequestKeyBackup when no verified
// device of this account sent the key backup key in time. The recovery
// key still works: RestoreFromRecoveryKey, then RestoreKeyBackup.
var ErrBackupKeyNotShared = errors.New("rihma: no verified device shared the key backup key")

// shareRequestInterval bounds one request. A device that has not yet seen
// this one verified ignores the request rather than queueing it, so the
// request is repeated until the wait ends.
var shareRequestInterval = 15 * time.Second

// RequestKeyBackup asks this account's other verified devices for the key
// backup key, as other clients do once a device is verified, and restores
// the backup with it as RestoreKeyBackup does. Only a key whose public half
// matches the server's latest backup is accepted. Call it after this device
// is verified; the devices answering also check that.
//
// An account without a backup returns nil and leaves KeyBackupVersion
// empty. If no device answers within wait, it returns
// ErrBackupKeyNotShared.
func (c *Client) RequestKeyBackup(ctx context.Context, wait time.Duration) error {
	// wait bounds the whole request, connecting and the server lookup included.
	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if err := c.Connect(waitCtx); err != nil {
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case waitCtx.Err() != nil:
			return ErrBackupKeyNotShared
		}
		return err
	}
	latest, err := c.GetKeyBackupLatestVersion(waitCtx)
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case waitCtx.Err() != nil:
		return ErrBackupKeyNotShared
	case errors.Is(err, mautrix.MNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("rihma: read key backup version: %w", err)
	case latest.Version == "":
		return nil
	}
	if latest.Algorithm != id.KeyBackupAlgorithmMegolmBackupV1 {
		return fmt.Errorf("rihma: unsupported key backup algorithm %s", latest.Algorithm)
	}
	mach := c.OlmMachine()
	var key *backup.MegolmBackupKey
	accept := func(secret string) (bool, error) {
		candidate, ok := parseBackupSecret(secret)
		if !ok || backupPublicKey(candidate) != latest.AuthData.PublicKey {
			// A stale key, or one for a backup another client replaced.
			return false, nil
		}
		key = candidate
		return true, nil
	}
	for key == nil {
		attempt, stop := context.WithTimeout(waitCtx, shareRequestInterval)
		err := mach.GetOrRequestSecret(attempt, id.SecretMegolmBackupV1, accept, shareRequestInterval)
		stop()
		switch {
		case key != nil:
		case ctx.Err() != nil:
			return ctx.Err()
		case waitCtx.Err() != nil:
			return ErrBackupKeyNotShared
		case err != nil && !errors.Is(err, context.DeadlineExceeded):
			return fmt.Errorf("rihma: request key backup key: %w", err)
		}
	}
	// Verifies the latest version against the key before importing.
	version, err := mach.DownloadAndStoreLatestKeyBackup(ctx, key)
	if err != nil {
		return fmt.Errorf("rihma: restore key backup: %w", err)
	}
	if version == "" {
		return nil
	}
	return c.useBackup(ctx, mach, key, version)
}

// storeBackupSecret keeps the backup key where mautrix answers verified
// devices' secret requests. The wire form is unpadded base64, as other
// clients send it.
func storeBackupSecret(ctx context.Context, mach *crypto.OlmMachine, key *backup.MegolmBackupKey) error {
	if mach == nil {
		return nil
	}
	secret := base64.RawStdEncoding.EncodeToString(key.Bytes())
	if stored, err := mach.CryptoStore.GetSecret(ctx, id.SecretMegolmBackupV1); err == nil && stored == secret {
		return nil
	}
	if err := mach.CryptoStore.PutSecret(ctx, id.SecretMegolmBackupV1, secret); err != nil {
		return fmt.Errorf("rihma: store backup key for sharing: %w", err)
	}
	return nil
}

func parseBackupSecret(secret string) (*backup.MegolmBackupKey, bool) {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(secret), "="))
	if err != nil {
		return nil, false
	}
	key, err := backup.MegolmBackupKeyFromBytes(raw)
	return key, err == nil
}

func backupPublicKey(key *backup.MegolmBackupKey) id.Ed25519 {
	return id.Ed25519(base64.RawStdEncoding.EncodeToString(key.PublicKey().Bytes()))
}
