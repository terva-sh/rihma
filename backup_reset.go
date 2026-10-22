package rihma

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/backup"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/crypto/ssss"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// After ResetCrossSigningIdentity the key backup is stranded: its key sits in
// secret storage under the old recovery key, and its auth data carries the
// old master key's signature. The application picks one of two repairs.
// CarryKeyBackup keeps the backup, so old room keys stay readable, and needs
// its key. ReplaceKeyBackup starts a new backup and works without the old
// key, but drops the room keys that no device holds. Neither runs on its own.

var (
	// ErrNoKeyBackup is returned by CarryKeyBackup when the account has no
	// key backup. Nothing was changed: EnableKeyBackup creates one.
	ErrNoKeyBackup = errors.New("rihma: the account has no key backup")

	// ErrBackupKeyUnavailable is returned by CarryKeyBackup when neither
	// this device nor secret storage under the given recovery key holds
	// the key of the account's current backup. Nothing was changed. Get the
	// key from another device (RequestKeyBackup) or with the old recovery
	// key, or give up the old room keys with ReplaceKeyBackup.
	ErrBackupKeyUnavailable = errors.New("rihma: the key of the account's current key backup is not available")
)

// replaceRollbackTimeout bounds the cleanup ReplaceKeyBackup runs after a
// failure, which is not bound to the caller's cancellation.
const replaceRollbackTimeout = 30 * time.Second

// CarryKeyBackup moves the account's key backup over to the current
// cross-signing identity and secret storage, typically right after
// ResetCrossSigningIdentity with the recovery key it returned. The backup's
// version and key do not change, so every room key already in it stays
// readable. Its key is stored in secret storage under recoveryKey, and the
// backup's auth data is signed again with the master key this device holds,
// so other clients trust it. Then this device uploads to it.
//
// It needs the backup's key. Either this device uploads to the backup, or
// secret storage under recoveryKey already holds the key, from an earlier
// call that was interrupted. Otherwise it returns ErrBackupKeyUnavailable.
// It returns ErrNoKeyBackup on an account without a backup, and
// ErrNoCrossSigningKeys if this device does not hold the cross-signing
// identity the server publishes. None of these changes anything.
//
// The key is stored before the auth data is signed. A failure between
// the two leaves a backup that the new recovery key restores but that is
// signed by the old identity; run CarryKeyBackup again to finish. It is
// safe to repeat.
func (c *Client) CarryKeyBackup(ctx context.Context, recoveryKey string) error {
	master, ssssKey, err := c.backupResetKeys(ctx, recoveryKey)
	if err != nil {
		return err
	}
	latest, err := c.latestBackupRaw(ctx)
	if err != nil {
		return fmt.Errorf("rihma: read key backup version: %w", err)
	} else if latest == nil {
		return ErrNoKeyBackup
	}
	if latest.Algorithm != id.KeyBackupAlgorithmMegolmBackupV1 {
		return fmt.Errorf("rihma: unsupported key backup algorithm %s", latest.Algorithm)
	}
	var auth backup.MegolmAuthData
	if err := json.Unmarshal(latest.AuthData, &auth); err != nil {
		return fmt.Errorf("rihma: key backup auth data: %w", err)
	}
	mach := c.OlmMachine()
	key, err := c.currentBackupKey(ctx, mach, ssssKey, auth.PublicKey)
	if err != nil {
		return err
	}
	log := c.opts.Logger.With().Stringer("version", latest.Version).Logger()

	// 1. From here the new recovery key restores the backup: mautrix trusts
	// a backup whose public key matches the key it read.
	if err := mach.SSSS.SetEncryptedAccountData(ctx, event.AccountDataMegolmBackupKey, key.Bytes(), ssssKey); err != nil {
		return fmt.Errorf("rihma: store backup key in secret storage: %w", err)
	}
	// 2. From here clients that check the signature trust it too.
	signed, err := resignBackupAuth(latest.AuthData, c.UserID, master)
	if err != nil {
		return fmt.Errorf("rihma: sign key backup: %w", err)
	}
	if err := c.updateBackupAuth(ctx, latest.Algorithm, latest.Version, signed); err != nil {
		return fmt.Errorf("rihma: store key backup signature: %w", err)
	}
	log.Debug().Msg("key backup carried over to the current identity")
	// 3. Adopting is a no-op on the device that already uploads to it.
	return c.useBackup(ctx, mach, key, latest.Version)
}

// ReplaceKeyBackup deletes the account's key backup and creates a new one
// with a new key, as other clients do when they reset encryption. The key is
// stored in secret storage under recoveryKey, the new backup is signed by the
// master key this device holds, and this device uploads every room key it
// holds to it. On an account without a backup it creates one, as
// EnableKeyBackup does.
//
// This loses every room key that only the old backup held. Prefer
// CarryKeyBackup when it works, and replace only when the person accepts
// that loss. It returns ErrNoCrossSigningKeys, without changing anything,
// if this device does not hold the cross-signing identity the server
// publishes.
//
// The new backup is made readable under recoveryKey before the old one is
// deleted, and no room key goes into the new one until then. If storing the
// key fails, secret storage is read back. A write that landed regardless
// carries on, a refused one deletes the new backup again so the old one
// stays as it was, and an unknown outcome leaves both backups in place.
// Any later failure leaves the new backup readable with recoveryKey; run
// ReplaceKeyBackup again. A repeated call deletes the backups the
// earlier call left behind, including the one this device uploaded to.
func (c *Client) ReplaceKeyBackup(ctx context.Context, recoveryKey string) error {
	master, ssssKey, err := c.backupResetKeys(ctx, recoveryKey)
	if err != nil {
		return err
	}
	// The backups to delete: the latest one, and the one this device used
	// if an earlier replace left it behind.
	var old []id.KeyBackupVersion
	latest, err := c.GetKeyBackupLatestVersion(ctx)
	switch {
	case err == nil && latest.Version != "":
		old = append(old, latest.Version)
	case err != nil && !errors.Is(err, mautrix.MNotFound):
		return fmt.Errorf("rihma: read key backup version: %w", err)
	}
	c.backup.mu.Lock()
	if v := c.session.BackupVersion; v != "" && (len(old) == 0 || v != old[0]) {
		old = append(old, v)
	}
	c.backup.mu.Unlock()

	key, err := backup.NewMegolmBackupKey()
	if err != nil {
		return err
	}
	auth, err := signedBackupAuth(c.UserID, master, key)
	if err != nil {
		return err
	}
	// 1. The new version is the latest from here, but empty: nothing is
	// uploaded to it before step 4.
	resp, err := c.CreateKeyBackupVersion(ctx, &mautrix.ReqRoomKeysVersionCreate[backup.MegolmAuthData]{
		Algorithm: id.KeyBackupAlgorithmMegolmBackupV1, AuthData: auth,
	})
	if err != nil {
		return fmt.Errorf("rihma: create key backup: %w", err)
	}
	log := c.opts.Logger.With().Stringer("version", resp.Version).Logger()
	mach := c.OlmMachine()
	// 2. The old backup's key stays in secret storage until this write.
	if err := mach.SSSS.SetEncryptedAccountData(ctx, event.AccountDataMegolmBackupKey, key.Bytes(), ssssKey); err != nil {
		// An error does not prove the write was refused: it may have
		// landed and lost its answer, and then the old key is gone from
		// secret storage and the new backup must stay. Read it back, with
		// a context that outlives a cancelled ctx.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), replaceRollbackTimeout)
		defer cancel()
		switch holds, known := storesBackupKey(cleanup, mach, ssssKey, key); {
		case holds:
			log.Debug().Msg("the backup key was stored although its write failed")
		case !known:
			log.Warn().Msg("cannot tell whether the new backup key was stored; keeping the new key backup, run ReplaceKeyBackup again")
			return fmt.Errorf("rihma: store backup key in secret storage: %w", err)
		default:
			// Refused: without its key in secret storage the new backup
			// must not stay the latest one.
			if delErr := c.DeleteKeyBackupVersion(cleanup, resp.Version); delErr != nil && !errors.Is(delErr, mautrix.MNotFound) {
				log.Warn().Err(delErr).Msg("cannot delete the half-made key backup; run ReplaceKeyBackup again")
			} else {
				// The old backup is the latest again; uploads to it may resume.
				c.backup.mu.Lock()
				c.backup.stopped = false
				c.backup.mu.Unlock()
			}
			return fmt.Errorf("rihma: store backup key in secret storage: %w", err)
		}
	}
	// 3. Only now is the old backup's key gone from secret storage.
	for _, v := range old {
		if v == resp.Version {
			continue
		}
		if err := c.DeleteKeyBackupVersion(ctx, v); err != nil && !errors.Is(err, mautrix.MNotFound) {
			return fmt.Errorf("rihma: delete the old key backup %s: %w", v, err)
		}
		log.Debug().Stringer("old_version", v).Msg("old key backup deleted")
	}
	log.Debug().Msg("key backup replaced")
	// 4. Upload every room key this device holds to the new backup.
	return c.useBackup(ctx, mach, key, resp.Version)
}

// backupResetKeys checks the preconditions both repairs share, before
// anything is written: this device holds the identity the server publishes,
// whose master key signs the backup, and recoveryKey opens the account's
// default secret storage key.
func (c *Client) backupResetKeys(ctx context.Context, recoveryKey string) (olm.PKSigning, *ssss.Key, error) {
	if err := c.Connect(ctx); err != nil {
		return nil, nil, err
	}
	if !c.HasCrossSigningKeys() {
		return nil, nil, ErrNoCrossSigningKeys
	}
	resp, err := c.queryIdentities(ctx)
	if err != nil {
		return nil, nil, err
	}
	keys := c.OlmMachine().CrossSigningKeys
	if published := crossSigningKeysIn(resp, c.UserID); published == nil || *published != *keys.PublicKeys() {
		return nil, nil, fmt.Errorf("%w: the server publishes another identity for this account", ErrNoCrossSigningKeys)
	}
	ssssKey, err := c.secretStorageKey(ctx, recoveryKey)
	if err != nil {
		return nil, nil, err
	}
	return keys.MasterKey, ssssKey, nil
}

// currentBackupKey finds the private key whose public half is the
// backup's: the one this device uploads with, or else the one in secret
// storage under ssssKey.
func (c *Client) currentBackupKey(ctx context.Context, mach *crypto.OlmMachine, ssssKey *ssss.Key, public id.Ed25519) (*backup.MegolmBackupKey, error) {
	c.backup.mu.Lock()
	held := c.backup.key
	c.backup.mu.Unlock()
	if held != nil && backupPublicKey(held) == public {
		return held, nil
	}
	raw, err := mach.SSSS.GetDecryptedAccountData(ctx, event.AccountDataMegolmBackupKey, ssssKey)
	switch {
	case errors.Is(err, mautrix.MNotFound), errors.Is(err, ssss.ErrNotEncryptedForKey):
		return nil, ErrBackupKeyUnavailable
	case err != nil:
		return nil, fmt.Errorf("rihma: read backup key from secret storage: %w", err)
	}
	stored, err := backup.MegolmBackupKeyFromBytes(raw)
	if err != nil || backupPublicKey(stored) != public {
		// Unreadable, or the key of a backup that has since been replaced.
		return nil, ErrBackupKeyUnavailable
	}
	return stored, nil
}

// storesBackupKey reports whether secret storage under ssssKey holds key.
// known is false when that cannot be read: the server did not answer, or
// what it holds under ssssKey does not decrypt.
func storesBackupKey(ctx context.Context, mach *crypto.OlmMachine, ssssKey *ssss.Key, key *backup.MegolmBackupKey) (holds, known bool) {
	raw, err := mach.SSSS.GetDecryptedAccountData(ctx, event.AccountDataMegolmBackupKey, ssssKey)
	switch {
	case err == nil:
		return bytes.Equal(raw, key.Bytes()), true
	case errors.Is(err, mautrix.MNotFound), errors.Is(err, ssss.ErrNotEncryptedForKey):
		return false, true
	}
	return false, false
}

// signedBackupAuth is the auth data of a new backup with key, signed by
// master.
func signedBackupAuth(user id.UserID, master olm.PKSigning, key *backup.MegolmBackupKey) (backup.MegolmAuthData, error) {
	auth := backup.MegolmAuthData{PublicKey: backupPublicKey(key)}
	sig, err := master.SignJSON(auth)
	if err != nil {
		return auth, fmt.Errorf("rihma: sign key backup: %w", err)
	}
	auth.Signatures = signatures.NewSingleSignature(user, id.KeyAlgorithmEd25519, master.PublicKey().String(), sig)
	return auth, nil
}

// resignBackupAuth returns auth with this user's signatures replaced by
// master's. Those signatures came from the old identity and its devices,
// which clients no longer trust. Every other field, including any a client
// put there for its own use, is kept as the server has it.
func resignBackupAuth(auth json.RawMessage, user id.UserID, master olm.PKSigning) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(auth, &fields); err != nil || fields == nil {
		return nil, errors.New("auth data is not a JSON object")
	}
	// SignJSON leaves out the signatures field.
	sig, err := master.SignJSON(fields)
	if err != nil {
		return nil, err
	}
	var sigs signatures.Signatures
	if raw, ok := fields["signatures"]; ok {
		// A malformed signatures field signs nothing worth keeping.
		_ = json.Unmarshal(raw, &sigs)
	}
	if sigs == nil {
		sigs = signatures.Signatures{}
	}
	sigs[user] = map[id.KeyID]string{id.NewKeyID(id.KeyAlgorithmEd25519, master.PublicKey().String()): sig}
	if fields["signatures"], err = json.Marshal(sigs); err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}

// latestBackupRaw reads the latest backup version with its auth data as the
// server sent it, so a re-signed copy keeps fields mautrix does not model.
// It returns nil when the account has no backup.
func (c *Client) latestBackupRaw(ctx context.Context) (*mautrix.RespRoomKeysVersion[json.RawMessage], error) {
	var resp *mautrix.RespRoomKeysVersion[json.RawMessage]
	_, err := c.MakeRequest(ctx, http.MethodGet, c.BuildClientURL("v3", "room_keys", "version"), nil, &resp)
	switch {
	case errors.Is(err, mautrix.MNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	case resp == nil || resp.Version == "":
		return nil, nil
	}
	return resp, nil
}

// updateBackupAuth replaces a version's auth data (PUT
// /room_keys/version/{version}). mautrix's UpdateKeyBackupVersion sends no
// body as of v0.31.0, so rihma makes the request itself.
func (c *Client) updateBackupAuth(ctx context.Context, algorithm id.KeyBackupAlgorithm, version id.KeyBackupVersion, auth json.RawMessage) error {
	req := &mautrix.ReqRoomKeysVersionUpdate[json.RawMessage]{Algorithm: algorithm, AuthData: auth, Version: version}
	_, err := c.MakeRequest(ctx, http.MethodPut, c.BuildClientURL("v3", "room_keys", "version", version), req, nil)
	return err
}
