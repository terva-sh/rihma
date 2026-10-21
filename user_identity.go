package rihma

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/id"
)

// Another user's cross-signing identity is vouched for by signing their
// master key with this account's user-signing key. The caller's proof is
// that a given key belongs to a given user, so rihma signs only the key the
// server publishes at that moment, and only if it is the one expected:
// signing what the cache holds would vouch for a key the server swapped in
// since. Every answer here comes from a fresh /keys/query, and every
// signature reported is checked, not taken from the server's word.

var (
	// ErrOwnUser is returned for this account's own user id. Its identity
	// is this device's to hold (OwnMasterKey), not another user's to sign.
	ErrOwnUser = errors.New("rihma: that is this account's own identity")
	// ErrNoCrossSigningKeys is returned when this device does not hold the
	// account's cross-signing keys (HasCrossSigningKeys), or when the keys
	// it holds are no longer the identity the server publishes.
	ErrNoCrossSigningKeys = errors.New("rihma: this device does not hold the account's cross-signing keys")
	// ErrNoUserIdentity is returned when the user publishes no
	// cross-signing master key.
	ErrNoUserIdentity = errors.New("rihma: the user publishes no cross-signing identity")
	// ErrMasterKeyMismatch is returned when the published master key is
	// not the expected one. The wrapping message names both keys.
	ErrMasterKeyMismatch = errors.New("rihma: the published master key is not the expected one")
)

// UserIdentity is another user's cross-signing identity as the homeserver
// publishes it.
type UserIdentity struct {
	UserID id.UserID
	// MasterKey is the user's master public key, unpadded base64 as the
	// server publishes it. It is public and safe to log.
	MasterKey id.Ed25519
	// SignedByUs: this account's user-signing key has a valid signature
	// on MasterKey, so this account vouches for the user's devices.
	//
	// Whether the user has signed this account cannot be read: servers
	// show a user-signing key's signatures only to their maker.
	SignedByUs bool
}

// IdentityChange reports that a user whose master key this account signed
// now publishes a different one. rihma never signs the new key on its own.
type IdentityChange struct {
	UserID id.UserID
	// Signed is the master key this account signed.
	Signed id.Ed25519
	// Published is the master key the user publishes now.
	Published id.Ed25519
}

// OwnMasterKey returns the public half of the master key this device
// holds, once a fresh query shows the server still publishes it. It never
// returns a key only the server vouches for, so a proof built on it
// cannot name a key swapped in by the server. It returns
// ErrNoCrossSigningKeys if this device does not hold the keys, and
// ErrMasterKeyMismatch if the server publishes another identity.
func (c *Client) OwnMasterKey(ctx context.Context) (id.Ed25519, error) {
	if err := c.Connect(ctx); err != nil {
		return "", err
	}
	if !c.HasCrossSigningKeys() {
		return "", ErrNoCrossSigningKeys
	}
	resp, err := c.queryIdentities(ctx)
	if err != nil {
		return "", err
	}
	held := c.OlmMachine().CrossSigningKeys.PublicKeys()
	if published := crossSigningKeysIn(resp, c.UserID); published == nil || *published != *held {
		return "", fmt.Errorf("%w: this device holds %s, the server publishes %s", ErrMasterKeyMismatch, held.MasterKey, publishedMaster(published))
	}
	return held.MasterKey, nil
}

// UserIdentity fetches userID's published identity from the homeserver
// and checks whether this account's signature on it is valid. It also
// refreshes the user's devices in the crypto store. It returns
// ErrNoUserIdentity when the user publishes none and ErrOwnUser for this
// account.
//
// Without the cross-signing keys on this device, SignedByUs rests on the
// server's report of this account's own identity.
func (c *Client) UserIdentity(ctx context.Context, userID id.UserID) (*UserIdentity, error) {
	if userID == c.UserID {
		return nil, ErrOwnUser
	}
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	resp, err := c.queryIdentities(ctx, userID)
	if err != nil {
		return nil, err
	}
	theirs, ok := masterKeyIn(resp, userID)
	if !ok {
		return nil, ErrNoUserIdentity
	}
	ident := &UserIdentity{UserID: userID, MasterKey: theirs.FirstKey()}
	if own := c.anchorKeys(resp); own != nil {
		ident.SignedByUs = signedBy(theirs, c.UserID, own.UserSigningKey)
	}
	if ident.SignedByUs {
		if err := c.rememberSigned(ctx, userID, ident.MasterKey); err != nil {
			return nil, fmt.Errorf("rihma: record %s's signed identity: %w", userID, err)
		}
	} else {
		c.observeIdentity(ctx, userID, ident.MasterKey)
	}
	if _, err := c.OlmMachine().FetchKeys(quiet(ctx), []id.UserID{userID}, true); err != nil {
		return nil, fmt.Errorf("rihma: fetch %s's devices: %w", userID, err)
	}
	return ident, nil
}

// SignUserIdentity signs userID's master key with this account's
// user-signing key, if the key the server publishes now is expected.
// Afterwards this client treats the user's cross-signed devices as
// verified. A key this account has already signed is not signed again.
//
// It refuses with ErrOwnUser, ErrNoCrossSigningKeys, ErrNoUserIdentity, or
// ErrMasterKeyMismatch, each matched by errors.Is. A failure after the
// signature is uploaded, in recording it for change reports or in the
// device refresh, leaves the key signed; calling again finishes the work
// without signing twice.
func (c *Client) SignUserIdentity(ctx context.Context, userID id.UserID, expected id.Ed25519) error {
	if userID == c.UserID {
		return ErrOwnUser
	}
	if err := c.Connect(ctx); err != nil {
		return err
	}
	if !c.HasCrossSigningKeys() {
		return ErrNoCrossSigningKeys
	}
	resp, err := c.queryIdentities(ctx, userID)
	if err != nil {
		return err
	}
	mach := c.OlmMachine()
	held := mach.CrossSigningKeys.PublicKeys()
	if published := crossSigningKeysIn(resp, c.UserID); published == nil || *published != *held {
		return fmt.Errorf("%w: the server publishes another identity for this account", ErrNoCrossSigningKeys)
	}
	theirs, ok := masterKeyIn(resp, userID)
	if !ok {
		return ErrNoUserIdentity
	}
	master := theirs.FirstKey()
	if master != expected {
		c.observeIdentity(ctx, userID, master)
		return fmt.Errorf("%w: %s publishes %s, expected %s", ErrMasterKeyMismatch, userID, master, expected)
	}
	if !signedBy(theirs, c.UserID, held.UserSigningKey) {
		// The signature covers exactly master, so a key swapped in after
		// the query is not vouched for by it.
		if err := mach.SignUser(quiet(ctx), userID, master); err != nil {
			return fmt.Errorf("rihma: sign %s's master key: %w", userID, err)
		}
	}
	// Without the record a later change would go unreported. The key is
	// signed either way, so a retry records it without signing again.
	if err := c.rememberSigned(ctx, userID, master); err != nil {
		return fmt.Errorf("rihma: record %s's signed identity: %w", userID, err)
	}
	// Store the user's keys, devices and our signature where trust checks
	// read them.
	if _, err := mach.FetchKeys(quiet(ctx), []id.UserID{userID}, true); err != nil {
		return fmt.Errorf("rihma: fetch %s's devices: %w", userID, err)
	}
	return nil
}

// queryIdentities asks the server for this account's keys and those of
// users.
func (c *Client) queryIdentities(ctx context.Context, users ...id.UserID) (*mautrix.RespQueryKeys, error) {
	req := mautrix.DeviceKeysRequest{c.UserID: mautrix.DeviceIDList{}}
	for _, user := range users {
		req[user] = mautrix.DeviceIDList{}
	}
	resp, err := c.QueryKeys(quiet(ctx), &mautrix.ReqQueryKeys{DeviceKeys: req})
	if err != nil {
		return nil, fmt.Errorf("rihma: query keys: %w", err)
	}
	return resp, nil
}

// anchorKeys is the identity this account's signatures are checked
// against: the keys this device holds, or else the published ones when
// their user-signing key carries the master key's signature.
func (c *Client) anchorKeys(resp *mautrix.RespQueryKeys) *crypto.CrossSigningPublicKeysCache {
	if c.HasCrossSigningKeys() {
		return c.OlmMachine().CrossSigningKeys.PublicKeys()
	}
	published := crossSigningKeysIn(resp, c.UserID)
	if published == nil || !signedBy(resp.UserSigningKeys[c.UserID], c.UserID, published.MasterKey) {
		return nil
	}
	return published
}

// masterKeyIn returns userID's master key object from a query response, if
// it publishes one.
func masterKeyIn(resp *mautrix.RespQueryKeys, userID id.UserID) (mautrix.CrossSigningKeys, bool) {
	keys, ok := resp.MasterKeys[userID]
	if !ok || keys.UserID != userID || !slices.Contains(keys.Usage, id.XSUsageMaster) || keys.FirstKey() == "" {
		return mautrix.CrossSigningKeys{}, false
	}
	return keys, true
}

// signedBy reports whether keys carries a valid signature by signer's
// key.
func signedBy(keys mautrix.CrossSigningKeys, signer id.UserID, key id.Ed25519) bool {
	if key == "" {
		return false
	}
	ok, err := signatures.VerifySignatureJSON(keys, signer, key.String(), key)
	return err == nil && ok
}

func publishedMaster(keys *crypto.CrossSigningPublicKeysCache) id.Ed25519 {
	if keys == nil {
		return "no complete identity"
	}
	return keys.MasterKey
}

// quiet keeps mautrix's crypto logs on the machine's logger, which drops
// signatures, rather than on a logger the caller's context may carry.
func quiet(ctx context.Context) context.Context { return zerolog.Nop().WithContext(ctx) }

// signedIdentities remembers, in the store, the master key this account
// signed for each user and every other key since reported for them, so a
// change is reported once per key, across restarts. Signing another key
// starts the reports afresh.
type signedIdentities struct {
	mu     sync.Mutex
	loaded bool
	users  map[id.UserID]*signedIdentity
}

type signedIdentity struct {
	signed   id.Ed25519
	reported map[id.Ed25519]bool
}

func (c *Client) loadSignedIdentities(ctx context.Context) error {
	s := &c.signed
	if s.loaded {
		return nil
	}
	for _, table := range []string{
		"CREATE TABLE IF NOT EXISTS rihma_signed_identity (user_id TEXT PRIMARY KEY, master_key TEXT NOT NULL)",
		"CREATE TABLE IF NOT EXISTS rihma_reported_identity (user_id TEXT NOT NULL, master_key TEXT NOT NULL, PRIMARY KEY (user_id, master_key))",
	} {
		if _, err := c.db.Exec(ctx, table); err != nil {
			return err
		}
	}
	users := map[id.UserID]*signedIdentity{}
	err := c.scanRows(ctx, "SELECT user_id, master_key FROM rihma_signed_identity", func(user id.UserID, key id.Ed25519) {
		users[user] = &signedIdentity{signed: key, reported: map[id.Ed25519]bool{}}
	})
	if err != nil {
		return err
	}
	err = c.scanRows(ctx, "SELECT user_id, master_key FROM rihma_reported_identity", func(user id.UserID, key id.Ed25519) {
		if ident := users[user]; ident != nil {
			ident.reported[key] = true
		}
	})
	if err != nil {
		return err
	}
	s.users, s.loaded = users, true
	return nil
}

func (c *Client) scanRows(ctx context.Context, query string, row func(id.UserID, id.Ed25519)) error {
	rows, err := c.db.Query(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var user id.UserID
		var key id.Ed25519
		if err := rows.Scan(&user, &key); err != nil {
			return err
		}
		row(user, key)
	}
	return rows.Err()
}

// rememberSigned records that this account vouches for key as userID's
// master key. Its error means a later change may go unreported.
func (c *Client) rememberSigned(ctx context.Context, userID id.UserID, key id.Ed25519) error {
	c.signed.mu.Lock()
	defer c.signed.mu.Unlock()
	if err := c.loadSignedIdentities(ctx); err != nil {
		return err
	}
	if ident := c.signed.users[userID]; ident != nil && ident.signed == key {
		return nil
	}
	err := c.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		if _, err := c.db.Exec(ctx, `INSERT INTO rihma_signed_identity (user_id, master_key) VALUES ($1, $2)
			ON CONFLICT (user_id) DO UPDATE SET master_key=excluded.master_key`, userID, key); err != nil {
			return err
		}
		_, err := c.db.Exec(ctx, "DELETE FROM rihma_reported_identity WHERE user_id=$1", userID)
		return err
	})
	if err != nil {
		return err
	}
	c.signed.users[userID] = &signedIdentity{signed: key, reported: map[id.Ed25519]bool{}}
	return nil
}

// observeIdentity reports published as a change if userID's master key was
// signed by this account and published is neither that key nor one already
// reported.
func (c *Client) observeIdentity(ctx context.Context, userID id.UserID, published id.Ed25519) {
	if published == "" {
		return
	}
	c.signed.mu.Lock()
	err := c.loadSignedIdentities(ctx)
	var signed id.Ed25519
	report := false
	if ident := c.signed.users[userID]; err == nil && ident != nil && published != ident.signed && !ident.reported[published] {
		// A change is a security warning, so it is delivered even when the
		// store refuses the record; marking it here stops this process
		// repeating it, and only a restart can report it once more.
		_, err = c.db.Exec(ctx, "INSERT INTO rihma_reported_identity (user_id, master_key) VALUES ($1, $2) ON CONFLICT DO NOTHING", userID, published)
		ident.reported[published] = true
		signed, report = ident.signed, true
	}
	c.signed.mu.Unlock()
	if err != nil {
		c.opts.Logger.Warn().Err(err).Stringer("user_id", userID).Msg("cannot record a signed identity's change; a restart may report it again")
	}
	if !report {
		return
	}
	c.opts.Logger.Warn().
		Stringer("user_id", userID).
		Stringer("signed_master_key", signed).
		Stringer("published_master_key", published).
		Msg("a user this account signed publishes a different master key; it is not signed")
	if c.opts.OnIdentityChange != nil {
		c.opts.OnIdentityChange(IdentityChange{UserID: userID, Signed: signed, Published: published})
	}
}

// checkIdentityChanges runs after the crypto machine has fetched the keys
// of users whose devices changed, and compares each signed user's master
// key in the crypto store with the one this account signed.
func (c *Client) checkIdentityChanges(ctx context.Context, changed []id.UserID) {
	if len(changed) == 0 {
		return
	}
	c.signed.mu.Lock()
	err := c.loadSignedIdentities(ctx)
	var watched []id.UserID
	for _, user := range changed {
		if _, ok := c.signed.users[user]; ok {
			watched = append(watched, user)
		}
	}
	c.signed.mu.Unlock()
	if err != nil {
		c.opts.Logger.Warn().Err(err).Msg("cannot check signed identities for changes")
		return
	}
	if len(watched) == 0 {
		return
	}
	mach := c.OlmMachine()
	ctx = quiet(ctx)
	own, err := mach.GetOwnCrossSigningPublicKeys(ctx)
	if err != nil {
		c.opts.Logger.Warn().Err(err).Msg("cannot check signed identities for changes")
		return
	}
	for _, user := range watched {
		keys, err := mach.CryptoStore.GetCrossSigningKeys(ctx, user)
		if err != nil {
			c.opts.Logger.Warn().Err(err).Stringer("user_id", user).Msg("cannot check a signed identity for changes")
			continue
		}
		master := keys[id.XSUsageMaster].Key
		if master == "" {
			continue
		}
		// Another device of this account may have signed the new key.
		var signed bool
		if own != nil && own.UserSigningKey != "" {
			if signed, err = mach.CryptoStore.IsKeySignedBy(ctx, user, master, c.UserID, own.UserSigningKey); err != nil {
				c.opts.Logger.Warn().Err(err).Stringer("user_id", user).Msg("cannot check a signed identity for changes")
				continue
			}
		}
		if signed {
			if err := c.rememberSigned(ctx, user, master); err != nil {
				c.opts.Logger.Warn().Err(err).Stringer("user_id", user).Msg("cannot record a signed identity; a later change to it may go unreported")
			}
		} else {
			c.observeIdentity(ctx, user, master)
		}
	}
}
