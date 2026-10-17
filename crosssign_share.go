package rihma

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

// Cross-signing private keys let a device sign the account's other devices,
// so a device verified by SAS can verify the next one. rihma keeps them in
// the crypto store, encrypted with the pickle key, under its own names so
// they survive restarts. mautrix answers verified siblings' secret requests
// from the standard names, so rihma copies the keys there only once it has
// checked them against the identity the server publishes, and clears those
// copies at every Connect until the check passes again.

// ErrCrossSigningKeysNotShared is returned by RequestCrossSigningKeys when no
// verified device of this account sent all three cross-signing keys in time.
// The recovery key still works: RestoreFromRecoveryKey.
var ErrCrossSigningKeysNotShared = errors.New("rihma: no verified device shared the cross-signing keys")

// crossSigningSecrets names each key: name is the shared, standard secret
// and kept is rihma's private copy.
var crossSigningSecrets = [...]struct {
	name, kept id.Secret
	usage      id.CrossSigningUsage
}{
	{id.SecretXSMaster, "rihma.cross_signing.master", id.XSUsageMaster},
	{id.SecretXSSelfSigning, "rihma.cross_signing.self_signing", id.XSUsageSelfSigning},
	{id.SecretXSUserSigning, "rihma.cross_signing.user_signing", id.XSUsageUserSigning},
}

type crossSigningState struct {
	// slot admits one RequestCrossSigningKeys at a time; a queued caller
	// can still give up when its context or wait ends.
	once sync.Once
	slot chan struct{}
	// held is set once this device holds checked keys. mautrix reads and
	// writes its own key field unsynchronized, so callers read this instead.
	held atomic.Bool
}

func (x *crossSigningState) admit() chan struct{} {
	x.once.Do(func() { x.slot = make(chan struct{}, 1) })
	return x.slot
}

// HasCrossSigningKeys reports whether this device holds the account's
// cross-signing private keys, and so can verify the account's other devices.
func (c *Client) HasCrossSigningKeys() bool { return c.xsign.held.Load() }

// RequestCrossSigningKeys asks this account's other verified devices for the
// cross-signing private keys, as other clients do once a device is verified.
// Each key is accepted only if its public half is the one the server
// publishes. Afterwards this device signs the devices it verifies.
//
// A device that already holds the keys, or an account without an identity,
// returns nil. If no device sends all three within wait, it returns
// ErrCrossSigningKeysNotShared.
func (c *Client) RequestCrossSigningKeys(ctx context.Context, wait time.Duration) error {
	// wait bounds the whole request: connecting, which checks stored keys
	// against the server, and time queued behind another request.
	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if err := c.Connect(waitCtx); err != nil {
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case waitCtx.Err() != nil:
			return ErrCrossSigningKeysNotShared
		}
		return err
	}
	select {
	case c.xsign.admit() <- struct{}{}:
		defer func() { <-c.xsign.admit() }()
	case <-waitCtx.Done():
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrCrossSigningKeysNotShared
	}
	published, err := c.publishedCrossSigningKeys(waitCtx)
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case waitCtx.Err() != nil:
		return ErrCrossSigningKeysNotShared
	case err != nil:
		return err
	case published == nil:
		return nil
	}
	mach := c.OlmMachine()
	if have := mach.CrossSigningKeys; c.xsign.held.Load() && have != nil && *have.PublicKeys() == *published {
		return nil
	}
	var seeds crypto.CrossSigningSeeds
	for _, secret := range crossSigningSecrets {
		want := publishedKey(published, secret.usage)
		var seed []byte
		accept := func(value string) (bool, error) {
			candidate, ok := parseSeed(value)
			if !ok || seedPublicKey(candidate) != want {
				// A stale key, or one from before an identity reset.
				return false, nil
			}
			seed = candidate
			return true, nil
		}
		for seed == nil {
			attempt, stop := context.WithTimeout(waitCtx, shareRequestInterval)
			err := mach.GetOrRequestSecret(attempt, secret.name, accept, shareRequestInterval)
			stop()
			switch {
			case seed != nil:
			case ctx.Err() != nil:
				return ctx.Err()
			case waitCtx.Err() != nil:
				return ErrCrossSigningKeysNotShared
			case err != nil && !errors.Is(err, context.DeadlineExceeded):
				return fmt.Errorf("rihma: request cross-signing key: %w", err)
			}
		}
		switch secret.usage {
		case id.XSUsageMaster:
			seeds.MasterKey = seed
		case id.XSUsageSelfSigning:
			seeds.SelfSigningKey = seed
		case id.XSUsageUserSigning:
			seeds.UserSigningKey = seed
		}
	}
	if err := mach.ImportCrossSigningKeys(seeds); err != nil {
		return fmt.Errorf("rihma: import cross-signing keys: %w", err)
	}
	return c.storeCrossSigningSecrets(ctx, mach)
}

// storeCrossSigningSecrets keeps the machine's cross-signing keys, which the
// caller has just created or checked, for restarts and for verified
// siblings' requests. The wire form is unpadded base64, as other clients
// send it.
func (c *Client) storeCrossSigningSecrets(ctx context.Context, mach *crypto.OlmMachine) error {
	keys := mach.CrossSigningKeys
	if keys == nil {
		return nil
	}
	seeds := keys.Seeds()
	for _, secret := range crossSigningSecrets {
		value := base64.RawStdEncoding.EncodeToString(seedFor(&seeds, secret.usage))
		for _, name := range []id.Secret{secret.kept, secret.name} {
			if err := mach.CryptoStore.PutSecret(ctx, name, value); err != nil {
				return fmt.Errorf("rihma: store cross-signing keys: %w", err)
			}
		}
	}
	c.xsign.held.Store(true)
	return nil
}

func seedFor(seeds *crypto.CrossSigningSeeds, usage id.CrossSigningUsage) []byte {
	switch usage {
	case id.XSUsageMaster:
		return seeds.MasterKey
	case id.XSUsageSelfSigning:
		return seeds.SelfSigningKey
	default:
		return seeds.UserSigningKey
	}
}

// loadCrossSigningSecrets restores the kept keys if they are still the
// identity published says the server has. Until that check passes nothing is
// shareable: the shared copies are cleared first, and only checked keys are
// copied back. Keys from before another device reset the identity, or an
// incomplete set, are deleted. When the server cannot be asked, the kept
// keys wait for the next Connect.
func (c *Client) loadCrossSigningSecrets(ctx context.Context, mach *crypto.OlmMachine, published func(context.Context) (*crypto.CrossSigningPublicKeysCache, error)) error {
	if err := deleteSecrets(ctx, mach, false); err != nil {
		return err
	}
	var seeds crypto.CrossSigningSeeds
	for _, secret := range crossSigningSecrets {
		value, err := mach.CryptoStore.GetSecret(ctx, secret.kept)
		if err != nil {
			return err
		}
		seed, ok := parseSeed(value)
		if !ok {
			return deleteSecrets(ctx, mach, true)
		}
		switch secret.usage {
		case id.XSUsageMaster:
			seeds.MasterKey = seed
		case id.XSUsageSelfSigning:
			seeds.SelfSigningKey = seed
		case id.XSUsageUserSigning:
			seeds.UserSigningKey = seed
		}
	}
	want, err := published(ctx)
	if err != nil {
		return err
	}
	stored, err := seeds.Decode()
	if err != nil || want == nil || *stored.PublicKeys() != *want {
		return deleteSecrets(ctx, mach, true)
	}
	if err := mach.ImportCrossSigningKeys(seeds); err != nil {
		return err
	}
	return c.storeCrossSigningSecrets(ctx, mach)
}

// deleteSecrets removes the shared copies, and with kept the private ones too.
func deleteSecrets(ctx context.Context, mach *crypto.OlmMachine, kept bool) error {
	for _, secret := range crossSigningSecrets {
		names := []id.Secret{secret.name}
		if kept {
			names = append(names, secret.kept)
		}
		for _, name := range names {
			if err := mach.CryptoStore.DeleteSecret(ctx, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// publishedCrossSigningKeys asks the server for the account's cross-signing
// public keys, or nil when the account has no complete identity.
func (c *Client) publishedCrossSigningKeys(ctx context.Context) (*crypto.CrossSigningPublicKeysCache, error) {
	resp, err := c.QueryKeys(ctx, &mautrix.ReqQueryKeys{
		DeviceKeys: mautrix.DeviceKeysRequest{c.UserID: mautrix.DeviceIDList{}},
	})
	if err != nil {
		return nil, fmt.Errorf("rihma: query own keys: %w", err)
	}
	master, self, user := resp.MasterKeys[c.UserID], resp.SelfSigningKeys[c.UserID], resp.UserSigningKeys[c.UserID]
	keys := &crypto.CrossSigningPublicKeysCache{MasterKey: master.FirstKey(), SelfSigningKey: self.FirstKey(), UserSigningKey: user.FirstKey()}
	if keys.MasterKey == "" || keys.SelfSigningKey == "" || keys.UserSigningKey == "" {
		return nil, nil
	}
	return keys, nil
}

func publishedKey(keys *crypto.CrossSigningPublicKeysCache, usage id.CrossSigningUsage) id.Ed25519 {
	switch usage {
	case id.XSUsageMaster:
		return keys.MasterKey
	case id.XSUsageSelfSigning:
		return keys.SelfSigningKey
	default:
		return keys.UserSigningKey
	}
}

func parseSeed(value string) ([]byte, bool) {
	seed, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(value), "="))
	if err != nil || len(seed) != 32 {
		return nil, false
	}
	return seed, true
}

func seedPublicKey(seed []byte) id.Ed25519 {
	key, err := olm.NewPKSigningFromSeed(seed)
	if err != nil {
		return ""
	}
	return key.PublicKey()
}
