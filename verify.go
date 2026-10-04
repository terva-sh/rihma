package rihma

import (
	"context"
	"errors"
	"fmt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/id"
)

// ErrIdentityExists is returned by CreateRecoveryKey when the account
// already has a cross-signing identity. Replacing it would make every
// device and user that trusts the old one distrust this account, so
// CreateRecoveryKey never does it; restore from the existing recovery
// key instead. ResetCrossSigningIdentity replaces one deliberately.
var ErrIdentityExists = errors.New("rihma: account already has a cross-signing identity; restore it with its recovery key")

// OlmMachine is the mautrix crypto machine, for verification and trust
// queries rihma does not wrap. It is nil until Connect succeeds.
func (c *Client) OlmMachine() *crypto.OlmMachine { return c.helper.Machine() }

// HasCrossSigningIdentity asks the server whether the account has a
// cross-signing master key.
func (c *Client) HasCrossSigningIdentity(ctx context.Context) (bool, error) {
	resp, err := c.QueryKeys(ctx, &mautrix.ReqQueryKeys{
		DeviceKeys: mautrix.DeviceKeysRequest{c.UserID: mautrix.DeviceIDList{}},
	})
	if err != nil {
		return false, fmt.Errorf("rihma: query own keys: %w", err)
	}
	// A server may list the user with an empty key set; that is no identity.
	return len(resp.MasterKeys[c.UserID].Keys) > 0, nil
}

// CreateRecoveryKey gives a new account a cross-signing identity and
// secret storage, signs this device with it, and returns the recovery
// key. The key is secret: show it to the person once and never log it.
//
// It returns ErrIdentityExists if the account already has an identity,
// including one another device creates while this call runs: when the
// server asks for auth, rihma checks for an identity again before
// answering. password answers a server that asks for it before accepting
// a first identity, as servers before Matrix v1.11 did; current servers
// need none, and "" is fine. If such a server asks and password is "",
// the call fails with ErrPasswordRequired. On such a server, an identity
// created between that second check and the upload can still be
// replaced. The server accepts the keys before anything is
// written to secret storage; a failure after that is
// ErrIdentityIncomplete, which ResetCrossSigningIdentity repairs.
func (c *Client) CreateRecoveryKey(ctx context.Context, password string) (string, error) {
	return c.bootstrapIdentity(ctx, CrossSigningAuth{Password: password}, false)
}

// RestoreFromRecoveryKey fetches the account's cross-signing keys from
// secret storage with the recovery key and signs this device with them.
func (c *Client) RestoreFromRecoveryKey(ctx context.Context, recoveryKey string) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	if err := c.OlmMachine().VerifyWithRecoveryKey(ctx, recoveryKey); err != nil {
		return fmt.Errorf("rihma: restore from recovery key: %w", err)
	}
	return nil
}

func (c *Client) signSelf(ctx context.Context) error {
	mach := c.OlmMachine()
	if err := mach.SignOwnDevice(ctx, mach.OwnIdentity()); err != nil {
		return fmt.Errorf("rihma: sign own device: %w", err)
	}
	if err := mach.SignOwnMasterKey(ctx); err != nil {
		return fmt.Errorf("rihma: sign own master key: %w", err)
	}
	return nil
}

// Verdict is this device's standing with the account's cross-signing
// identity.
type Verdict string

const (
	// Verified: the identity's self-signing key has signed this device.
	Verified Verdict = "verified"
	// Unverified: the account has an identity and this device is not
	// signed by it. Verify it from another device, or restore from the
	// recovery key.
	Unverified Verdict = "unverified"
	// NoIdentity: the account has no cross-signing identity, so no
	// device can be verified. Create one (CreateRecoveryKey); no emoji
	// verification can help.
	NoIdentity Verdict = "no identity"
)

// Verification reads this device's verdict from the server, where other
// devices' signatures land.
func (c *Client) Verification(ctx context.Context) (Verdict, error) {
	if err := c.Connect(ctx); err != nil {
		return "", err
	}
	exists, err := c.HasCrossSigningIdentity(ctx)
	if err != nil {
		return "", err
	}
	if !exists {
		return NoIdentity, nil
	}
	ok, err := c.DeviceVerified(ctx)
	if err != nil {
		return "", err
	}
	if ok {
		return Verified, nil
	}
	return Unverified, nil
}

// DeviceVerified reports whether this device is signed by the account's
// cross-signing identity, as the server currently says.
func (c *Client) DeviceVerified(ctx context.Context) (bool, error) {
	if err := c.Connect(ctx); err != nil {
		return false, err
	}
	mach := c.OlmMachine()
	if _, err := mach.GetOwnCrossSigningPublicKeys(ctx); err != nil {
		return false, fmt.Errorf("rihma: fetch cross-signing keys: %w", err)
	}
	// Refresh our own device from the server, where other clients' signatures land.
	devices, err := mach.FetchKeys(ctx, []id.UserID{c.UserID}, true)
	if err != nil {
		return false, fmt.Errorf("rihma: fetch own device: %w", err)
	}
	dev, ok := devices[c.UserID][c.DeviceID]
	if !ok {
		return false, fmt.Errorf("rihma: server does not list this device")
	}
	trust, err := mach.ResolveTrustContext(ctx, dev)
	if err != nil {
		return false, err
	}
	return trust >= id.TrustStateCrossSignedVerified, nil
}
