package connector

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"terva.sh/rihma"
)

// sasWait bounds how long setup and verify wait for another client to
// start an emoji verification, as terva-conn-matrix does.
const sasWait = 2 * time.Minute

// backupTimeout bounds downloading a key backup, which can be large.
const backupTimeout = 2 * time.Minute

// e2eeSetup is setup's verification step, after the session is saved: a
// failure here costs the operator a verified device, never the login.
// The default, [1], is what piped provisioning gets.
func e2eeSetup(client *rihma.Client, password string, r *bufio.Reader, in *os.File, out io.Writer) {
	fmt.Fprintln(out, "\ne2ee: how should this device be verified?")
	fmt.Fprintln(out, "  [1] create a new recovery key (a new bot account; the key prints once)")
	fmt.Fprintln(out, "  [2] restore from the account's recovery key")
	fmt.Fprintln(out, "  [3] skip (encrypted rooms still work; verify later with `verify`)")
	choice := promptDefault(r, out, "choice [1]: ", "1")

	ctx, cancel := context.WithTimeout(context.Background(), remoteTimeout)
	defer cancel()
	switch choice {
	case "2":
		key, err := promptSecret(r, in, out, "recovery key: ")
		if err != nil {
			fmt.Fprintf(out, "no recovery key read (%v); skipping\n", err)
			break
		}
		if err := client.RestoreFromRecoveryKey(ctx, key); err != nil {
			fmt.Fprintf(out, "restore failed: %v\n", err)
			break
		}
		fmt.Fprintln(out, "restored the account's identity; this device is signed by it")
		bctx, bcancel := context.WithTimeout(context.Background(), backupTimeout)
		err = client.RestoreKeyBackup(bctx, key)
		bcancel()
		switch {
		case err != nil:
			fmt.Fprintf(out, "key backup: restore failed: %v\n", err)
		case client.KeyBackupVersion() == "":
			fmt.Fprintln(out, "key backup: the account has none")
		default:
			fmt.Fprintf(out, "key backup: restored version %s; new room keys upload to it\n", client.KeyBackupVersion())
		}
	case "3":
		fmt.Fprintln(out, "skipped")
	default:
		key, err := client.CreateRecoveryKey(ctx, password)
		if errors.Is(err, rihma.ErrIdentityExists) {
			fmt.Fprintln(out, "this account already has a cross-signing identity, and replacing it would make")
			fmt.Fprintln(out, "everyone who trusts it distrust this account, so rihma never does.")
			fmt.Fprintln(out, "run setup again and choose [2] with the account's recovery key, or verify by emoji below.")
			break
		}
		if err != nil {
			fmt.Fprintf(out, "creating a recovery key failed: %v\n", err)
			break
		}
		fmt.Fprintf(out, "\nrecovery key (shown once; store it safely, a later setup can restore with it):\n\n  %s\n\n", key)
		switch err := client.EnableKeyBackup(ctx, key); {
		case errors.Is(err, rihma.ErrBackupExists):
			fmt.Fprintln(out, "key backup: the account already has one, and rihma never replaces it; none enabled")
		case err != nil:
			fmt.Fprintf(out, "key backup: not enabled: %v\n", err)
		default:
			fmt.Fprintf(out, "key backup: enabled, version %s\n", client.KeyBackupVersion())
		}
	}

	verdict := readVerdict(client, out, "setup")
	if verdict == rihma.Unverified && yes(promptDefault(r, out, "wait for emoji verification from another client now? [y/N]: ", "n")) {
		runSAS(client, r, out)
		readVerdict(client, out, "setup")
	}
}

// readVerdict asks the server for this device's verdict, prints it, and
// records it in config.json for status. A failed read records nothing,
// so status keeps the last thing actually known.
func readVerdict(client *rihma.Client, out io.Writer, source string) rihma.Verdict {
	ctx, cancel := context.WithTimeout(context.Background(), remoteTimeout)
	defer cancel()
	v, err := client.Verification(ctx)
	if err != nil {
		fmt.Fprintf(out, "could not read the verification state: %v\n", err)
		return ""
	}
	fmt.Fprintf(out, "device %s: %s\n", client.DeviceID, v)
	if v == rihma.NoIdentity {
		fmt.Fprintln(out, "note: the account has no cross-signing identity, so no device can read as verified.")
		fmt.Fprintln(out, "      Create one with setup, option [1]; an emoji verification cannot help.")
	}
	if err := recordVerdict(v, source); err != nil {
		fmt.Fprintf(out, "could not record the verdict: %v\n", err)
	}
	return v
}

func recordVerdict(v rihma.Verdict, source string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	cfg.E2EE, cfg.E2EESource = string(v), source
	return saveConfig(cfg)
}

// runSAS waits for an emoji verification started from another client on
// the bot's account, and asks the operator to compare the emoji.
func runSAS(client *rihma.Client, r *bufio.Reader, out io.Writer) {
	fmt.Fprintf(out, "waiting up to %s: start an emoji verification from another client logged in as %s\n", sasWait, client.UserID)
	fmt.Fprintf(out, "(this device shows as %q, id %s)...\n", deviceName, client.DeviceID)
	ctx, cancel := context.WithTimeout(context.Background(), sasWait)
	defer cancel()
	err := client.AwaitSAS(ctx, func(emoji []rihma.SASEmoji) bool {
		fmt.Fprintln(out, "\ncompare with the other client:")
		for _, e := range emoji {
			fmt.Fprintf(out, "  %s  %s\n", e.Emoji, e.Description)
		}
		return yes(promptDefault(r, out, "do the emoji match on both devices? [y/N]: ", "n"))
	})
	switch {
	case err == nil:
		fmt.Fprintln(out, "emoji verification done")
	case errors.Is(err, rihma.ErrSyncInProgress):
		fmt.Fprintln(out, "the connector is running on this state, and two syncs on one device lose encryption keys.")
		fmt.Fprintln(out, "stop the bot first, then run verify.")
	case errors.Is(err, context.DeadlineExceeded):
		fmt.Fprintln(out, "no verification arrived; skipping")
	default:
		fmt.Fprintf(out, "emoji verification failed: %v\n", err)
	}
}

// promptDefault reads one line; an empty line or end of input is def.
func promptDefault(r *bufio.Reader, out io.Writer, label, def string) string {
	fmt.Fprint(out, label)
	line, _ := r.ReadString('\n')
	if line = strings.TrimSpace(line); line != "" {
		return line
	}
	return def
}

func yes(s string) bool {
	switch strings.ToLower(s) {
	case "y", "yes":
		return true
	}
	return false
}
