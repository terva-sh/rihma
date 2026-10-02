package connector

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/term"
	"maunium.net/go/mautrix"

	"terva.sh/rihma"
)

// remoteTimeout bounds the network calls a verb makes on its own: a
// verb must not hang on a homeserver that is down.
const remoteTimeout = 30 * time.Second

// Setup asks for the homeserver, user, and password, and logs in as a
// new device. Off a terminal it reads plain lines, so it can be scripted:
//
//	printf 'https://hs\n@bot:hs\npassword\n' | terva-rihma setup
//
// The new device logs in before anything stored is touched, so a failed
// login leaves the existing session working; after it succeeds the old
// session is logged out, best effort. Then it offers
// to create or restore the account's recovery key, and an emoji
// verification; piped input that stops after the password gets the
// defaults, a new recovery key and no emoji wait.
func Setup() error { return setup(os.Stdin, os.Stdout) }

func setup(in *os.File, out io.Writer) error {
	r := bufio.NewReader(in)
	hs, err := prompt(r, out, "homeserver URL (e.g. https://matrix.example.org): ")
	if err != nil {
		return err
	}
	user, err := prompt(r, out, "bot user id (e.g. @bot:example.org): ")
	if err != nil {
		return err
	}
	password, err := promptSecret(r, in, out, "password: ")
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), remoteTimeout)
	defer cancel()

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	login := &mautrix.ReqLogin{
		Type:       mautrix.AuthTypePassword,
		Identifier: mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: user},
		Password:   password,
	}
	fresh, err := stageLogin(ctx, cfg, hs, login)
	if err != nil {
		return fmt.Errorf("login failed; the existing session is untouched: %w", err)
	}

	// The new device works. Only now retire the old one, whose session
	// logoutStored reads from config.json, so it goes before the save.
	if cfg.configured() {
		fmt.Fprintln(out, "replacing the existing session")
		logoutStored(ctx, cfg, out)
	}
	cfg, err = loadConfig()
	if err != nil {
		return err
	}
	cfg.HomeserverURL = hs
	cfg.Session, cfg.DeviceID = nil, ""
	cfg.E2EE, cfg.E2EESource = "", ""
	if cfg.AutoJoin == "" {
		cfg.AutoJoin = autoJoinAlways
	}
	if err := saveConfig(cfg); err != nil {
		return err
	}
	if err := (sessionStore{}).Save(ctx, fresh); err != nil {
		return err
	}
	if err := os.RemoveAll(storeDir()); err != nil {
		return err
	}
	if err := os.Rename(stagingDir(), storeDir()); err != nil {
		return err
	}
	cfg, err = loadConfig()
	if err != nil {
		return err
	}
	client, err := rihma.Open(ctx, verbOptions(cfg, nil))
	if err != nil {
		return err
	}
	defer client.Close()
	fmt.Fprintf(out, "logged in as %s (device %s)\nsaved: %s\n", client.UserID, client.DeviceID, State.Path())
	e2eeSetup(client, password, r, in, out)
	fmt.Fprintln(out, "\nnext: start the bot through terva, then invite it to a DM.")
	return nil
}

// verbOptions are clientOptions for the interactive verbs. Their stderr
// is the operator's terminal, not the host's log, so mautrix's routine
// info lines (schema upgrades, key uploads) would bury the prompts and
// the one-time recovery key. Warnings still show.
func verbOptions(c fileConfig, login *mautrix.ReqLogin) rihma.Options {
	o := clientOptions(c, login)
	o.Logger = o.Logger.Level(zerolog.WarnLevel)
	return o
}

// stagingDir holds a new login's store until the login has worked.
func stagingDir() string { return storeDir() + ".setup" }

// stageLogin logs in as a new device without touching the stored
// session: the store goes to stagingDir and the session stays in memory.
// A wrong URL or password must not cost the operator a working bot.
func stageLogin(ctx context.Context, cfg fileConfig, hs string, login *mautrix.ReqLogin) (*rihma.Session, error) {
	if err := os.RemoveAll(stagingDir()); err != nil {
		return nil, err
	}
	held := &heldSession{}
	opts := verbOptions(cfg, login)
	opts.Homeserver, opts.StateDir, opts.Sessions = hs, stagingDir(), held
	client, err := rihma.Open(ctx, opts)
	if err != nil {
		_ = os.RemoveAll(stagingDir())
		return nil, err
	}
	client.Close()
	return held.s, nil
}

// heldSession is a SessionStore that keeps the session in memory.
type heldSession struct{ s *rihma.Session }

func (h *heldSession) Load(context.Context) (*rihma.Session, error) { return h.s, nil }
func (h *heldSession) Save(_ context.Context, s *rihma.Session) error {
	h.s = s
	return nil
}
func (h *heldSession) Clear(context.Context) error {
	h.s = nil
	return nil
}

func prompt(r *bufio.Reader, out io.Writer, label string) (string, error) {
	fmt.Fprint(out, label)
	line, err := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		if err != nil {
			return "", fmt.Errorf("setup: no answer to %q: %w", strings.TrimSpace(label), err)
		}
		return "", fmt.Errorf("setup: empty answer to %q", strings.TrimSpace(label))
	}
	return line, nil
}

// promptSecret hides the input on a terminal and reads a plain line
// otherwise.
func promptSecret(r *bufio.Reader, in *os.File, out io.Writer, label string) (string, error) {
	if !term.IsTerminal(int(in.Fd())) {
		return prompt(r, out, label)
	}
	fmt.Fprint(out, label)
	b, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", errors.New("setup: empty password")
	}
	return string(b), nil
}

// logoutStored ends the stored session on the server and locally, best
// effort: a dead token or an unreachable server must not block setup or
// reset, which are how an operator recovers from exactly those.
func logoutStored(ctx context.Context, cfg fileConfig, out io.Writer) {
	client, err := rihma.Open(ctx, verbOptions(cfg, nil))
	if err != nil {
		fmt.Fprintf(out, "warning: could not open the old session: %v\n", err)
		return
	}
	if err := client.Logout(ctx); err != nil {
		fmt.Fprintf(out, "warning: server-side logout failed, the old device may remain listed: %v\n", err)
		client.Close()
	}
}

// Status describes the configuration from local files only, with every
// secret masked.
func Status() (string, error) {
	cfg, err := loadConfig()
	if err != nil {
		return "", err
	}
	if !cfg.configured() {
		return "not configured (run `terva bot setup --connector rihma`)", nil
	}
	store := "present"
	if _, err := os.Stat(storeDir()); errors.Is(err, fs.ErrNotExist) {
		store = "missing"
	}
	autoJoin := cfg.AutoJoin
	if autoJoin == "" {
		autoJoin = autoJoinAlways
	}
	// No verdict is not "unverified": it is what a setup killed before
	// reading one leaves, and verify is the verb that fixes it.
	var e2ee string
	switch {
	case cfg.E2EE == "":
		e2ee = "not recorded (run `./run.sh verify` in the connector directory)"
	case cfg.E2EESource == "verify":
		e2ee = cfg.E2EE + " (as of the last verify)"
	default:
		e2ee = cfg.E2EE + " (as of setup)"
	}
	return fmt.Sprintf(`rihma bot:   %s (device %s)
homeserver:  %s
token:       %s
auto join:   %s
speaker:     %s
e2ee:        %s
key backup:  %s
store:       %s
config file: %s`, cfg.UserID, cfg.DeviceID, cfg.HomeserverURL, maskToken(cfg.Session.AccessToken), autoJoin, speakerStatus(cfg.Speaker), e2ee, backupStatus(cfg), store, State.Path()), nil
}

func speakerStatus(mode string) string {
	switch mode {
	case "", speakerOff:
		return "off (terva prefixes the name)"
	case speakerNameOnly, speakerFull:
		return mode + " (MSC4144 profiles)"
	}
	return fmt.Sprintf("%q is not off, name_only, or full; off", mode)
}

func backupStatus(cfg fileConfig) string {
	if cfg.Session.BackupKey == "" || cfg.Session.BackupVersion == "" {
		return "none"
	}
	return "version " + cfg.Session.BackupVersion
}

// maskToken shows only enough of a token to tell two apart.
func maskToken(tok string) string {
	if len(tok) <= 10 {
		return "<hidden>"
	}
	return tok[:4] + "..." + tok[len(tok)-4:]
}

// Configured is true when a session is stored. It reads only local files.
func Configured() bool {
	cfg, err := loadConfig()
	return err == nil && cfg.configured()
}

// Reset logs out on the server, best effort, then removes config.json and
// rihma's store. It never touches the host's pairing.json or data/.
func Reset() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.configured() {
		ctx, cancel := context.WithTimeout(context.Background(), remoteTimeout)
		logoutStored(ctx, cfg, os.Stdout)
		cancel()
	}
	removed := false
	for _, p := range []string{State.Path(), storeDir()} {
		if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := os.RemoveAll(p); err != nil {
			return err
		}
		fmt.Printf("removed %s\n", p)
		removed = true
	}
	if !removed {
		fmt.Println("no rihma config to remove")
	}
	return nil
}

// Verify reads this device's verification verdict on the stored session,
// without logging in again, records it for status, and when the device
// is unverified offers to wait for an emoji verification. The verdict is
// recorded before the wait, so a closed terminal still leaves it. terva
// never calls this verb; an operator runs it.
func Verify() error { return verify(os.Stdin, os.Stdout) }

func verify(in *os.File, out io.Writer) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if !cfg.configured() {
		return errors.New("not configured (run `terva bot setup --connector rihma`)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), remoteTimeout)
	defer cancel()
	client, err := rihma.Open(ctx, verbOptions(cfg, nil))
	if err != nil {
		return err
	}
	defer client.Close()
	v := readVerdict(client, out, "verify")
	if v == "" {
		return errors.New("the verification state could not be read")
	}
	r := bufio.NewReader(in)
	if v == rihma.Unverified && yes(promptDefault(r, out, "wait for emoji verification from another client now? [y/N]: ", "n")) {
		runSAS(client, r, out)
		v = readVerdict(client, out, "verify")
	}
	// The exit status carries the verdict, for scripts.
	if v != rihma.Verified {
		return fmt.Errorf("device %s is not verified", client.DeviceID)
	}
	return nil
}
