package connector

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestSessionSecretsRedacted checks that the sealed session values never
// print through fmt, alone or inside the config, while JSON, the sealed
// format, keeps them.
func TestSessionSecretsRedacted(t *testing.T) {
	const access = "synthetic-sealed-access"
	s := &sessionSecrets{AccessToken: access, PickleKey: "synthetic-sealed-pickle", BackupKey: "synthetic-sealed-backup"}
	// Only fileConfig holds a sessionSecrets, in an exported field, where
	// fmt calls its formatter.
	for _, v := range []any{s, *s, fileConfig{Session: s}, &fileConfig{Session: s}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			out := fmt.Sprintf(verb, v)
			for _, secret := range []string{access, "synthetic-sealed-pickle", "synthetic-sealed-backup", fmt.Sprintf("%x", access)} {
				if strings.Contains(out, secret) {
					t.Fatalf("%s leaked a sealed value: %q", verb, out)
				}
			}
		}
	}
	if b, err := json.Marshal(s); err != nil || !strings.Contains(string(b), access) {
		t.Fatal("sealed JSON lost the access token")
	}
}
