//go:build dogfood

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOversizeNeedsFreshOperatorAndDiagnosticEvidence(t *testing.T) {
	const diagnostic = "{\"event_id\":\"$oversize\",\"message\":\"dropping attachment\"}\n"
	const warning = "Matrix room \"!room:hs\", event \"$oversize\": dropped attachment. Limit 1048576 bytes.\n"
	for _, tc := range []struct {
		name, baseline, diagnostic, operator string
		wantDrop, wantWarn                   bool
	}{
		{"both", "", diagnostic, warning, true, true},
		{"CLI connector prefix", "", diagnostic, `connector "rihma": ` + warning, true, true},
		{"log only", "", diagnostic, "", true, false},
		{"operator only", "", "", warning, false, true},
		{"stale output", diagnostic + warning, "", "", false, false},
		{"other event", "", "{\"event_id\":\"$other\",\"message\":\"dropping attachment\"}\n", "Matrix room \"!room:hs\", event \"$other\": dropped attachment.\n", false, false},
		{"diagnostic forwarded as output", "", diagnostic, diagnostic, true, false},
		{"split across lines", "", "{\"event_id\":\"$oversize\"}\n{\"message\":\"dropping attachment\"}\n", "Matrix room \"!room:hs\", event \"$oversize\"\ndropped attachment.\n", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			marks := make([]logMark, 2)
			for i, name := range []string{"connector.log", "operator.log"} {
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte(tc.baseline), 0o600); err != nil {
					t.Fatal(err)
				}
				var err error
				marks[i], err = markLog(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			for i, content := range []string{tc.diagnostic, tc.operator} {
				f, err := os.OpenFile(marks[i].path, os.O_APPEND|os.O_WRONLY, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString(content)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			drop, warn, err := oversizeEvidence(marks[0], marks[1], "$oversize")
			if err != nil || drop != tc.wantDrop || warn != tc.wantWarn {
				t.Fatalf("evidence: diagnostic=%v operator=%v error=%v", drop, warn, err)
			}
		})
	}
}

func TestLogEvidenceRejectsRotationAndTruncation(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "log")
		if err := os.WriteFile(path, []byte("previous output\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		mark, err := markLog(path)
		if err != nil {
			t.Fatal(err)
		}
		if rotate {
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := mark.read(); err == nil {
			t.Fatal("changed log accepted as fresh evidence")
		}
	}
}
