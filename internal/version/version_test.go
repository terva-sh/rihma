package version

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionMatchesManifest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "connector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Exec    string `json:"exec"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != Version {
		t.Errorf("connector.json version %q, internal/version %q", m.Version, Version)
	}
	if m.Name != "rihma" {
		t.Errorf("connector.json name %q, want rihma (decision 0002)", m.Name)
	}
}

// TestRunShIsExecutable checks the mode git tracks, which is what a
// clone gets, and the working tree's, which is what the host execs.
func TestRunShIsExecutable(t *testing.T) {
	root := filepath.Join("..", "..")
	info, err := os.Stat(filepath.Join(root, "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Error("run.sh is not executable in the working tree")
	}
	out, err := exec.Command("git", "-C", root, "ls-files", "-s", "run.sh").Output()
	if err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	if fields := strings.Fields(string(out)); len(fields) == 0 {
		t.Error("run.sh is not tracked by git")
	} else if fields[0] != "100755" {
		t.Errorf("git tracks run.sh as mode %s, want 100755", fields[0])
	}
}
