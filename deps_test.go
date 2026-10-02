package rihma

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestRootPackageKnowsNothingOfTerva enforces the dependency rule: the
// library never imports terva, so programs outside terva can use it and
// terva's graph stays out of theirs. Only internal/connector may.
func TestRootPackageKnowsNothingOfTerva(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go command")
	}
	cmd := exec.Command("go", "list", "-deps", "-tags", "goolm", ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, pkg := range strings.Fields(string(out)) {
		if pkg == "terva.sh/terva" || strings.HasPrefix(pkg, "terva.sh/terva/") {
			t.Errorf("root package depends on %s", pkg)
		}
	}
}
