package rihma

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRequireGoolm(t *testing.T) {
	if err := requireGoolm(); err != nil {
		t.Fatal(err)
	}
}

// TestBuildWithoutGoolmNamesTheTag builds the package without -tags
// goolm, with cgo off and on, and checks the failure names the tag.
func TestBuildWithoutGoolmNamesTheTag(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go command")
	}
	for _, cgo := range []string{"0", "1"} {
		t.Run("CGO_ENABLED="+cgo, func(t *testing.T) {
			cmd := exec.Command("go", "build", "-o", os.DevNull, ".")
			cmd.Env = append(os.Environ(), "CGO_ENABLED="+cgo, "GOFLAGS=")
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatal("build without -tags goolm succeeded")
			}
			if !strings.Contains(string(out), "buildwithtagsgoolm") {
				t.Fatalf("build error does not name the tag:\n%s", out)
			}
		})
	}
}
