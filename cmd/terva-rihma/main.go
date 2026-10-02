// Command terva-rihma is the rihma terva chat connector. terva runs it
// through connector.json and run.sh; the verbs are connsdk's (run, setup,
// status, reset, configured) plus verify.
package main

import (
	"fmt"
	"os"

	"terva.sh/terva/packages/agent/connsdk"

	"terva.sh/rihma/internal/connector"
)

func main() {
	// connsdk.Main knows only its own verbs, so verify is dispatched here
	// first (docs/connsdk-proposals.md). Main also reads the last argument.
	if len(os.Args) >= 2 && os.Args[len(os.Args)-1] == "verify" {
		if err := connector.Verify(); err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			os.Exit(1)
		}
		return
	}
	connsdk.Main(connector.Config())
}
