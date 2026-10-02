// Command terva-rihma is the rihma terva chat connector. terva runs it
// through connector.json and run.sh; the verbs are connsdk's (run, setup,
// status, reset, configured) plus verify.
package main

import (
	"terva.sh/terva/packages/agent/connsdk"

	"terva.sh/rihma/internal/connector"
)

func main() {
	connsdk.Main(connector.Config())
}
