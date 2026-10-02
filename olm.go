package rihma

import (
	"fmt"

	// Importing crypto runs its init, which registers an Olm backend:
	// goolm under -tags goolm, libolm (cgo) otherwise.
	_ "maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/olm"
)

// requireGoolm reports an error unless mautrix registered the pure-Go
// Olm backend. guard_nogoolm.go stops a build without the tag; this
// catches a binary that got past it some other way.
func requireGoolm() error {
	if olm.Driver != "goolm" {
		return fmt.Errorf("rihma: Olm backend is %q, want \"goolm\"; build with CGO_ENABLED=0 -tags goolm", olm.Driver)
	}
	return nil
}
