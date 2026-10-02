// Package rihma turns mautrix-go into a cgo-free, end-to-end-encrypted
// Matrix client with the operational discipline already solved: session
// login and restore, sealed secret storage, a pure-Go SQLite store,
// device verification, first-connect history discard, and bounded
// unable-to-decrypt reporting.
//
// rihma exposes mautrix types rather than wrapping them, and knows
// nothing about terva. Build it with CGO_ENABLED=0 and -tags goolm; a
// build without the tag fails on purpose.
package rihma
