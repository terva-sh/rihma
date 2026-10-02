//go:build !goolm

package rihma

// rihma must be built with -tags goolm, which makes mautrix use its
// pure-Go Olm backend instead of cgo libolm. This import fails at load
// time with "build constraints exclude all Go files in
// .../internal/buildwithtagsgoolm", so the build output names the fix.
// With cgo on it is the only error, including where libolm is installed
// and the build would otherwise succeed on it. With cgo off Go also
// reports mautrix's own libolm error, sorted ahead of this one.
import _ "terva.sh/rihma/internal/buildwithtagsgoolm"
