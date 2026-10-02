//go:build goolm

// Package buildwithtagsgoolm exists only to be unbuildable without
// -tags goolm. guard_nogoolm.go imports it in builds that lack the tag,
// so the build fails naming this directory. Nothing imports it
// otherwise.
package buildwithtagsgoolm
