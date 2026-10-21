package rihma

import "github.com/rs/zerolog"

// signatureLogMessages are the mautrix log lines that carry a signature
// rihma makes or checks: SignUser, SignOwnMasterKey and SignOwnDevice at
// debug, and the self-signing check of every fetched device at trace.
// TestSignatureLogFilterCoversMautrix fails when mautrix logs a signature
// under a message missing here.
var signatureLogMessages = map[string]bool{
	"Signed master key of user with our user-signing key": true,
	"Signed own master key with own device key":           true,
	"Signed own device key with self-signing key":         true,
	"Verified self-signing signature":                     true,
}

// signatureLogFilter discards those lines before they are written. A hook
// cannot remove one field, so the whole line goes.
type signatureLogFilter struct{}

func (signatureLogFilter) Run(e *zerolog.Event, _ zerolog.Level, msg string) {
	if signatureLogMessages[msg] {
		e.Discard()
	}
}
