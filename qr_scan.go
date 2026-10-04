package rihma

import (
	"context"
	"encoding/binary"
	"errors"

	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/id"
)

// Policy limits for the future QR controller. 2953 bytes is the largest QR
// binary payload (version 40, error correction L). Transaction IDs have a
// separate conservative admission limit; these are not Matrix protocol limits.
const (
	maxQRScanBytes        = 2953
	maxQRTransactionBytes = 256
	qrScanPrefixBytes     = 10
	qrScanKeyBytes        = 64
)

var (
	errInvalidQRScan = errors.New("rihma: invalid QR verification data")
	errQRScanFailed  = errors.New("rihma: QR verification scan failed")
)

type qrScanHandler interface {
	HandleScannedQRData(context.Context, []byte) error
}

// scanQR is a private admission boundary, not a public verification controller.
// Its caller must serialize commands and supply the current active transaction.
// Retain this preflight while mautrix v0.31.0's decoder uses uint16 additions:
// bounding only the buffer does not prevent a forged length from overflowing.
func scanQR(ctx context.Context, active id.VerificationTransactionID, data []byte, handler qrScanHandler) error {
	if len(active) == 0 || len(active) > maxQRTransactionBytes || len(data) > maxQRScanBytes || len(data) < qrScanPrefixBytes+qrScanKeyBytes+verificationhelper.MinQRSharedSecretLength {
		return errInvalidQRScan
	}
	// The caller must keep input stable throughout admission and helper use.
	// Upstream can retain the secret in its transaction store; buffer lifetime
	// belongs to the caller and future controller/store integration.
	if string(data[:6]) != "MATRIX" || data[6] != 2 || data[7] > 2 {
		return errInvalidQRScan
	}
	// Convert before adding, and check the remaining space before slicing.
	txnLen := int(binary.BigEndian.Uint16(data[8:10]))
	if txnLen == 0 || txnLen > maxQRTransactionBytes || txnLen > len(data)-qrScanPrefixBytes-qrScanKeyBytes-verificationhelper.MinQRSharedSecretLength {
		return errInvalidQRScan
	}
	if string(data[qrScanPrefixBytes:qrScanPrefixBytes+txnLen]) != string(active) {
		return errInvalidQRScan
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := handler.HandleScannedQRData(ctx, data); err != nil {
		return errQRScanFailed
	}
	return nil
}
