package rihma

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/id"
)

type qrScanProbe struct {
	calls  int
	parsed bool
	fail   bool
	secret []byte
}

func (p *qrScanProbe) HandleScannedQRData(_ context.Context, data []byte) error {
	p.calls++
	code, err := verificationhelper.NewQRCodeFromBytes(data)
	p.parsed = err == nil && code != nil
	if p.parsed {
		p.secret = code.SharedSecret
	}
	if p.fail {
		return errors.New("private upstream detail")
	}
	return err
}

func qrScanFixture(txn string, secretLen int) []byte {
	data := make([]byte, 10+len(txn)+64+secretLen)
	copy(data, "MATRIX")
	data[6] = 2
	data[7] = 1
	binary.BigEndian.PutUint16(data[8:10], uint16(len(txn)))
	copy(data[10:], txn)
	for i := 10 + len(txn); i < len(data); i++ {
		data[i] = 1
	}
	return data
}

func TestQRScanAdmission(t *testing.T) {
	valid := qrScanFixture("active", 8)
	cases := []struct {
		name   string
		active string
		data   []byte
		valid  bool
	}{
		{"minimum", "x", qrScanFixture("x", 8), true},
		{"maximum transaction", strings.Repeat("x", maxQRTransactionBytes), qrScanFixture(strings.Repeat("x", maxQRTransactionBytes), 8), true},
		{"maximum payload", "active", qrScanFixture("active", maxQRScanBytes-74-6), true},
		{"empty active", "", valid, false},
		{"wrong transaction", "other", valid, false},
		{"empty transaction", "active", qrScanFixture("", 8), false},
		{"transaction too long", strings.Repeat("x", 257), qrScanFixture(strings.Repeat("x", 257), 8), false},
		{"payload too long", "active", qrScanFixture("active", maxQRScanBytes-74-6+1), false},
		{"short secret", "active", qrScanFixture("active", 7), false},
	}
	for _, mode := range []byte{0, 2} {
		data := bytes.Clone(valid)
		data[7] = mode
		cases = append(cases, struct {
			name   string
			active string
			data   []byte
			valid  bool
		}{"valid mode", "active", data, true})
	}
	for _, length := range []uint16{257, 65462, 65503, 65525, 65535} {
		malformed := qrScanFixture("", 8)
		binary.BigEndian.PutUint16(malformed[8:10], length)
		cases = append(cases, struct {
			name   string
			active string
			data   []byte
			valid  bool
		}{"forged length", "active", malformed, false})
	}
	for _, offset := range []int{0, 6, 7} {
		malformed := bytes.Clone(valid)
		malformed[offset] = 255
		cases = append(cases, struct {
			name   string
			active string
			data   []byte
			valid  bool
		}{"bad format", "active", malformed, false})
	}
	for n := 0; n < len(valid); n++ {
		cases = append(cases, struct {
			name   string
			active string
			data   []byte
			valid  bool
		}{"truncated", "active", valid[:n], false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := bytes.Clone(tc.data)
			p := &qrScanProbe{}
			err := scanQR(context.Background(), id.VerificationTransactionID(tc.active), tc.data, p)
			if tc.valid {
				if err != nil || p.calls != 1 || !p.parsed {
					t.Fatal("valid scan rejected")
				}
			} else if err != errInvalidQRScan || p.calls != 0 {
				t.Fatal("invalid scan reached helper")
			}
			if tc.valid && !bytes.Equal(p.secret, bytes.Repeat([]byte{1}, len(p.secret))) {
				t.Fatal("retained protocol secret changed")
			}
			if !bytes.Equal(original, tc.data) {
				t.Fatal("caller input changed")
			}
		})
	}
}

func TestQRScanFailureAndCancellation(t *testing.T) {
	data := qrScanFixture("active", 8)
	p := &qrScanProbe{fail: true}
	if scanQR(context.Background(), "active", data, p) != errQRScanFailed {
		t.Fatal("upstream error escaped")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p = &qrScanProbe{}
	if scanQR(ctx, "active", data, p) != context.Canceled || p.calls != 0 {
		t.Fatal("cancelled scan reached helper")
	}
}

func FuzzQRScan(f *testing.F) {
	f.Add(qrScanFixture("active", 8), "active")
	for _, length := range []uint16{0, 256, 257, 65462, 65503, 65525, 65535} {
		data := qrScanFixture("", 8)
		binary.BigEndian.PutUint16(data[8:10], length)
		f.Add(data, "active")
	}
	f.Fuzz(func(t *testing.T, data []byte, active string) {
		p := &qrScanProbe{}
		err := scanQR(context.Background(), id.VerificationTransactionID(active), data, p)
		if err != nil && (err != errInvalidQRScan || p.calls != 0) {
			t.Fatal("invalid scan reached helper")
		}
		if err == nil && (p.calls != 1 || !p.parsed || string(data[10:10+int(binary.BigEndian.Uint16(data[8:10]))]) != active) {
			t.Fatal("unbound scan accepted")
		}
	})
}
