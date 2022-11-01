package ascii

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func TestValidIntFromDecimal(t *testing.T) {
	for _, table := range []struct {
		in   string
		want uint64
	}{
		{"0", 0},
		{"1", 1},
		{"0123456789", 123456789},
		{"9223372036854775807", (1 << 63) - 1},
	} {
		x, err := IntFromDecimal(table.in)
		if err != nil {
			t.Errorf("error on valid input %q: %v", table.in, err)
		}
		if x != table.want {
			t.Errorf("failed on %q, wanted %d, got %d",
				table.in, table.want, x)
		}
	}
}

func TestInvalidIntFromDecimal(t *testing.T) {
	for _, in := range []string{
		"",
		"-1",
		"+9",
		"0123456789x",
		"9223372036854775808",
		"99223372036854775808",
	} {
		x, err := IntFromDecimal(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %d",
				in, x)
		}
	}
}

func incBytes(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = byte(i)
	}
}

func newIncBytes(n int) []byte {
	b := make([]byte, n)
	incBytes(b)
	return b
}

func incHash() (h crypto.Hash) {
	incBytes(h[:])
	return
}

func incSignature() (s crypto.Signature) {
	incBytes(s[:])
	return
}

func TestValidHashFromHex(t *testing.T) {
	b := newIncBytes(32)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		s, strings.ToUpper(s),
	} {
		hash, err := HashFromHex(in)
		if err != nil {
			t.Errorf("error on input %q: %v", in, err)
		}
		if !bytes.Equal(b, hash[:]) {
			t.Errorf("fail on input %q, wanted %x, got %x", in, b, hash)
		}
	}
}

func TestInvalidHashFromHex(t *testing.T) {
	b := newIncBytes(33)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		"", "0x11", "123z", s[:63], s[:65], s[:66],
	} {
		hash, err := HashFromHex(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %x",
				in, hash)
		}
	}
}

func TestValidPublicKeyFromHex(t *testing.T) {
	b := newIncBytes(32)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		s, strings.ToUpper(s),
	} {
		hash, err := PublicKeyFromHex(in)
		if err != nil {
			t.Errorf("error on input %q: %v", in, err)
		}
		if !bytes.Equal(b, hash[:]) {
			t.Errorf("fail on input %q, wanted %x, got %x", in, b, hash)
		}
	}
}

func TestInvalidPublicKeyFromHex(t *testing.T) {
	b := newIncBytes(33)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		"", "0x11", "123z", s[:63], s[:65], s[:66],
	} {
		hash, err := PublicKeyFromHex(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %x",
				in, hash)
		}
	}
}

func TestValidSignatureFromHex(t *testing.T) {
	b := newIncBytes(64)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		s, strings.ToUpper(s),
	} {
		hash, err := SignatureFromHex(in)
		if err != nil {
			t.Errorf("error on input %q: %v", in, err)
		}
		if !bytes.Equal(b, hash[:]) {
			t.Errorf("fail on input %q, wanted %x, got %x", in, b, hash)
		}
	}
}

func TestInvalidSignatureFromHex(t *testing.T) {
	b := newIncBytes(65)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		"", "0x11", "123z", s[:127], s[:129], s[:130],
	} {
		hash, err := SignatureFromHex(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %x",
				in, hash)
		}
	}
}
