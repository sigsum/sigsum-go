package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func incBytes(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < len(b); i++ {
		b[i] = byte(i)
	}
	return b
}

func TestValidHashFromHex(t *testing.T) {
	b := incBytes(32)
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
	b := incBytes(33)
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

func mustHashFromHex(t *testing.T, s string) Hash {
	hash, err := HashFromHex(s)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

// Basic sanity check, not intended as thorough SHA256 regression test.
func TestHash(t *testing.T) {
	for _, table := range []struct {
		in  string
		out string
	}{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	} {
		want := mustHashFromHex(t, table.out)
		in := []byte(table.in)
		if got := HashBytes(in); got != want {
			t.Errorf("incorrect HashBytes of %q: got: %x, expected: %x",
				table.in, got, want)
		}
		if got, err := HashFile(bytes.NewBuffer(in)); err != nil || got != want {
			if err != nil {
				t.Fatal(err)
			}
			t.Errorf("incorrect HashFile of %q: got: %x, expected: %x",
				table.in, got, want)
		}
	}
}
