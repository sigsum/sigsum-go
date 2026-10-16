package crypto

import (
	"strings"

	"testing"
)

func TestValidateEd25519PublicKeyOk(t *testing.T) {
	pub, _, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEd25519PublicKey(&pub); err != nil {
		t.Errorf("valid public key %x was rejected: %v", pub, err)
	}
}

func TestValidateEd25519PublicKeyNonCanonical(t *testing.T) {
	for _, in := range []struct {
		valid bool // Valid encoding to edwards25519
		hex   string
	}{
		{true, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "f4ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "f4ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "f5ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "f5ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "f9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "f9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "faffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "faffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "fbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "fbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		// Low order point, in non-canonical serialization.
		// See https://eprint.iacr.org/2020/1244.pdf, table 6b.
		{true, "0100000000000000000000000000000000000000000000000000000000000080"},
	} {
		pub, err := Ed25519PublicKeyFromHex(in.hex)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateEd25519PublicKey(&pub); err == nil {
			t.Errorf("non-canonical key %x was not rejected", pub)
		} else if in.valid {
			if !strings.Contains(err.Error(), "non-canonical") {
				t.Errorf("non-canonical key %x was rejected with unexpected error: %v", pub, err)
			}
		} else if !strings.Contains(err.Error(), "invalid point") {
			t.Errorf("invalid key %x was rejected with unexpected error: %v", pub, err)
		}
	}
}

func TestValidateEd25519PublicKeyLowOrder(t *testing.T) {
	for _, hex := range []string{
		// List from https://eprint.iacr.org/2020/1244.pdf, table 6b.
		"0100000000000000000000000000000000000000000000000000000000000000", // Identity
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // Order 2
		"0000000000000000000000000000000000000000000000000000000000000080", // Order 4
		"0000000000000000000000000000000000000000000000000000000000000000", // Order 4
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // Order 8
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // Order 8
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // Order 8
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // Order 8
	} {
		pub, err := Ed25519PublicKeyFromHex(hex)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateEd25519PublicKey(&pub); err == nil {
			t.Errorf("low-order key %x was not rejected", pub)
		} else if !strings.Contains(err.Error(), "low-order") {
			t.Errorf("low-order key %x was rejected with unexpected error: %v", pub, err)
		}
	}
}
