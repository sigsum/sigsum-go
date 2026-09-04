package crypto

import (
	"strings"

	"testing"
)

func TestValidateEd25519PublicKeyOk(t *testing.T) {
	pub, _, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateEd25519PublicKey(&pub); err != nil {
		t.Errorf("valid public key %x was rejected: %v", pub, err)
	}
}

func TestValidateEd25519PublicKeyNonCanonical(t *testing.T) {
	for _, hex := range []string{
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7F",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		// "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "f4ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "f4ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		// "f5ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "f5ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		// "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "f9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "f9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		// "faffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "faffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"fbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"fbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		// "feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// Low order point, in non-canonical serialization.
		// See https://eprint.iacr.org/2020/1244.pdf, table 6b.
		"0100000000000000000000000000000000000000000000000000000000000080",
	} {
		pub, err := PublicKeyFromHex(hex)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateEd25519PublicKey(&pub); err == nil {
			t.Errorf("non-canonical key %x was not rejected", pub)
		} else if !strings.Contains(err.Error(), "non-canonical") {
			t.Errorf("non-canonical key %x was rejected with unexpected error: %v", pub, err)
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
		pub, err := PublicKeyFromHex(hex)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateEd25519PublicKey(&pub); err == nil {
			t.Errorf("low-order key %x was not rejected", pub)
		} else if !strings.Contains(err.Error(), "low-order") {
			t.Errorf("low-order key %x was rejected with unexpected error: %v", pub, err)
		}
	}
}
