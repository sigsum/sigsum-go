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
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "f4ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "f5ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		// "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "f9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "faffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"fbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// "feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
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
		// The all-zero public key has order 4 and generates this subgroup.
		// TODO: There ought to be an order 8 point, but what is it?
		"0100000000000000000000000000000000000000000000000000000000000000", // Identity
		"0000000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000080",
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

// func TestEnumerateLowOrder(t *testing.T) {
// 	// One of the low-order points
// 	pub, err := PublicKeyFromHex("0000000000000000000000000000000000000000000000000000000000000000")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
//
// 	var G edwards25519.Point
// 	if _, err := G.SetBytes(pub[:]); err != nil {
// 		t.Fatal(err)
// 	}
// 	P := edwards25519.NewIdentityPoint()
// 	for i := 0; i < 10; i++ {
// 		t.Logf("%d: %x", i, P.Bytes())
// 		P.Add(P, &G)
// 	}
// }
