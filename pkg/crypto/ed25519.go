package crypto

import (
	"bytes"
	"fmt"

	"filippo.io/edwards25519"
)

func validateEd25519Point(b []byte) error {
	if len(b) != 32 {
		panic("internal error")
	}
	var A edwards25519.Point
	if _, err := A.SetBytes(b); err != nil {
		return err
	}
	if !bytes.Equal(b, A.Bytes()) {
		return fmt.Errorf("non-canonical representation of public key")
	}
	if new(edwards25519.Point).MultByCofactor(&A).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return fmt.Errorf("invalid public key, low-order point")
	}
	// Allows points that are the sum of a point in the order-q
	// subgroup and one of the 7 non-identity low order points.
	// That appears to be harmless, and to reject such points, we
	// would need to check that q A is the identity point, which
	// is rather expensive.
	return nil
}

func validateEd25519PublicKey(key *PublicKey) error {
	return validateEd25519Point(key[:])
}

func validateEd25519Signature(sig *Signature) error {
	// First half of the signature represents R which should be a
	// valid point.
	return validateEd25519Point(sig[:32])
}
