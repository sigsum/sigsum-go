package crypto

import (
	"bytes"
	"fmt"

	"filippo.io/edwards25519"
)

func ValidateEd25519PublicKey(key *PublicKey) error {
	var A, P edwards25519.Point
	if _, err := A.SetBytes(key[:]); err != nil {
		return err
	}
	if !bytes.Equal(key[:], A.Bytes()) {
		return fmt.Errorf("non-canonical representation of public key")
	}
	if P.MultByCofactor(&A).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return fmt.Errorf("invalid public key, low-order point")
	}
	// Allows points that are the sum of a point in the order-q
	// subgroup and one of the 7 non-identity low order points.
	// That appears to be harmless, and to reject such points, we
	// would need to check that q A is the identity point, which
	// is rather expensive.
	return nil
}
