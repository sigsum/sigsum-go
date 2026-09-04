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
	// TODO: Also check that q A is the identity, to ensure that A
	// belongs to the intended subgroup of order q?
	return nil
}
