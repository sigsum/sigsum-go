package crypto

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"filippo.io/edwards25519"
)

const (
	Ed25519SignatureSize  = ed25519.SignatureSize
	Ed25519PublicKeySize  = ed25519.PublicKeySize
	Ed25519PrivateKeySize = ed25519.SeedSize
)

type Ed25519PublicKey [Ed25519PublicKeySize]byte
type Ed25519PrivateKey [Ed25519PrivateKeySize]byte
type Ed25519Signature [Ed25519SignatureSize]byte

func (k *Ed25519PublicKey) Hash() Hash {
	return HashBytes((*k)[:])
}

// Rejecting public keys representing low-order points helps prevent
// log poisoning. According to RFC 8032, a signature {R, S} is valid if
//
//	[S]B = R + k A'
//
// where A' is the public key and
//
//	k = SHA512(dom2(F, C) || R || A || PH(M))
//
// In a log-poisoning attack, all of R, S and A are directly
// controlled by the attacker, while M is essentially a hash of an
// attacker-controlled value. If A' is of low order, the attacker can
// choose S freely and pick one of the few possible values for k A'
// (e.g., k A' = 0). The attacker can then compute a matching R, and
// finally try a few different messages until one is found that
// results in the right value of k A'.
func (k *Ed25519PublicKey) Verify(msg []byte, sig Signature) bool {
	// These validation criteria are intended to be consistent
	// with ed25519-dalek's verify_strict(). See
	// https://github.com/C2SP/CCTV/tree/main/ed25519.
	if len(sig) == 0 {
		panic("bad call")
	}
	return len(sig) == Ed25519SignatureSize &&
		validateEd25519PublicKey(k) == nil &&
		validateEd25519Signature(sig) == nil &&
		ed25519.Verify(ed25519.PublicKey(k[:]), msg, sig)
}

func (k *Ed25519PublicKey) Bytes() []byte {
	return append([]byte{}, (*k)[:]...) // Make a copy
}

func (k *Ed25519PublicKey) Equal(other PublicKey) bool {
	o, ok := other.(*Ed25519PublicKey)
	return ok && *k == *o
}

func Ed25519PublicKeyFromHex(s string) (*Ed25519PublicKey, error) {
	var pub Ed25519PublicKey
	if err := decodeHex(pub[:], s); err != nil {
		return nil, err
	}
	return &pub, nil
}

type Ed25519Signer struct {
	secret ed25519.PrivateKey
}

func NewEd25519Signer(key *Ed25519PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{secret: ed25519.NewKeyFromSeed((*key)[:])}
}

func (s *Ed25519Signer) Sign(msg []byte) (Signature, error) {
	sig, err := s.secret.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		return Signature{}, err
	}
	if len(sig) != Ed25519SignatureSize {
		return Signature{}, fmt.Errorf("internal error, unexpected signature size %d: ", len(sig))
	}
	return sig, nil
}

func (s *Ed25519Signer) Public() PublicKey {
	var pub Ed25519PublicKey
	copy(pub[:], s.secret.Public().(ed25519.PublicKey))
	return &pub
}

func (s *Ed25519Signer) Private() Ed25519PrivateKey {
	var key Ed25519PrivateKey
	copy(key[:], s.secret.Seed())
	return key
}

func NewEd25519KeyPair() (*Ed25519PublicKey, *Ed25519Signer, error) {
	var secret Ed25519PrivateKey
	n, err := rand.Read(secret[:])
	if err != nil {
		return nil, nil, err
	}
	if n != Ed25519PrivateKeySize {
		return nil, nil, fmt.Errorf("key generation failed, got only %d out of %d random bytes",
			n, Ed25519PrivateKeySize)
	}
	signer := NewEd25519Signer(&secret)
	return signer.Public().(*Ed25519PublicKey), signer, nil
}

func Ed25519SignerFromHex(s string) (*Ed25519Signer, error) {
	var secret Ed25519PrivateKey
	if err := decodeHex(secret[:], s); err != nil {
		return nil, err
	}
	return NewEd25519Signer(&secret), nil
}

func Ed25519SignatureFromHex(s string) (Signature, error) {
	var sig Ed25519Signature
	if err := decodeHex(sig[:], s); err != nil {
		return nil, err
	}
	return sig[:], nil
}

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

func validateEd25519PublicKey(key *Ed25519PublicKey) error {
	return validateEd25519Point(key[:])
}

func validateEd25519Signature(sig Signature) error {
	// First half of the signature represents R which should be a
	// valid point.
	return validateEd25519Point(sig[:32])
}
