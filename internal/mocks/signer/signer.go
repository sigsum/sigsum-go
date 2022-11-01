package signer

import (
	"sigsum.org/sigsum-go/pkg/crypto"
)

// Signer implements crypto.Signer with fixed outputs.  Use for tests only.
type Signer struct {
	PublicKey crypto.PublicKey
	Signature crypto.Signature
	Error     error
}

func (s *Signer) Public() crypto.PublicKey {
	return s.PublicKey
}

func (s *Signer) Sign(_ []byte) (crypto.Signature, error) {
	return s.Signature, s.Error
}
