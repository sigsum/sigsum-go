package signer

import (
	"crypto"
	"crypto/ed25519"
	"io"
)

// Signer implements crypto.Signer with fixed outputs.  Use for tests only.
type Signer struct {
	PublicKey []byte
	Signature []byte
	Error     error
}

func (s *Signer) Public() crypto.PublicKey {
	return ed25519.PublicKey(s.PublicKey[:])
}

func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.Signature[:], s.Error
}
