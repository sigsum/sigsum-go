package types

import (
	"crypto/ed25519"
)

const (
	SignatureSize = ed25519.SignatureSize
	PublicKeySize = ed25519.PublicKeySize
)

type (
	Signature [SignatureSize]byte
	PublicKey [PublicKeySize]byte
)
