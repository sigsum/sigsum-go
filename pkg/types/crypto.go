package types

import (
	"crypto/ed25519"
	"crypto/sha256"
)

const (
	HashSize      = sha256.Size
	SignatureSize = ed25519.SignatureSize
	PublicKeySize = ed25519.PublicKeySize

	InteriorNodePrefix = byte(0x00)
	LeafNodePrefix     = byte(0x01)
)

type (
	Hash      [HashSize]byte
	Signature [SignatureSize]byte
	PublicKey [PublicKeySize]byte
)

func HashFn(buf []byte) *Hash {
	var hash Hash = sha256.Sum256(buf)
	return &hash
}

func LeafHash(buf []byte) *Hash {
	return HashFn(append([]byte{LeafNodePrefix}, buf...))
}
