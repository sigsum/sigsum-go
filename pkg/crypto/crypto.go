// package crypto provides lowest-level crypto types and primitives used by sigsum
package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	HashSize      = sha256.Size
	SignatureSize = ed25519.SignatureSize
	PublicKeySize = ed25519.PublicKeySize
)

type (
	Hash      [HashSize]byte
	Signature [SignatureSize]byte
	PublicKey [PublicKeySize]byte
)

func HashBytes(b []byte) Hash {
	return sha256.Sum256(b)
}

func Verify(pub *PublicKey, msg []byte, sig *Signature) bool {
	return ed25519.Verify(ed25519.PublicKey(pub[:]), msg, sig[:])
}

func Sign(priv crypto.Signer, msg []byte) (Signature, error) {
	var ret Signature
	if _, ok := priv.Public().(ed25519.PublicKey); !ok {
		return ret, fmt.Errorf("internal error, unexpected signer type %T: ", priv.Public())
	}
	s, err := priv.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		return ret, err
	}
	if len(s) != SignatureSize {
		return ret, fmt.Errorf("internal error, unexpected signature size %d: ", len(s))
	}
	copy(ret[:], s[:])
	return ret, nil
}

func decodeHex(s string, size int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, fmt.Errorf("unexpected length of hex data, expected %d, got %d", size, len(b))
	}
	return b, nil
}

func HashFromHex(s string) (h Hash, err error) {
	var b []byte
	b, err = decodeHex(s, HashSize)
	copy(h[:], b)
	return
}

func PublicKeyFromHex(s string) (pub PublicKey, err error) {
	var b []byte
	b, err = decodeHex(s, PublicKeySize)
	copy(pub[:], b)
	return
}

func SignatureFromHex(s string) (sig Signature, err error) {
	var b []byte
	b, err = decodeHex(s, SignatureSize)
	copy(sig[:], b)
	return
}
