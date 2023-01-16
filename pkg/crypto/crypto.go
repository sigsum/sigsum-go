// package crypto provides lowest-level crypto types and primitives used by sigsum
package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	HashSize       = sha256.Size
	SignatureSize  = ed25519.SignatureSize
	PublicKeySize  = ed25519.PublicKeySize
	PrivateKeySize = ed25519.SeedSize
)

type (
	Hash       [HashSize]byte
	Signature  [SignatureSize]byte
	PublicKey  [PublicKeySize]byte
	PrivateKey [PrivateKeySize]byte
)

type Signer interface {
	Sign([]byte) (Signature, error)
	Public() PublicKey
}

func HashBytes(b []byte) Hash {
	return sha256.Sum256(b)
}

func HashFile(f io.Reader) (digest Hash, err error) {
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return
	}
	copy(digest[:], h.Sum(nil))
	return
}

func Verify(pub *PublicKey, msg []byte, sig *Signature) bool {
	return ed25519.Verify(ed25519.PublicKey(pub[:]), msg, sig[:])
}

type Ed25519Signer struct {
	secret ed25519.PrivateKey
}

func NewEd25519Signer(key *PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{secret: ed25519.NewKeyFromSeed((*key)[:])}
}

func (s *Ed25519Signer) Sign(msg []byte) (Signature, error) {
	sig, err := s.secret.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		return Signature{}, err
	}
	if len(sig) != SignatureSize {
		return Signature{}, fmt.Errorf("internal error, unexpected signature size %d: ", len(sig))
	}
	var ret Signature
	copy(ret[:], sig)
	return ret, nil
}

func (s *Ed25519Signer) Public() (ret PublicKey) {
	copy(ret[:], s.secret.Public().(ed25519.PublicKey))
	return
}

func (s *Ed25519Signer) Private() (ret PrivateKey) {
	copy(ret[:], s.secret.Seed())
	return
}

func NewKeyPair() (PublicKey, *Ed25519Signer, error) {
	var secret PrivateKey
	n, err := rand.Read(secret[:])
	if err != nil {
		return PublicKey{}, nil, err
	}
	if n != PrivateKeySize {
		return PublicKey{}, nil, fmt.Errorf("key generation failed, got only %d out of %d random bytes",
			n, PrivateKeySize)
	}
	signer := NewEd25519Signer(&secret)
	return signer.Public(), signer, nil
}

func decodeHex(out []byte, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != len(out) {
		return fmt.Errorf("unexpected length of hex data, expected %d, got %d", len(out), len(b))
	}
	copy(out, b)
	return nil
}

func HashFromHex(s string) (h Hash, err error) {
	err = decodeHex(h[:], s)
	return
}

func PublicKeyFromHex(s string) (pub PublicKey, err error) {
	err = decodeHex(pub[:], s)
	return
}

func SignatureFromHex(s string) (sig Signature, err error) {
	err = decodeHex(sig[:], s)
	return
}

func SignerFromHex(s string) (*Ed25519Signer, error) {
	var secret PrivateKey
	err := decodeHex(secret[:], s)
	if err != nil {
		return nil, err
	}
	return NewEd25519Signer(&secret), nil
}
