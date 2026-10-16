// package crypto provides lowest-level crypto types and primitives used by sigsum
package crypto

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	HashSize              = sha256.Size
	Ed25519SignatureSize  = ed25519.SignatureSize
	Ed25519PublicKeySize  = ed25519.PublicKeySize
	Ed25519PrivateKeySize = ed25519.SeedSize
)

type (
	Hash              [HashSize]byte
	Ed25519Signature  [Ed25519SignatureSize]byte
	Ed25519PublicKey  [Ed25519PublicKeySize]byte
	Ed25519PrivateKey [Ed25519PrivateKeySize]byte
)

type Signer interface {
	Sign([]byte) (Ed25519Signature, error)
	Public() Ed25519PublicKey
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

func (k Ed25519PublicKey) Hash() Hash {
	return HashBytes(k[:])
}

// Rejecting public keys representing low-order points helps prevent
// log poisoning. According to RFC 8032, a signature {R, S} is valid if
//
//   [S]B = R + k A'
//
// where A' is the public key and
//
//   k = SHA512(dom2(F, C) || R || A || PH(M))
//
// In a log-poisoning attack, all of R, S and A are directly
// controlled by the attacker, while M is essentially a hash of an
// attacker-controlled value. If A' is of low order, the attacker can
// choose S freely and pick one of the few possible values for k A'
// (e.g., k A' = 0). The attacker can then compute a matching R, and
// finally try a few different messages until one is found that
// results in the right value of k A'.
func (k Ed25519PublicKey) Verify(msg []byte, sig *Ed25519Signature) bool {
	// These validation criteria are intended to be consistent
	// with ed25519-dalek's verify_strict(). See
	// https://github.com/C2SP/CCTV/tree/main/ed25519.
	return validateEd25519PublicKey(&k) == nil &&
		validateEd25519Signature(sig) == nil &&
		ed25519.Verify(ed25519.PublicKey(k[:]), msg, sig[:])
}

type Ed25519Signer struct {
	secret ed25519.PrivateKey
}

func NewEd25519Signer(key *Ed25519PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{secret: ed25519.NewKeyFromSeed((*key)[:])}
}

func (s *Ed25519Signer) Sign(msg []byte) (Ed25519Signature, error) {
	sig, err := s.secret.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		return Ed25519Signature{}, err
	}
	if len(sig) != Ed25519SignatureSize {
		return Ed25519Signature{}, fmt.Errorf("internal error, unexpected signature size %d: ", len(sig))
	}
	var ret Ed25519Signature
	copy(ret[:], sig)
	return ret, nil
}

func (s *Ed25519Signer) Public() (ret Ed25519PublicKey) {
	copy(ret[:], s.secret.Public().(ed25519.PublicKey))
	return
}

func (s *Ed25519Signer) Private() (ret Ed25519PrivateKey) {
	copy(ret[:], s.secret.Seed())
	return
}

func NewEd25519KeyPair() (Ed25519PublicKey, *Ed25519Signer, error) {
	var secret Ed25519PrivateKey
	n, err := rand.Read(secret[:])
	if err != nil {
		return Ed25519PublicKey{}, nil, err
	}
	if n != Ed25519PrivateKeySize {
		return Ed25519PublicKey{}, nil, fmt.Errorf("key generation failed, got only %d out of %d random bytes",
			n, Ed25519PrivateKeySize)
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

func Ed25519PublicKeyFromHex(s string) (pub Ed25519PublicKey, err error) {
	err = decodeHex(pub[:], s)
	return
}

func Ed25519SignatureFromHex(s string) (sig Ed25519Signature, err error) {
	err = decodeHex(sig[:], s)
	return
}

func Ed25519SignerFromHex(s string) (*Ed25519Signer, error) {
	var secret Ed25519PrivateKey
	err := decodeHex(secret[:], s)
	if err != nil {
		return nil, err
	}
	return NewEd25519Signer(&secret), nil
}

func decodeBase64(out []byte, s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != len(out) {
		return fmt.Errorf("unexpected length of base data, expected %d, got %d", len(out), len(b))
	}
	copy(out, b)
	return nil
}

func HashFromBase64(s string) (h Hash, err error) {
	err = decodeBase64(h[:], s)
	return
}

func AttachNamespace(namespace string, msg []byte) []byte {
	return bytes.Join([][]byte{[]byte(namespace), msg}, []byte{0})
}
