package crypto

import (
	"crypto/mldsa"
	"fmt"
)

const (
	MLDSA44SignatureSize  = mldsa.MLDSA44SignatureSize
	MLDSA44PublicKeySize  = mldsa.MLDSA44PublicKeySize
	MLDSA44PrivateKeySize = mldsa.PrivateKeySize
)

type MLDSA44PublicKey [MLDSA44PublicKeySize]byte
type MLDSA44PrivateKey [MLDSA44PrivateKeySize]byte
type MLDSA44Signature [MLDSA44SignatureSize]byte

func (k MLDSA44PublicKey) Hash() Hash {
	return HashBytes(k[:])
}

func (k MLDSA44PublicKey) Verify(msg []byte, sig *MLDSA44Signature) bool {
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA44(), k[:])
	if err != nil {
		return false
	}
	return mldsa.Verify(pub, msg, sig[:], nil) == nil
}

type MLDSA44Signer struct {
	secret *mldsa.PrivateKey
}

func NewMLDSA44Signer(key *MLDSA44PrivateKey) *MLDSA44Signer {
	secret, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), (*key)[:])
	if err != nil {
		panic(fmt.Sprintf("failed to create MLDSA44 private key: %v", err))
	}
	return &MLDSA44Signer{secret: secret}
}

func (s *MLDSA44Signer) Sign(msg []byte) (MLDSA44Signature, error) {
	// TODO: Use SignDeterministic? Is there any actual difference?
	sig, err := s.secret.Sign(nil, msg, nil)
	if err != nil {
		return MLDSA44Signature{}, err
	}
	if len(sig) != MLDSA44SignatureSize {
		return MLDSA44Signature{}, fmt.Errorf("internal error, unexpected signature size %d: ", len(sig))
	}
	var ret MLDSA44Signature
	copy(ret[:], sig)
	return ret, nil
}

func (s *MLDSA44Signer) Public() (ret MLDSA44PublicKey) {
	pub := s.secret.Public().(*mldsa.PublicKey)
	copy(ret[:], pub.Bytes())
	return
}

func (s *MLDSA44Signer) Private() (ret MLDSA44PrivateKey) {
	copy(ret[:], s.secret.Bytes())
	return
}

func NewMLDSA44KeyPair() (MLDSA44PublicKey, *MLDSA44Signer, error) {
	secret, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return MLDSA44PublicKey{}, nil, err
	}
	signer := &MLDSA44Signer{secret}
	return signer.Public(), signer, nil
}

func MLDSA44PublicKeyFromHex(s string) (pub MLDSA44PublicKey, err error) {
	err = decodeHex(pub[:], s)
	return
}

func MLDSA44SignatureFromHex(s string) (sig MLDSA44Signature, err error) {
	err = decodeHex(sig[:], s)
	return
}

func MLDSA44SignerFromHex(s string) (*MLDSA44Signer, error) {
	var secret MLDSA44PrivateKey
	err := decodeHex(secret[:], s)
	if err != nil {
		return nil, err
	}
	return NewMLDSA44Signer(&secret), nil
}
