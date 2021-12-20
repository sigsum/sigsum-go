package types

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
)

type testSigner struct {
	PublicKey PublicKey
	Signature Signature
	Error     error
}

func (ts *testSigner) Public() crypto.PublicKey {
	return ed25519.PublicKey(ts.PublicKey[:])
}

func (ts *testSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ts.Signature[:], ts.Error
}

func newKeyPair(t *testing.T) (crypto.Signer, PublicKey) {
	vk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var pub PublicKey
	copy(pub[:], vk[:])
	return sk, pub
}

func newHashBufferInc(t *testing.T) *Hash {
	t.Helper()

	var buf Hash
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}
	return &buf
}

func newSigBufferInc(t *testing.T) *Signature {
	t.Helper()

	var buf Signature
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}
	return &buf
}

func newPubBufferInc(t *testing.T) *PublicKey {
	t.Helper()

	var buf PublicKey
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}
	return &buf
}
