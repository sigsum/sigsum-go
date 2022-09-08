package types

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"sigsum.org/sigsum-go/pkg/merkle"
)

func newKeyPair(t *testing.T) (crypto.Signer, PublicKey) {
	vk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var pub PublicKey
	copy(pub[:], vk[:])
	return sk, pub
}

func newHashBufferInc(t *testing.T) *merkle.Hash {
	t.Helper()

	var buf merkle.Hash
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
