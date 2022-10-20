package types

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/merkle"
)

const (
	TreeLeafNamespace = "tree_leaf:v0@sigsum.org"
)

type Leaf struct {
	Checksum  merkle.Hash `ascii:"checksum"`
	Signature Signature   `ascii:"signature"`
	KeyHash   merkle.Hash `ascii:"key_hash"`
}

type Leaves []Leaf

func leafSignedData(checksum *merkle.Hash) []byte {
	return ssh.SignedDataFromHash(TreeLeafNamespace, *checksum)
}

func SignLeafChecksum(signer crypto.Signer, checksum *merkle.Hash) (*Signature, error) {
	sig, err := signer.Sign(nil, leafSignedData(checksum), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("types: failed signing statement")
	}

	var signature Signature
	copy(signature[:], sig)
	return &signature, nil
}

func (l *Leaf) Verify(key *PublicKey) bool {
	if l.KeyHash != *merkle.HashFn(key[:]) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(key[:]),
		leafSignedData(&l.Checksum), l.Signature[:])
}

func (l *Leaf) ToBinary() []byte {
	b := make([]byte, 128)
	copy(b[:32], l.Checksum[:])
	copy(b[32:96], l.Signature[:])
	copy(b[96:], l.KeyHash[:])
	return b
}

func (l *Leaf) FromBinary(b []byte) error {
	if len(b) != 128 {
		return fmt.Errorf("types: invalid leaf size: %d", len(b))
	}

	copy(l.Checksum[:], b[:32])
	copy(l.Signature[:], b[32:96])
	copy(l.KeyHash[:], b[96:])
	return nil
}

func (l *Leaf) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, l)
}

func (l *Leaf) FromASCII(r io.Reader) error {
	return ascii.StdEncoding.Deserialize(r, l)
}

func (l *Leaves) FromASCII(r io.Reader) error {
	leaves := &struct {
		Checksum  []merkle.Hash `ascii:"checksum"`
		Signature []Signature   `ascii:"signature"`
		KeyHash   []merkle.Hash `ascii:"key_hash"`
	}{}

	if err := ascii.StdEncoding.Deserialize(r, leaves); err != nil {
		return err
	}
	n := len(leaves.Checksum)
	if n != len(leaves.Signature) {
		return fmt.Errorf("types: mismatched leaf field counts")
	}
	if n != len(leaves.KeyHash) {
		return fmt.Errorf("types: mismatched leaf field counts")
	}

	*l = make([]Leaf, 0, n)
	for i := 0; i < n; i++ {
		*l = append(*l, Leaf{
			Checksum:  leaves.Checksum[i],
			Signature: leaves.Signature[i],
			KeyHash:   leaves.KeyHash[i],
		})
	}
	return nil
}
