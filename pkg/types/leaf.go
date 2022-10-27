package types

import (
	"fmt"
	"io"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
)

const (
	TreeLeafNamespace = "tree_leaf:v0@sigsum.org"
)

type Leaf struct {
	Checksum  crypto.Hash
	Signature crypto.Signature
	KeyHash   crypto.Hash
}

type Leaves []Leaf

func leafSignedData(checksum *crypto.Hash) []byte {
	return ssh.SignedDataFromHash(TreeLeafNamespace, *checksum)
}

func SignLeafChecksum(signer crypto.Signer, checksum *crypto.Hash) (crypto.Signature, error) {
	return signer.Sign(leafSignedData(checksum))
}

func VerifyLeafChecksum(key *crypto.PublicKey, checksum *crypto.Hash, sig *crypto.Signature) bool {
	return crypto.Verify(key, leafSignedData(checksum), sig)
}

func SignLeafMessage(signer crypto.Signer, msg []byte) (crypto.Signature, error) {
	checksum := crypto.HashBytes(msg)
	return SignLeafChecksum(signer, &checksum)
}

func VerifyLeafMessage(key *crypto.PublicKey, msg []byte, sig *crypto.Signature) bool {
	checksum := crypto.HashBytes(msg)
	return VerifyLeafChecksum(key, &checksum, sig)
}

func (l *Leaf) Verify(key *crypto.PublicKey) bool {
	if l.KeyHash != crypto.HashBytes(key[:]) {
		return false
	}
	return VerifyLeafChecksum(key, &l.Checksum, &l.Signature)
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
	return fmt.Errorf("not implemented") // XXX ascii.StdEncoding.Serialize(w, l)
}

func (l *Leaves) FromASCII(r io.Reader) error {
	leaves := &struct {
		Checksum  []crypto.Hash      `ascii:"checksum"`
		Signature []crypto.Signature `ascii:"signature"`
		KeyHash   []crypto.Hash      `ascii:"key_hash"`
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
