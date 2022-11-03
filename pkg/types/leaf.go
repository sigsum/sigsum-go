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

func LeavesToASCII(w io.Writer, leaves []Leaf) error {
	for _, leaf := range leaves {
		if err := ascii.WriteLineHex(w, "leaf",
			leaf.Checksum[:], leaf.Signature[:], leaf.KeyHash[:]); err != nil {
			return err
		}
	}
	return nil
}

func LeavesFromASCII(r io.Reader) ([]Leaf, error) {
	var leaves []Leaf
	p := ascii.NewParser(r)
	for {
		v, err := p.GetValues("leaf", 3)
		if err == io.EOF {
			if len(leaves) == 0 {
				return nil, fmt.Errorf("no leaves")
			}
			return leaves, nil
		}
		if err != nil {
			return nil, err
		}
		checksum, err := crypto.HashFromHex(v[0])
		if err != nil {
			return nil, fmt.Errorf("invalid leaf checksum: %v", err)
		}
		signature, err := crypto.SignatureFromHex(v[1])
		if err != nil {
			return nil, fmt.Errorf("invalid leaf signature: %v", err)
		}
		keyHash, err := crypto.HashFromHex(v[2])
		if err != nil {
			return nil, fmt.Errorf("invalid leaf key hash: %v", err)
		}
		leaves = append(leaves, Leaf{
			Checksum:  checksum,
			Signature: signature,
			KeyHash:   keyHash,
		})
	}
}
