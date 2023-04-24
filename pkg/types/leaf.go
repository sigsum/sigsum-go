package types

import (
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
)

const (
	TreeLeafNamespace = "sigsum.org/v1/tree-leaf"
)

type Leaf struct {
	Checksum  crypto.Hash
	Signature crypto.Signature
	KeyHash   crypto.Hash
}

func leafSignedData(checksum *crypto.Hash) []byte {
	return crypto.AttachNamespace(TreeLeafNamespace, checksum[:])
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

func (l *Leaf) ToHash() crypto.Hash {
	return merkle.HashLeafNode(l.ToBinary())
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
	return ascii.WriteLine(w, "leaf",
		l.Checksum[:], l.Signature[:], l.KeyHash[:])
}

func LeavesToASCII(w io.Writer, leaves []Leaf) error {
	for _, leaf := range leaves {
		if err := leaf.ToASCII(w); err != nil {
			return err
		}
	}
	return nil
}

func (l *Leaf) Parse(p *ascii.Parser) error {
	v, err := p.GetValues("leaf", 3)
	if err != nil {
		return err
	}
	l.Checksum, err = crypto.HashFromHex(v[0])
	if err != nil {
		return fmt.Errorf("invalid leaf checksum: %v", err)
	}
	l.Signature, err = crypto.SignatureFromHex(v[1])
	if err != nil {
		return fmt.Errorf("invalid leaf signature: %v", err)
	}
	l.KeyHash, err = crypto.HashFromHex(v[2])
	if err != nil {
		return fmt.Errorf("invalid leaf key hash: %v", err)
	}
	return nil
}

func LeavesFromASCII(r io.Reader) ([]Leaf, error) {
	var leaves []Leaf
	p := ascii.NewParser(r)
	for {
		var leaf Leaf
		err := leaf.Parse(&p)
		if err == io.EOF {
			if len(leaves) == 0 {
				return nil, fmt.Errorf("no leaves")
			}
			return leaves, nil
		}
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, leaf)
	}
}
