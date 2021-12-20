package types

import (
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"

	"git.sigsum.org/sigsum-lib-go/pkg/ascii"
)

type TreeHead struct {
	Timestamp uint64 `ascii:"timestamp"`
	TreeSize  uint64 `ascii:"tree_size"`
	RootHash  Hash   `ascii:"root_hash"`
}

type SignedTreeHead struct {
	TreeHead
	Signature Signature `ascii:"signature"`
}

type CosignedTreeHead struct {
	SignedTreeHead
	Cosignature []Signature `ascii:"cosignature"`
	KeyHash     []Hash      `ascii:"key_hash"`
}

func (th *TreeHead) ToBinary(keyHash *Hash) []byte {
	b := make([]byte, 80)
	binary.BigEndian.PutUint64(b[0:8], th.Timestamp)
	binary.BigEndian.PutUint64(b[8:16], th.TreeSize)
	copy(b[16:48], th.RootHash[:])
	copy(b[48:80], keyHash[:])
	return b
}

func (th *TreeHead) Sign(s crypto.Signer, ctx *Hash) (*SignedTreeHead, error) {
	sig, err := s.Sign(nil, th.ToBinary(ctx), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("types: failed signing tree head")
	}

	sth := &SignedTreeHead{
		TreeHead: *th,
	}
	copy(sth.Signature[:], sig)
	return sth, nil
}

func (sth *SignedTreeHead) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, sth)
}

func (sth *SignedTreeHead) FromASCII(r io.Reader) error {
	return ascii.StdEncoding.Deserialize(r, sth)
}

func (sth *SignedTreeHead) Verify(key *PublicKey, ctx *Hash) bool {
	return ed25519.Verify(ed25519.PublicKey(key[:]), sth.TreeHead.ToBinary(ctx), sth.Signature[:])
}

func (cth *CosignedTreeHead) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, cth)
}

func (cth *CosignedTreeHead) FromASCII(r io.Reader) error {
	if err := ascii.StdEncoding.Deserialize(r, cth); err != nil {
		return err
	}
	if len(cth.Cosignature) != len(cth.KeyHash) {
		return fmt.Errorf("types: mismatched cosignature count")
	}
	return nil
}
