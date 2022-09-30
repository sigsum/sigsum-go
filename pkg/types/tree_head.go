package types

import (
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/merkle"
)

type TreeHead struct {
	Timestamp uint64      `ascii:"timestamp"`
	TreeSize  uint64      `ascii:"tree_size"`
	RootHash  merkle.Hash `ascii:"root_hash"`
}

type SignedTreeHead struct {
	TreeHead
	Signature Signature `ascii:"signature"`
}

type CosignedTreeHead struct {
	SignedTreeHead
	Cosignature []Signature   `ascii:"cosignature"`
	KeyHash     []merkle.Hash `ascii:"key_hash"`
}

func (th *TreeHead) ToBinary() []byte {
	b := make([]byte, 48)
	binary.BigEndian.PutUint64(b[0:8], th.Timestamp)
	binary.BigEndian.PutUint64(b[8:16], th.TreeSize)
	copy(b[16:48], th.RootHash[:])
	return b
}

func TreeHeadNamespace(keyHash *merkle.Hash) string {
	return fmt.Sprintf("tree_head:v0:%s@sigsum.org", hex.EncodeToString(keyHash[:]))
}

func (th *TreeHead) Sign(s crypto.Signer, kh *merkle.Hash) (*SignedTreeHead, error) {
	sig, err := s.Sign(nil,
		ssh.SignedData(TreeHeadNamespace(kh), th.ToBinary()),
		crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("types: failed signing tree head")
	}

	sth := &SignedTreeHead{
		TreeHead: *th,
	}
	copy(sth.Signature[:], sig)
	return sth, nil
}

func (th *TreeHead) Verify(key *PublicKey, signature *Signature, kh *merkle.Hash) bool {
	return ed25519.Verify(ed25519.PublicKey(key[:]),
		ssh.SignedData(TreeHeadNamespace(kh),
			sth.TreeHead.ToBinary()), signature[:])
}

func (th *TreeHead) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, th)
}

func (th *TreeHead) FromASCII(r io.Reader) error {
	return ascii.StdEncoding.Deserialize(r, th)
}

func (sth *SignedTreeHead) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, sth)
}

func (sth *SignedTreeHead) FromASCII(r io.Reader) error {
	return ascii.StdEncoding.Deserialize(r, sth)
}

func (sth *SignedTreeHead) Verify(key *PublicKey, kh *merkle.Hash) bool {
	return sth.TreeHead.Verify(key, &sth.Signature, kh)
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
