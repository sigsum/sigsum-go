package types

import (
	stdcrypto "crypto"
	"encoding/binary"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
)

const (
	TreeHeadNamespace = "tree_head:v0@sigsum.org"
)

type TreeHead struct {
	Timestamp uint64      `ascii:"timestamp"`
	TreeSize  uint64      `ascii:"tree_size"`
	RootHash  crypto.Hash `ascii:"root_hash"`
}

type SignedTreeHead struct {
	TreeHead
	Signature crypto.Signature `ascii:"signature"`
}

type CosignedTreeHead struct {
	SignedTreeHead
	Cosignature []crypto.Signature `ascii:"cosignature"`
	KeyHash     []crypto.Hash      `ascii:"key_hash"`
}

func (th *TreeHead) toSignedData(keyHash *crypto.Hash) []byte {
	b := make([]byte, 80)
	binary.BigEndian.PutUint64(b[0:8], th.Timestamp)
	binary.BigEndian.PutUint64(b[8:16], th.TreeSize)
	copy(b[16:48], th.RootHash[:])
	copy(b[48:80], keyHash[:])
	return ssh.SignedData(TreeHeadNamespace, b)
}

func (th *TreeHead) Sign(s stdcrypto.Signer, kh *crypto.Hash) (*SignedTreeHead, error) {
	sig, err := crypto.Sign(s, th.toSignedData(kh))
	if err != nil {
		return nil, fmt.Errorf("types: failed signing tree head")
	}

	return &SignedTreeHead{
		TreeHead:  *th,
		Signature: sig,
	}, nil
}

func (th *TreeHead) Verify(key *crypto.PublicKey, signature *crypto.Signature, kh *crypto.Hash) bool {
	return crypto.Verify(key, th.toSignedData(kh), signature)
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

func (sth *SignedTreeHead) Verify(key *crypto.PublicKey) bool {
	keyHash := crypto.HashBytes(key[:])
	return sth.TreeHead.Verify(key, &sth.Signature, &keyHash)
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
