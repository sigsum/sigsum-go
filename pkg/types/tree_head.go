package types

import (
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"

	"git.sigsum.org/sigsum-go/pkg/ascii"
	"git.sigsum.org/sigsum-go/pkg/hex"
	"git.sigsum.org/sigsum-go/pkg/merkle"
)

type TreeHead struct {
	Timestamp uint64 `ascii:"timestamp"`
	TreeSize  uint64 `ascii:"tree_size"`
	RootHash  merkle.Hash   `ascii:"root_hash"`
}

type SignedTreeHead struct {
	TreeHead
	Signature Signature `ascii:"signature"`
}

type CosignedTreeHead struct {
	SignedTreeHead
	Cosignature []Signature `ascii:"cosignature"`
	KeyHash     []merkle.Hash      `ascii:"key_hash"`
}

func (th *TreeHead) toBinary() []byte {
	b := make([]byte, 48)
	binary.BigEndian.PutUint64(b[0:8], th.Timestamp)
	binary.BigEndian.PutUint64(b[8:16], th.TreeSize)
	copy(b[16:48], th.RootHash[:])
	return b
}

func (th *TreeHead) ToBinary(keyHash *merkle.Hash) []byte {
	namespace := fmt.Sprintf("tree_head:v0:%s@sigsum.org", hex.Serialize(keyHash[:])) // length 88
	b := make([]byte, 6+4+88+4+0+4+6+4+merkle.HashSize)

	copy(b[0:6], "SSHSIG")
	i := 6
	i += putSSHString(b[i:], namespace)
	i += putSSHString(b[i:], "")
	i += putSSHString(b[i:], "sha256")
	i += putSSHString(b[i:], string((*merkle.HashFn(th.toBinary()))[:]))

	return b
}

func (th *TreeHead) Sign(s crypto.Signer, kh *merkle.Hash) (*SignedTreeHead, error) {
	sig, err := s.Sign(nil, th.ToBinary(kh), crypto.Hash(0))
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

func (sth *SignedTreeHead) Verify(key *PublicKey, kh *merkle.Hash) bool {
	return ed25519.Verify(ed25519.PublicKey(key[:]), sth.TreeHead.ToBinary(kh), sth.Signature[:])
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
