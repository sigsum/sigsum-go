package types

import (
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"

	"git.sigsum.org/sigsum-lib-go/pkg/ascii"
)

type Statement struct {
	ShardHint uint64 `ascii:"shard_hint"`
	Checksum  Hash   `ascii:"checksum"`
}

type Leaf struct {
	Statement
	Signature Signature `ascii:"signature"`
	KeyHash   Hash      `ascii:"key_hash"`
}

type Leaves []Leaf

func (s *Statement) ToBinary() []byte {
	namespace := fmt.Sprintf("tree_leaf:v0:%d@sigsum.org", s.ShardHint)
	b := make([]byte, 6+4+len(namespace)+4+0+4+6+4+HashSize)

	copy(b[0:6], "SSHSIG")
	i := 6
	i += putSSHString(b[i:], namespace)
	i += putSSHString(b[i:], "")
	i += putSSHString(b[i:], "sha256")
	i += putSSHString(b[i:], string(s.Checksum[:]))

	return b
}

func (s *Statement) Sign(signer crypto.Signer) (*Signature, error) {
	sig, err := signer.Sign(nil, s.ToBinary(), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("types: failed signing statement")
	}

	var signature Signature
	copy(signature[:], sig)
	return &signature, nil
}

func (s *Statement) Verify(key *PublicKey, sig *Signature) bool {
	return ed25519.Verify(ed25519.PublicKey(key[:]), s.ToBinary(), sig[:])
}

func (l *Leaf) ToBinary() []byte {
	b := make([]byte, 136)
	binary.BigEndian.PutUint64(b[0:8], l.ShardHint)
	copy(b[8:40], l.Checksum[:])
	copy(b[40:104], l.Signature[:])
	copy(b[104:136], l.KeyHash[:])
	return b
}

func (l *Leaf) FromBinary(b []byte) error {
	if len(b) != 136 {
		return fmt.Errorf("types: invalid leaf size: %d", len(b))
	}

	l.ShardHint = binary.BigEndian.Uint64(b[0:8])
	copy(l.Checksum[:], b[8:40])
	copy(l.Signature[:], b[40:104])
	copy(l.KeyHash[:], b[104:136])
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
		ShardHint []uint64    `ascii:"shard_hint"`
		Checksum  []Hash      `ascii:"checksum"`
		Signature []Signature `ascii:"signature"`
		KeyHash   []Hash      `ascii:"key_hash"`
	}{}

	if err := ascii.StdEncoding.Deserialize(r, leaves); err != nil {
		return err
	}
	n := len(leaves.ShardHint)
	if n != len(leaves.Checksum) {
		return fmt.Errorf("types: mismatched leaf field counts")
	}
	if n != len(leaves.Signature) {
		return fmt.Errorf("types: mismatched leaf field counts")
	}
	if n != len(leaves.KeyHash) {
		return fmt.Errorf("types: mismatched leaf field counts")
	}

	*l = make([]Leaf, 0, n)
	for i := 0; i < n; i++ {
		*l = append(*l, Leaf{
			Statement: Statement{
				ShardHint: leaves.ShardHint[i],
				Checksum:  leaves.Checksum[i],
			},
			Signature: leaves.Signature[i],
			KeyHash:   leaves.KeyHash[i],
		})
	}
	return nil
}
