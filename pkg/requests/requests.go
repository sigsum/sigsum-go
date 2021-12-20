package requests

import (
	"io"

	"git.sigsum.org/sigsum-lib-go/pkg/ascii"
	"git.sigsum.org/sigsum-lib-go/pkg/types"
)

type Leaf struct {
	types.Statement
	Signature       types.Signature `ascii:"signature"`
	VerificationKey types.PublicKey `ascii:"verification_key"`
	DomainHint      string          `ascii:"domain_hint"`
}

type Leaves struct {
	StartSize uint64 `ascii:"start_size"`
	EndSize   uint64 `ascii:"end_size"`
}

type InclusionProof struct {
	LeafHash types.Hash `ascii:"leaf_hash"`
	TreeSize uint64     `ascii:"tree_size"`
}

type ConsistencyProof struct {
	NewSize uint64 `ascii:"new_size"`
	OldSize uint64 `ascii:"old_size"`
}

type Cosignature struct {
	Cosignature types.Signature `ascii:"cosignature"`
	KeyHash     types.Hash      `ascii:"key_hash"`
}

func (req *Leaf) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, req)
}

func (req *Leaves) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, req)
}

func (req *InclusionProof) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, req)
}

func (req *ConsistencyProof) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, req)
}

func (req *Cosignature) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, req)
}

func (req *Leaf) FromASCII(r io.Reader) error {
	return ascii.StdEncoding.Deserialize(r, req)
}

func (req *Leaves) FromASCII(r io.Reader) error {
	return ascii.StdEncoding.Deserialize(r, req)
}

func (req *InclusionProof) FromASCII(r io.Reader) error {
	return ascii.StdEncoding.Deserialize(r, req)
}

func (req *ConsistencyProof) FromASCII(r io.Reader) error {
	return ascii.StdEncoding.Deserialize(r, req)
}

func (req *Cosignature) FromASCII(r io.Reader) error {
	return ascii.StdEncoding.Deserialize(r, req)
}
