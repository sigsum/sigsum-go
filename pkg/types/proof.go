package types

import (
	"io"

	"git.sigsum.org/sigsum-lib-go/pkg/ascii"
)

type InclusionProof struct {
	TreeSize  uint64
	LeafIndex uint64 `ascii:"leaf_index"`
	Path      []Hash `ascii:"inclusion_path"`
}

type ConsistencyProof struct {
	NewSize uint64
	OldSize uint64
	Path    []Hash `ascii:"consistency_path"`
}

func (p *InclusionProof) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, p)
}

func (p *InclusionProof) FromASCII(r io.Reader, treeSize uint64) error {
	p.TreeSize = treeSize
	return ascii.StdEncoding.Deserialize(r, p)
}

func (p *InclusionProof) Verify(treeSize uint64) bool {
	return false // TODO: verify inclusion proof
}

func (p *ConsistencyProof) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, p)
}

func (p *ConsistencyProof) FromASCII(r io.Reader, oldSize, newSize uint64) error {
	p.OldSize = oldSize
	p.NewSize = newSize
	return ascii.StdEncoding.Deserialize(r, p)
}

func (p *ConsistencyProof) Verify(newRoot, oldRoot *Hash) bool {
	return false // TODO: verify consistency proof
}
