package types

import (
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/merkle"
)

type InclusionProof struct {
	TreeSize  uint64
	LeafIndex uint64        `ascii:"leaf_index"`
	Path      []merkle.Hash `ascii:"inclusion_path"`
}

type ConsistencyProof struct {
	NewSize uint64
	OldSize uint64
	Path    []merkle.Hash `ascii:"consistency_path"`
}

func (p *InclusionProof) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, p)
}

func (p *InclusionProof) FromASCII(r io.Reader, treeSize uint64) error {
	p.TreeSize = treeSize
	return ascii.StdEncoding.Deserialize(r, p)
}

func (p *InclusionProof) Verify(leaf *merkle.Hash, root *merkle.Hash) error {
	return merkle.VerifyInclusion(*leaf, p.LeafIndex, p.TreeSize, *root, p.Path)
}

func (p *ConsistencyProof) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, p)
}

func (p *ConsistencyProof) FromASCII(r io.Reader, oldSize, newSize uint64) error {
	p.OldSize = oldSize
	p.NewSize = newSize
	return ascii.StdEncoding.Deserialize(r, p)
}

func (p *ConsistencyProof) Verify(oldRoot, newRoot *merkle.Hash) error {
	return merkle.VerifyConsistency(p.OldSize, p.NewSize, *oldRoot, *newRoot, p.Path)
}
