package types

import (
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
)

type hashes []crypto.Hash

type InclusionProof struct {
	TreeSize  uint64
	LeafIndex uint64
	Path      hashes
}

type ConsistencyProof struct {
	NewSize uint64
	OldSize uint64
	Path    hashes
}

func (h *hashes) toASCII(w io.Writer, name string) error {
	if len(*h) == 0 {
		return fmt.Errorf("internal error, empty %s", name)
	}
	for _, hash := range *h {
		err := ascii.WriteHash(w, name, &hash)
		if err != nil {
			return err
		}
	}
	return nil
}

// Treats empty list as an error.
func (h *hashes) fromASCII(p *ascii.Parser, name string) error {
	for {
		hash, err := p.GetHash(name)
		if err == io.EOF {
			if len(*h) == 0 {
				return fmt.Errorf("invalid path, empty")
			}

			return nil
		}
		if err != nil {
			return err
		}
		*h = append(*h, hash)
	}
}

// Note the tree_size is not included on the wire.
func (pr *InclusionProof) ToASCII(w io.Writer) error {
	if err := ascii.WriteInt(w, "leaf_index", pr.LeafIndex); err != nil {
		return err
	}
	return pr.Path.toASCII(w, "inclusion_path")
}

func (pr *InclusionProof) FromASCII(r io.Reader, treeSize uint64) error {
	pr.TreeSize = treeSize
	p := ascii.NewParser(r)
	var err error
	pr.LeafIndex, err = p.GetInt("leaf_index")
	if err != nil {
		return err
	}
	if pr.LeafIndex >= treeSize {
		return fmt.Errorf("leaf_index out of range")
	}
	return pr.Path.fromASCII(&p, "inclusion_path")
}

func (pr *InclusionProof) Verify(leaf *crypto.Hash, root *crypto.Hash) error {
	return merkle.VerifyInclusion(leaf, pr.LeafIndex, pr.TreeSize, root, pr.Path)
}

func (pr *ConsistencyProof) ToASCII(w io.Writer) error {
	return pr.Path.toASCII(w, "consistency_path")
}

func (pr *ConsistencyProof) FromASCII(r io.Reader, oldSize, newSize uint64) error {
	pr.OldSize = oldSize
	pr.NewSize = newSize
	p := ascii.NewParser(r)
	return pr.Path.fromASCII(&p, "consistency_path")
}

func (pr *ConsistencyProof) Verify(oldRoot, newRoot *crypto.Hash) error {
	return merkle.VerifyConsistency(pr.OldSize, pr.NewSize, oldRoot, newRoot, pr.Path)
}
