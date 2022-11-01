package types

import (
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
)

type InclusionProof struct {
	TreeSize  uint64
	LeafIndex uint64
	Path      []crypto.Hash
}

type ConsistencyProof struct {
	NewSize uint64
	OldSize uint64
	Path    []crypto.Hash
}

func writeHashes(w io.Writer, name string, hashes []crypto.Hash) error {
	for _, hash := range hashes {
		err := ascii.WriteHash(w, name, &hash)
		if err != nil {
			return err
		}
	}
	return nil
}

// Note the tree_size is not included on the wire.
func (pr *InclusionProof) ToASCII(w io.Writer) error {
 	if err := ascii.WriteInt(w, "leaf_index", pr.LeafIndex); err != nil {
 		return err
 	}
 	return writeHashes(w, "inclusion_path", pr.Path)
}

func (pr *InclusionProof) FromASCII(r io.Reader, treeSize uint64) error {
	pr.TreeSize = treeSize
	p := ascii.NewParser(r)
	var err error
	pr.LeafIndex, err = p.GetInt("leaf_index")
	if pr.LeafIndex >= treeSize {
		return fmt.Errorf("leaf_index out of range")
	}
	pr.Path, err = p.GetHashes("inclusion_path")
	return err
}

func (pr *InclusionProof) Verify(leaf *crypto.Hash, root *crypto.Hash) error {
	return merkle.VerifyInclusion(leaf, pr.LeafIndex, pr.TreeSize, root, pr.Path)
}

func (pr *ConsistencyProof) ToASCII(w io.Writer) error {
 	return writeHashes(w, "consistency_path", pr.Path)
}

func (pr *ConsistencyProof) FromASCII(r io.Reader, oldSize, newSize uint64) error {
	pr.OldSize = oldSize
	pr.NewSize = newSize
	p := ascii.NewParser(r)
	var err error
	pr.Path, err = p.GetHashes("consistency_path")
	return err
}

func (pr *ConsistencyProof) Verify(oldRoot, newRoot *crypto.Hash) error {
	return merkle.VerifyConsistency(pr.OldSize, pr.NewSize, oldRoot, newRoot, pr.Path)
}
