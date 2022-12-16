package types

import (
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
)

type InclusionProof struct {
	Size      uint64
	LeafIndex uint64
	Path      []crypto.Hash
}

type ConsistencyProof struct {
	NewSize uint64
	OldSize uint64
	Path    []crypto.Hash
}

func hashesToASCII(w io.Writer, hashes []crypto.Hash) error {
	if len(hashes) == 0 {
		return fmt.Errorf("internal error, empty path")
	}
	for _, hash := range hashes {
		err := ascii.WriteHash(w, "node_hash", &hash)
		if err != nil {
			return err
		}
	}
	return nil
}

// Treats empty list as an error.
func hashesFromASCII(p *ascii.Parser) ([]crypto.Hash, error) {
	var hashes []crypto.Hash
	for {
		hash, err := p.GetHash("node_hash")
		if err == io.EOF {
			if len(hashes) == 0 {
				return nil, fmt.Errorf("invalid path, empty")
			}

			return hashes, nil
		}
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
}

// Note the size is not included on the wire.
func (pr *InclusionProof) ToASCII(w io.Writer) error {
	if err := ascii.WriteInt(w, "leaf_index", pr.LeafIndex); err != nil {
		return err
	}
	return hashesToASCII(w, pr.Path)
}

func (pr *InclusionProof) FromASCII(r io.Reader, size uint64) error {
	pr.Size = size
	p := ascii.NewParser(r)
	var err error
	pr.LeafIndex, err = p.GetInt("leaf_index")
	if err != nil {
		return err
	}
	if pr.LeafIndex >= size {
		return fmt.Errorf("leaf_index out of range")
	}
	pr.Path, err = hashesFromASCII(&p)
	return err
}

func (pr *InclusionProof) Verify(leaf *crypto.Hash, root *crypto.Hash) error {
	return merkle.VerifyInclusion(leaf, pr.LeafIndex, pr.Size, root, pr.Path)
}

func (pr *ConsistencyProof) ToASCII(w io.Writer) error {
	return hashesToASCII(w, pr.Path)
}

func (pr *ConsistencyProof) FromASCII(r io.Reader, oldSize, newSize uint64) error {
	pr.OldSize = oldSize
	pr.NewSize = newSize
	p := ascii.NewParser(r)
	var err error

	pr.Path, err = hashesFromASCII(&p)
	return err
}

func (pr *ConsistencyProof) Verify(oldRoot, newRoot *crypto.Hash) error {
	return merkle.VerifyConsistency(pr.OldSize, pr.NewSize, oldRoot, newRoot, pr.Path)
}
