package types

import (
	"encoding/base64"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
)

const (
	proofSizeLimit = 63
)

type InclusionProof struct {
	LeafIndex uint64
	Path      []crypto.Hash
}

type ConsistencyProof struct {
	Path []crypto.Hash
}

func hashesToASCII(w io.Writer, hashes []crypto.Hash) error {
	for _, hash := range hashes {
		if err := ascii.WriteHash(w, "node_hash", &hash); err != nil {
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
		if len(hashes) >= proofSizeLimit {
			return nil, fmt.Errorf("too many node hashes")
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

func (pr *InclusionProof) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	var err error
	pr.LeafIndex, err = p.GetInt("leaf_index")
	if err != nil {
		return err
	}
	pr.Path, err = hashesFromASCII(&p)
	return err
}

func (pr *InclusionProof) Verify(leaf *crypto.Hash, th *TreeHead) error {
	return merkle.VerifyInclusion(leaf, pr.LeafIndex, th.Size, &th.RootHash, pr.Path)
}

func (pr *ConsistencyProof) ToASCII(w io.Writer) error {
	return hashesToASCII(w, pr.Path)
}

func (pr *ConsistencyProof) Parse(p *ascii.Parser) error {
	var err error
	pr.Path, err = hashesFromASCII(p)
	return err
}

func (pr *ConsistencyProof) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	return pr.Parse(&p)
}

func (pr *ConsistencyProof) ToBase64(w io.Writer) error {
	for _, hash := range pr.Path {
		if _, err := fmt.Fprintln(w, base64.StdEncoding.EncodeToString(hash[:])); err != nil {
			return err
		}
	}
	return nil
}

func (pr *ConsistencyProof) FromBase64(r ascii.LineReader) error {
	pr.Path = nil
	for {
		line, err := r.GetLine()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(pr.Path) >= proofSizeLimit {
			return fmt.Errorf("too many entries for consistency proof")
		}
		hash, err := crypto.HashFromBase64(line)
		if err != nil {
			return err
		}
		pr.Path = append(pr.Path, hash)
	}
}

func (pr *ConsistencyProof) Verify(oldTree, newTree *TreeHead) error {
	return merkle.VerifyConsistency(
		oldTree.Size, newTree.Size, &oldTree.RootHash, &newTree.RootHash, pr.Path)
}
