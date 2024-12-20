package proof

import (
	"encoding/hex"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	// The current version. Reading of version 1 is still supported.
	SigsumProofVersion     = 2
	prevSigsumProofVersion = 1
	// Relevant only for version 1 proofs.
	ShortChecksumSize = 2
)

// Variant of types.Leaf, without checksum.
type ShortLeaf struct {
	Signature crypto.Signature
	KeyHash   crypto.Hash
}

func NewShortLeaf(leaf *types.Leaf) ShortLeaf {
	return ShortLeaf{Signature: leaf.Signature, KeyHash: leaf.KeyHash}
}

func (l *ShortLeaf) ToLeaf(checksum *crypto.Hash) types.Leaf {
	return types.Leaf{Checksum: *checksum, Signature: l.Signature, KeyHash: l.KeyHash}
}

func (l *ShortLeaf) Parse(p ascii.Parser) error {
	// Same as a leaf line from get-leaves, except that checksum is omitted.
	v, err := p.GetValues("leaf", 2)
	if err != nil {
		return err
	}
	l.KeyHash, err = crypto.HashFromHex(v[0])
	if err != nil {
		return fmt.Errorf("invalid submitter key hash: %v", err)
	}
	l.Signature, err = crypto.SignatureFromHex(v[1])
	if err != nil {
		return fmt.Errorf("invalid leaf signature: %v", err)
	}
	return nil
}

func (l *ShortLeaf) ParseVersion1(p ascii.Parser) error {
	// Same as a leaf line from get-leaves, except that checksum is truncated.
	v, err := p.GetValues("leaf", 3)
	if err != nil {
		return err
	}
	if err := checkShortChecksum(v[0]); err != nil {
		return fmt.Errorf("invalid (version 1) checksum: %v", err)
	}

	l.KeyHash, err = crypto.HashFromHex(v[1])
	if err != nil {
		return fmt.Errorf("invalid submitter key hash: %v", err)
	}
	l.Signature, err = crypto.SignatureFromHex(v[2])
	if err != nil {
		return fmt.Errorf("invalid leaf signature: %v", err)
	}
	return nil
}

func (l *ShortLeaf) ToASCII(w io.Writer) error {
	return ascii.WriteLine(w, "leaf", l.KeyHash[:], l.Signature[:])
}

type SigsumProof struct {
	LogKeyHash crypto.Hash
	Leaf       ShortLeaf
	TreeHead   types.CosignedTreeHead
	Inclusion  types.InclusionProof
}

func checkShortChecksum(s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if got, want := len(b), ShortChecksumSize; got != want {
		return fmt.Errorf("unexpected checksum length, got %d, expected %d", got, want)
	}
	return nil
}

func (sp *SigsumProof) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	version, err := p.GetInt("version")
	if err != nil {
		return fmt.Errorf("invalid version line: %v", err)
	}
	if version != SigsumProofVersion && version != 1 {
		return fmt.Errorf("unknown version %d, wanted %d or %d", version, prevSigsumProofVersion, SigsumProofVersion)
	}

	sp.LogKeyHash, err = p.GetHash("log")
	if err != nil {
		return fmt.Errorf("invalid log line: %v", err)
	}
	if version == 1 {
		if err := sp.Leaf.ParseVersion1(p); err != nil {
			return err
		}
	} else if err := sp.Leaf.Parse(p); err != nil {
		return err
	}
	if err := p.GetEmptyLine(); err != nil {
		return err
	}

	emptyLine, err := sp.TreeHead.Parse(&p)
	if err != nil {
		return err
	}
	if sp.TreeHead.Size == 0 {
		return fmt.Errorf("invalid tree: empty")
	}
	if sp.TreeHead.Size == 1 {
		if emptyLine {
			return ascii.ErrEmptyLine
		}
		sp.Inclusion = types.InclusionProof{}
		return nil
	}
	if !emptyLine {
		return fmt.Errorf("missing inclusion proof part: %v", err)
	}
	return sp.Inclusion.Parse(p)
}

func (sp *SigsumProof) ToASCII(w io.Writer) error {
	if err := ascii.WriteInt(w, "version", SigsumProofVersion); err != nil {
		return err
	}
	if err := ascii.WriteHash(w, "log", &sp.LogKeyHash); err != nil {
		return err
	}
	if err := sp.Leaf.ToASCII(w); err != nil {
		return err
	}
	// Empty line as separator.
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		return err
	}
	if err := sp.TreeHead.ToASCII(w); err != nil {
		return err
	}
	if sp.TreeHead.Size <= 1 {
		return nil
	}
	// Empty line as separator.
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		return err
	}
	return sp.Inclusion.ToASCII(w)
}

func (sp *SigsumProof) Verify(msg *crypto.Hash, submitKeys map[crypto.Hash]crypto.PublicKey, policy *policy.Policy) error {
	checksum := crypto.HashBytes(msg[:])
	leaf := sp.Leaf.ToLeaf(&checksum)
	submitKey, ok := submitKeys[sp.Leaf.KeyHash]
	if !ok {
		return fmt.Errorf("unknown leaf key hash")
	}
	if !leaf.Verify(&submitKey) {
		return fmt.Errorf("leaf signature not valid")
	}
	if err := policy.VerifyCosignedTreeHead(&sp.LogKeyHash, &sp.TreeHead); err != nil {
		return err
	}
	leafHash := leaf.ToHash()
	return sp.Inclusion.Verify(&leafHash, &sp.TreeHead.TreeHead)
}

func (sp *SigsumProof) VerifyNoCosignatures(msg *crypto.Hash, submitKeys map[crypto.Hash]crypto.PublicKey, logKey *crypto.PublicKey) error {
	policy, err := policy.NewKofNPolicy([]crypto.PublicKey{*logKey}, nil, 0)
	if err != nil {
		return fmt.Errorf("internal error: %v", err)
	}
	return sp.Verify(msg, submitKeys, policy)
}
