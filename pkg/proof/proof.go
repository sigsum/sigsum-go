package proof

import (
	"bytes"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	SigsumProofVersion = 0
)

type SigsumProof struct {
	LogKeyHash       crypto.Hash
	SubmitterKeyHash crypto.Hash
	LeafSignature    crypto.Signature
	TreeHead         types.CosignedTreeHead
	InclusionProof   types.InclusionProof
}

func (sp *SigsumProof) FromASCII(r io.Reader) error {
	// Could do something more fancy with a reader or scanner to
	// split on empty line, without reading all the data up front.
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	proofParts := bytes.Split(data, []byte{'\n', '\n'})
	if len(proofParts) < 3 {
		return fmt.Errorf("invalid proof, too few parts")
	}

	p := ascii.NewParser(bytes.NewBuffer(proofParts[0]))
	version, err := p.GetInt("version")
	if err != nil {
		return fmt.Errorf("invalid version line: %v", err)
	}
	if version != SigsumProofVersion {
		return fmt.Errorf("unexpected version %d, wanted %d", version, SigsumProofVersion)
	}

	sp.LogKeyHash, err = p.GetHash("log")
	if err != nil {
		return fmt.Errorf("invalid log line: %v", err)
	}
	if err := p.GetEOF(); err != nil {
		return err
	}

	p = ascii.NewParser(bytes.NewBuffer(proofParts[1]))
	v, err := p.GetValues("leaf", 2)
	if err != nil {
		return err
	}
	sp.SubmitterKeyHash, err = crypto.HashFromHex(v[0])
	if err != nil {
		return fmt.Errorf("invalid submitter key hash: %v", err)
	}
	sp.LeafSignature, err = crypto.SignatureFromHex(v[1])
	if err != nil {
		return fmt.Errorf("invalid leaf signature: %v", err)
	}
	if err := p.GetEOF(); err != nil {
		return err
	}

	if err := sp.TreeHead.FromASCII(bytes.NewBuffer(proofParts[2])); err != nil {
		return err
	}
	if sp.TreeHead.Size == 0 {
		return fmt.Errorf("invalid tree: empty")
	}
	if sp.TreeHead.Size == 1 {
		if len(proofParts) != 3 {
			return fmt.Errorf("too many parts")
		}
		sp.InclusionProof = types.InclusionProof{}
		return nil
	}
	if len(proofParts) != 4 {
		return fmt.Errorf("too few parts")
	}
	return sp.InclusionProof.FromASCII(bytes.NewBuffer(proofParts[3]))
}

// TODO: Implement a more general verify method, taking policy,
// cosignatures, timestamps into account.
func (sp *SigsumProof) VerifyNoCosignatures(msg *crypto.Hash, submitKey *crypto.PublicKey, logKey *crypto.PublicKey) error {
	if sp.LogKeyHash != crypto.HashBytes(logKey[:]) {
		return fmt.Errorf("unexpected log key hash")
	}
	submitKeyHash := crypto.HashBytes(submitKey[:])
	if sp.SubmitterKeyHash != submitKeyHash {
		return fmt.Errorf("unexpected submitter hash")
	}
	if !types.VerifyLeafMessage(submitKey, msg[:], &sp.LeafSignature) {
		return fmt.Errorf("leaf signature not valid")
	}

	if !sp.TreeHead.Verify(logKey) {
		return fmt.Errorf("invalid log signature on tree head")
	}
	leafHash := (&types.Leaf{
		Checksum:  crypto.HashBytes(msg[:]),
		KeyHash:   submitKeyHash,
		Signature: sp.LeafSignature,
	}).ToHash()

	return sp.InclusionProof.Verify(&leafHash, &sp.TreeHead.TreeHead)
}
