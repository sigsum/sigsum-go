package requests

import (
	"encoding/hex"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

type Leaf struct {
	Message   crypto.Hash
	Signature crypto.Signature
	PublicKey crypto.PublicKey
}

type Leaves struct {
	StartIndex uint64
	EndIndex   uint64
}

type InclusionProof struct {
	Size     uint64
	LeafHash crypto.Hash
}

type ConsistencyProof struct {
	OldSize uint64
	NewSize uint64
}

func (req *Leaf) ToASCII(w io.Writer) error {
	if err := ascii.WriteLine(w, "message", req.Message[:]); err != nil {
		return err
	}
	if err := ascii.WriteLine(w, "signature", req.Signature[:]); err != nil {
		return err
	}
	return ascii.WriteLine(w, "public_key", req.PublicKey[:])
}

// Verifies the request signature, and creates a corresponding leaf on success.
func (req *Leaf) Verify() (types.Leaf, error) {
	if !types.VerifyLeafMessage(&req.PublicKey, req.Message[:], &req.Signature) {
		return types.Leaf{}, fmt.Errorf("invalid signature")
	}
	return types.Leaf{
		Checksum:  crypto.HashBytes(req.Message[:]),
		Signature: req.Signature,
		KeyHash:   crypto.HashBytes(req.PublicKey[:]),
	}, nil
}

// ToURL encodes request parameters at the end of a slash-terminated URL
func (req *Leaves) ToURL(url string) string {
	return url + fmt.Sprintf("%d/%d", req.StartIndex, req.EndIndex)
}

// ToURL encodes request parameters at the end of a slash-terminated URL
func (req *InclusionProof) ToURL(url string) string {
	return url + fmt.Sprintf("%d/%s", req.Size, hex.EncodeToString(req.LeafHash[:]))
}

// ToURL encodes request parameters at the end of a slash-terminated URL
func (req *ConsistencyProof) ToURL(url string) string {
	return url + fmt.Sprintf("%d/%d", req.OldSize, req.NewSize)
}

func (req *Leaf) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	var err error
	req.Message, err = p.GetHash("message")
	if err != nil {
		return err
	}
	req.Signature, err = p.GetSignature("signature")
	if err != nil {
		return err
	}
	req.PublicKey, err = p.GetPublicKey("public_key")
	if err != nil {
		return err
	}
	return p.GetEOF()
}

func (req *Leaves) FromURLArgs(start, end string) (err error) {
	if req.StartIndex, err = ascii.IntFromDecimal(start); err != nil {
		return err
	}
	req.EndIndex, err = ascii.IntFromDecimal(end)
	return err
}

func (req *InclusionProof) FromURLArgs(size, hash string) (err error) {
	if req.Size, err = ascii.IntFromDecimal(size); err != nil {
		return err
	}
	req.LeafHash, err = crypto.HashFromHex(hash)
	return err
}

func (req *ConsistencyProof) FromURLArgs(old, new string) (err error) {
	if req.OldSize, err = ascii.IntFromDecimal(old); err != nil {
		return err
	}
	req.NewSize, err = ascii.IntFromDecimal(new)
	return err
}
