package requests

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

type Leaf struct {
	Message   crypto.Hash
	Signature crypto.Signature
	PublicKey crypto.PublicKey

	// Domain is non-empty if and only if request carries a
	// Sigsum-Token header.
	Domain string
	Token  crypto.Signature
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

func (req *Leaf) ToTokenHeader() *string {
	if len(req.Domain) == 0 {
		return nil
	}
	header := fmt.Sprintf("%s %x", req.Domain, req.Token)
	return &header
}

func (req *Leaf) FromTokenHeader(header string) error {
	parts := strings.Split(header, " ")
	if n := len(parts); n != 2 {
		return fmt.Errorf("expected 2 parts, got %d", n)
	}
	if len(parts[0]) == 0 {
		return fmt.Errorf("malformed header, domain part empty")
	}
	var err error
	req.Token, err = crypto.SignatureFromHex(parts[1])
	if err == nil {
		req.Domain = parts[0]
	}
	return err
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

// FromURL parses request parameters from a URL that is not slash-terminated
func (req *Leaves) FromURL(url string) (err error) {
	split := strings.Split(url, "/")
	if len(split) < 2 {
		return fmt.Errorf("not enough input")
	}
	startIndex := split[len(split)-2]
	if req.StartIndex, err = ascii.IntFromDecimal(startIndex); err != nil {
		return err
	}
	endIndex := split[len(split)-1]
	if req.EndIndex, err = ascii.IntFromDecimal(endIndex); err != nil {
		return err
	}
	return nil
}

// FromURL parses request parameters from a URL that is not slash-terminated
func (req *InclusionProof) FromURL(url string) (err error) {
	split := strings.Split(url, "/")
	if len(split) < 2 {
		return fmt.Errorf("not enough input")
	}
	treeSize := split[len(split)-2]
	if req.Size, err = ascii.IntFromDecimal(treeSize); err != nil {
		return err
	}
	req.LeafHash, err = crypto.HashFromHex(split[len(split)-1])
	return err
}

// FromURL parses request parameters from a URL that is not slash-terminated
func (req *ConsistencyProof) FromURL(url string) (err error) {
	split := strings.Split(url, "/")
	if len(split) < 2 {
		return fmt.Errorf("not enough input")
	}
	oldSize := split[len(split)-2]
	if req.OldSize, err = ascii.IntFromDecimal(oldSize); err != nil {
		return err
	}
	newSize := split[len(split)-1]
	if req.NewSize, err = ascii.IntFromDecimal(newSize); err != nil {
		return err
	}
	return nil
}
