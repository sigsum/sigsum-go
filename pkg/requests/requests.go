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

// Returns the index of the nth last occurence of the substr, or -1 if
// there are not enough occurences. If n <= 0, returns len(s).
func nLastIndex(s, substr string, n int) int {
	for i := 0; i < n; i++ {
		index := strings.LastIndex(s, substr)
		if index < 0 {
			return index
		}
		s = s[:index]
	}
	return len(s)
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

func (req *Leaves) FromURLArgs(args string) (err error) {
	split := strings.Split(args, "/")
	if len(split) != 2 {
		return fmt.Errorf("invalid arguments")
	}
	if req.StartIndex, err = ascii.IntFromDecimal(split[0]); err != nil {
		return err
	}
	req.EndIndex, err = ascii.IntFromDecimal(split[1])
	return err
}

// FromURL parses request parameters from a URL that is not slash-terminated
func (req *Leaves) FromURL(url string) (err error) {
	index := nLastIndex(url, "/", 2)
	if index < 0 {
		return fmt.Errorf("not enough input")
	}
	return req.FromURLArgs(url[index+1:])
}

func (req *InclusionProof) FromURLArgs(args string) (err error) {
	split := strings.Split(args, "/")
	if len(split) != 2 {
		return fmt.Errorf("invalid arguments")
	}
	if req.Size, err = ascii.IntFromDecimal(split[0]); err != nil {
		return err
	}
	req.LeafHash, err = crypto.HashFromHex(split[1])
	return err
}

// FromURL parses request parameters from a URL that is not slash-terminated
func (req *InclusionProof) FromURL(url string) (err error) {
	index := nLastIndex(url, "/", 2)
	if index < 0 {
		return fmt.Errorf("not enough input")
	}
	return req.FromURLArgs(url[index+1:])
}

func (req *ConsistencyProof) FromURLArgs(args string) (err error) {
	split := strings.Split(args, "/")
	if len(split) != 2 {
		return fmt.Errorf("invalid arguments")
	}
	if req.OldSize, err = ascii.IntFromDecimal(split[0]); err != nil {
		return err
	}
	req.NewSize, err = ascii.IntFromDecimal(split[1])
	return err
}

// FromURL parses request parameters from a URL that is not slash-terminated
func (req *ConsistencyProof) FromURL(url string) (err error) {
	index := nLastIndex(url, "/", 2)
	if index < 0 {
		return fmt.Errorf("not enough input")
	}
	return req.FromURLArgs(url[index+1:])
}
