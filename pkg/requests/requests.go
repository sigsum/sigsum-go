package requests

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/hex"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/types"
)

type Leaf struct {
	ShardHint  uint64          `ascii:"shard_hint"`
	Message    merkle.Hash     `ascii:"message"`
	Signature  types.Signature `ascii:"signature"`
	PublicKey  types.PublicKey `ascii:"public_key"`
	DomainHint string          `ascii:"domain_hint"`
}

type Leaves struct {
	StartSize uint64
	EndSize   uint64
}

type InclusionProof struct {
	TreeSize uint64
	LeafHash merkle.Hash
}

type ConsistencyProof struct {
	OldSize uint64
	NewSize uint64
}

type Cosignature struct {
	Cosignature types.Signature `ascii:"cosignature"`
	KeyHash     merkle.Hash     `ascii:"key_hash"`
}

func (req *Leaf) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, req)
}

// ToURL encodes request parameters at the end of a slash-terminated URL
func (req *Leaves) ToURL(url string) string {
	return url + fmt.Sprintf("%d/%d", req.StartSize, req.EndSize)
}

// ToURL encodes request parameters at the end of a slash-terminated URL
func (req *InclusionProof) ToURL(url string) string {
	return url + fmt.Sprintf("%d/%s", req.TreeSize, hex.Serialize(req.LeafHash[:]))
}

// ToURL encodes request parameters at the end of a slash-terminated URL
func (req *ConsistencyProof) ToURL(url string) string {
	return url + fmt.Sprintf("%d/%d", req.OldSize, req.NewSize)
}

func (req *Cosignature) ToASCII(w io.Writer) error {
	return ascii.StdEncoding.Serialize(w, req)
}

func (req *Leaf) FromASCII(r io.Reader) error {
	return ascii.StdEncoding.Deserialize(r, req)
}

// FromURL parses request parameters from a URL that is not slash-terminated
func (req *Leaves) FromURL(url string) (err error) {
	split := strings.Split(url, "/")
	if len(split) < 2 {
		return fmt.Errorf("not enough input")
	}
	startSize := split[len(split)-2]
	if req.StartSize, err = strconv.ParseUint(startSize, 10, 64); err != nil {
		return err
	}
	endSize := split[len(split)-1]
	if req.EndSize, err = strconv.ParseUint(endSize, 10, 64); err != nil {
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
	if req.TreeSize, err = strconv.ParseUint(treeSize, 10, 64); err != nil {
		return err
	}
	b, err := hex.Deserialize(split[len(split)-1])
	if err != nil {
		return err
	}
	if n := len(b); n != merkle.HashSize {
		return fmt.Errorf("invalid hash size %d", n)
	}
	copy(req.LeafHash[:], b)
	return nil
}

// FromURL parses request parameters from a URL that is not slash-terminated
func (req *ConsistencyProof) FromURL(url string) (err error) {
	split := strings.Split(url, "/")
	if len(split) < 2 {
		return fmt.Errorf("not enough input")
	}
	oldSize := split[len(split)-2]
	if req.OldSize, err = strconv.ParseUint(oldSize, 10, 64); err != nil {
		return err
	}
	newSize := split[len(split)-1]
	if req.NewSize, err = strconv.ParseUint(newSize, 10, 64); err != nil {
		return err
	}
	return nil
}

func (req *Cosignature) FromASCII(r io.Reader) error {
	return ascii.StdEncoding.Deserialize(r, req)
}
