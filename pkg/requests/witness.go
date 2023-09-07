package requests

import (
	"fmt"
	"io"
	"strings"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

type AddTreeHead struct {
	KeyHash  crypto.Hash
	TreeHead types.SignedTreeHead
	OldSize  uint64
	Proof    types.ConsistencyProof
}

func (req *AddTreeHead) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	var err error
	req.KeyHash, err = p.GetHash("key_hash")
	if err != nil {
		return err
	}
	if err := req.TreeHead.Parse(&p); err != nil {
		return err
	}
	req.OldSize, err = p.GetInt("old_size")
	if err != nil {
		return err
	}
	if req.OldSize > req.TreeHead.Size {
		return fmt.Errorf("invalid request, old_size(%d) > size(%d)",
			req.OldSize, req.TreeHead.Size)
	}
	// Cases of trivial consistency.
	if req.OldSize == 0 || req.OldSize == req.TreeHead.Size {
		return p.GetEOF()
	}
	return req.Proof.Parse(&p)
}

func (req *AddTreeHead) ToASCII(w io.Writer) error {
	if err := ascii.WriteHash(w, "key_hash", &req.KeyHash); err != nil {
		return err
	}
	if err := req.TreeHead.ToASCII(w); err != nil {
		return err
	}
	if err := ascii.WriteInt(w, "old_size", req.OldSize); err != nil {
		return err
	}
	return req.Proof.ToASCII(w)
}

type GetTreeSize struct {
	KeyHash crypto.Hash
}

func (req *GetTreeSize) ToURL(url string) string {
	return fmt.Sprintf("%s%x", url, req.KeyHash)
}

func (req *GetTreeSize) FromURLArgs(args string) error {
	var err error
	req.KeyHash, err = crypto.HashFromHex(args)
	return err
}

func (req *GetTreeSize) FromURL(url string) error {
	split := strings.Split(url, "/")
	if len(split) < 1 {
		return fmt.Errorf("not enough input")
	}
	return req.FromURLArgs(split[len(split)-1])
}
