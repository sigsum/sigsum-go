package merkle

import (
	"encoding/base64"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/v2/pkg/ascii"
	"sigsum.org/sigsum-go/v2/pkg/crypto"
)

const CosignatureNamespace = "cosignature/v1"

type TreeHead struct {
	Size     uint64
	RootHash crypto.Hash
}

func NewEmptyTreeHead() TreeHead {
	return TreeHead{Size: 0, RootHash: HashEmptyTree()}
}

// Produces the checkpoint body, i.e., the data to be signed when
// represented as a "signed note".
func (th *TreeHead) FormatCheckpoint(origin string) string {
	return fmt.Sprintf("%s\n%d\n%s\n",
		origin, th.Size,
		base64.StdEncoding.EncodeToString(th.RootHash[:]))
}

func (th *TreeHead) ToASCII(w io.Writer) error {
	if err := ascii.WriteInt(w, "size", th.Size); err != nil {
		return err
	}
	return ascii.WriteHash(w, "root_hash", &th.RootHash)
}

func (th *TreeHead) ToCosignedData(origin string, timestamp uint64) string {
	return fmt.Sprintf("%s\ntime %d\n%s",
		CosignatureNamespace, timestamp,
		th.FormatCheckpoint(origin))
}

// Doesn't require EOF, so it can be used for parsing a tree head
// embedded in a larger struct.
func (th *TreeHead) Parse(p *ascii.Parser) error {
	var err error
	th.Size, err = p.GetInt("size")
	if err != nil {
		return err
	}
	th.RootHash, err = p.GetHash("root_hash")
	return err
}

func (th *TreeHead) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	err := th.Parse(&p)
	if err != nil {
		return err
	}
	return p.GetEOF()
}
