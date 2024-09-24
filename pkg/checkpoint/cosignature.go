package checkpoint

import (
	"bytes"
	"encoding/binary"
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

// Represents a checkpoint cosignature line.
type CosignatureLine struct {
	KeyName string
	KeyId   KeyId
	types.Cosignature
}

func (csl *CosignatureLine) ToASCII(w io.Writer) error {
	prefix := [8]byte{}
	binary.BigEndian.PutUint64(prefix[:], csl.Timestamp)
	return writeNoteSignature(w,
		csl.KeyName, csl.KeyId, bytes.Join([][]byte{prefix[:], csl.Signature[:]}, nil))
}

func CosignatureLinesFromASCII(r io.Reader) ([]CosignatureLine, error) {
	p := ascii.NewLineReader(r)
	var res []CosignatureLine

	for {
		line, err := p.GetLine()
		if err == io.EOF {
			return res, nil
		}
		if err != nil {
			return nil, err
		}
		name, keyId, blob, err := parseNoteSignature(line, 8+crypto.SignatureSize)
		if err != nil {
			if err != ErrUnwantedSignature {
				return nil, err
			}
			continue
		}
		csl := CosignatureLine{
			KeyName:     name,
			KeyId:       keyId,
			Cosignature: types.Cosignature{Timestamp: binary.BigEndian.Uint64(blob[:8])},
		}
		copy(csl.Signature[:], blob[8:])
		res = append(res, csl)
	}
}
