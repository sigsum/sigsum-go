// The checkpoint package implements the subset of the "checkpoint"
// specification needed for interaction with Sigsum logs and
// witnesses.
// https://github.com/C2SP/C2SP/blob/tlog-checkpoint/v1.0.0-rc.1/tlog-checkpoint.md

package checkpoint

import (
	"encoding/base64"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	// An implementatino of the signed note spec MUST support at
	// least 16 signature lines.
	signatureLimit = 16

	ContentTypeTlogSize = "text/x.tlog.size"
)

// Represents only the log's own signature on the checkpoint, i.e., a
// signature line where the key name equals the checkpoint origin.
type Checkpoint struct {
	Origin string
	// TODO: Make SignedTreeHead an anonymous field?
	TreeHead types.SignedTreeHead
	KeyId    KeyId
}

func (cp *Checkpoint) ToASCII(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "%s\n%d\n%s\n\n",
		cp.Origin, cp.TreeHead.Size, base64.StdEncoding.EncodeToString(cp.TreeHead.RootHash[:])); err != nil {
		return err
	}
	return WriteEd25519Signature(w, cp.Origin, cp.KeyId, &cp.TreeHead.Signature)
}

func (cp *Checkpoint) FromASCII(r io.Reader) error {
	reader := ascii.NewLineReader(r)

	origin, err := reader.GetLine()
	if err != nil {
		return err
	}

	// TODO: Validate syntax, e.g., no spaces?
	cp.Origin = origin

	sizeLine, err := reader.GetLine()
	if err != nil {
		return err
	}
	cp.TreeHead.Size, err = ascii.IntFromDecimal(sizeLine)
	if err != nil {
		return err
	}
	hashLine, err := reader.GetLine()
	if err != nil {
		return err
	}
	cp.TreeHead.RootHash, err = crypto.HashFromBase64(hashLine)
	if err != nil {
		return fmt.Errorf("invalid checkpoint, bad root hash %q: %v", hashLine, err)
	}

	if line, err := reader.GetLine(); err != nil {
		return err
	} else if line != "" {
		return fmt.Errorf("invalid checkpoint, root hash not followed by an empty line")
	}
	signatureCount := 0
	found := false
	for {
		line, err := reader.GetLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		signatureCount++
		if signatureCount > signatureLimit {
			return fmt.Errorf("invalid checkpoint, too many signatures")
		}
		keyId, signature, err := ParseEd25519SignatureLine(line, cp.Origin)
		if err != nil {
			if err != ErrUnwantedSignature {
				fmt.Errorf("invalid signature line %d: %s", signatureCount, err)
				return err
			}
			continue
		}
		if found {
			return fmt.Errorf("duplicate log signature on line %d: %s", signatureCount, err)
		}
		cp.KeyId = keyId
		cp.TreeHead.Signature = signature
		found = true
	}
	if !found {
		return fmt.Errorf("invalid checkpoint, %d signature lines, but no log signature", signatureCount)
	}
	return nil
}

func (cp *Checkpoint) Verify(publicKey *crypto.PublicKey) error {
	if cp.KeyId != NewLogKeyId(cp.Origin, publicKey) {
		return fmt.Errorf("unexpected checkpoint key id")
	}
	if !cp.TreeHead.Verify(publicKey) {
		return fmt.Errorf("invalid checkpoint signature")
	}
	return nil
}
