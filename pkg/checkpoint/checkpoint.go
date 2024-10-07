// The checkpoint package implements the subset of the "checkpoint"
// specification needed for interaction between a Sigsum log and its
// witnesses.
// https://github.com/C2SP/C2SP/blob/tlog-checkpoint/v1.0.0-rc.1/tlog-checkpoint.md
//
// This package aims to let a Sigsum log interact successfully with
// any witness conforming to the checkpoint spec. However, the current
// implementation enforces some additional requirements on logs (which
// are always satisfied by Sigsum logs):
//
// * The log’s key name on its signature line MUST match the origin
//   line. (In contrast to the spec, where this is a SHOULD).
//
// * There must be no extension lines.
//
// * There must be a single signature line with the origin as key
//   name, or rather, a single line where (i) the key name equals the
//   origin and (ii) the signature size is appropriate for an Ed25519
//   signature.
//
// Hence, a witness based on this package, in its current state, will
// not support logs where the origin line differs from the log's key
// name (e.g., the go checksum database, with an origin line "go.sum
// database tree" which isn't a syntactically valid key name), or
// logs that sign their checkpoints using multiple Ed25519 signatures,
// e.g., for key rotation.

package checkpoint

import (
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	// An implementation of the signed note spec MUST support at
	// least 16 signature lines.
	signatureLimit = 16

	ContentTypeTlogSize = "text/x.tlog.size"
)

// Represents only the log's own signature on the checkpoint, i.e., a
// signature line where the key name equals the checkpoint origin.
type Checkpoint struct {
	types.SignedTreeHead
	Origin string // Checkpoint origin
	KeyId  KeyId  // The key id associated with SignedTreeHead.Signature

}

func (cp *Checkpoint) ToASCII(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "%s\n", cp.TreeHead.FormatCheckpoint(cp.Origin)); err != nil {
		return err
	}
	return WriteEd25519Signature(w, cp.Origin, cp.KeyId, &cp.Signature)
}

// The keyName identifies the signature line of interest. If keyName
// is the empty string, use the checkpoint's origin. Intended for
// interop tests with non-Sigsum checkpoints.
func (cp *Checkpoint) fromASCIIWithKeyName(r io.Reader, keyName string) error {
	reader := ascii.NewLineReader(r)

	origin, err := reader.GetLine()
	if err != nil {
		return err
	}

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

	if keyName == "" {
		keyName = cp.Origin
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
		keyId, signature, err := ParseEd25519SignatureLine(line, keyName)
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
		cp.Signature = signature
		found = true
	}
	if !found {
		return fmt.Errorf("invalid checkpoint, %d signature lines, but no log signature", signatureCount)
	}
	return nil
}

func (cp *Checkpoint) FromASCII(r io.Reader) error {
	return cp.fromASCIIWithKeyName(r, "")
}

func (cp *Checkpoint) Verify(publicKey *crypto.PublicKey) error {
	if cp.KeyId != NewLogKeyId(cp.Origin, publicKey) {
		return fmt.Errorf("unexpected checkpoint key id")
	}
	if !cp.SignedTreeHead.Verify(publicKey) {
		return fmt.Errorf("invalid checkpoint signature")
	}
	return nil
}

func (cp *Checkpoint) Cosign(signer crypto.Signer, timestamp uint64) (types.Cosignature, error) {
	return cp.TreeHead.Cosign(signer, cp.Origin, timestamp)
}

func (cp *Checkpoint) VerifyCosignature(publicKey *crypto.PublicKey, cosignature *types.Cosignature) bool {
	return cosignature.Verify(publicKey, cp.Origin, &cp.SignedTreeHead.TreeHead)
}

// Returns a verified cosignature identified by public key. The key
// name on the signature line is ignored, except that it is used to
// construct the key id.
func (cp *Checkpoint) VerifyCosignatureByKey(signatures []CosignatureLine, publicKey *crypto.PublicKey) (types.Cosignature, error) {
	for _, signature := range signatures {
		if keyId := NewWitnessKeyId(signature.KeyName, publicKey); signature.KeyId != keyId {
			continue
		}
		if !cp.VerifyCosignature(publicKey, &signature.Cosignature) {
			return types.Cosignature{}, fmt.Errorf("cosignature not valid")
		}

		return signature.Cosignature, nil
	}
	return types.Cosignature{}, fmt.Errorf("no cosignature for given key")
}
