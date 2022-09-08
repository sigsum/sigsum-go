package inclusion

import (
	"bytes"
	"fmt"

	"sigsum.org/sigsum-go/internal/fmtio"
	"sigsum.org/sigsum-go/pkg/types"
)

func Main(args []string, optLeafHash, optRootHash string, optTreeSize uint64) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %v", args)
	}
	b, err := fmtio.BytesFromStdin()
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	var proof types.InclusionProof
	if err := proof.FromASCII(bytes.NewBuffer(b), optTreeSize); err != nil {
		return fmt.Errorf("parse proof: %w", err)
	}
	leafHash, err := fmtio.HashFromHex(optLeafHash)
	if err != nil {
		return fmt.Errorf("parse leaf hash: %w", err)
	}
	rootHash, err := fmtio.HashFromHex(optRootHash)
	if err != nil {
		return fmt.Errorf("parse root hash: %w", err)
	}
	if err := proof.Verify(&leafHash, &rootHash); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return nil
}
