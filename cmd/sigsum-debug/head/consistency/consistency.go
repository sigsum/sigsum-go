package consistency

import (
	"bytes"
	"fmt"

	"sigsum.org/sigsum-go/internal/fmtio"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

func Main(args []string, optOldSize, optNewSize uint64, optOldRoot, optNewRoot string) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %v", args)
	}
	b, err := fmtio.BytesFromStdin()
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	var proof types.ConsistencyProof
	if err := proof.FromASCII(bytes.NewBuffer(b), optOldSize, optNewSize); err != nil {
		return fmt.Errorf("parse proof: %w", err)
	}
	oldRoot, err := crypto.HashFromHex(optOldRoot)
	if err != nil {
		return fmt.Errorf("parse old root: %w", err)
	}
	newRoot, err := crypto.HashFromHex(optNewRoot)
	if err != nil {
		return fmt.Errorf("parse new root: %w", err)
	}
	if err := proof.Verify(&oldRoot, &newRoot); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return nil
}
