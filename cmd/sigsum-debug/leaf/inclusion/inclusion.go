package inclusion

import (
	"fmt"
	"os"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

func Main(args []string, optLeafHash, optRootHash string, optSize uint64) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %v", args)
	}
	var proof types.InclusionProof
	if err := proof.FromASCII(os.Stdin, optSize); err != nil {
		return fmt.Errorf("parse proof: %w", err)
	}
	leafHash, err := crypto.HashFromHex(optLeafHash)
	if err != nil {
		return fmt.Errorf("parse leaf hash: %w", err)
	}
	rootHash, err := crypto.HashFromHex(optRootHash)
	if err != nil {
		return fmt.Errorf("parse root hash: %w", err)
	}
	if err := proof.Verify(&leafHash, &rootHash); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return nil
}
