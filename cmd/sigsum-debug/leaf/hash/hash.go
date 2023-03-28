package hash

import (
	"fmt"
	"os"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

func Main(optKeyHash, optSignature string) error {
	keyHash, err := crypto.HashFromHex(optKeyHash)
	if err != nil {
		return fmt.Errorf("parse key hash: %w", err)
	}
	sig, err := crypto.SignatureFromHex(optSignature)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}

	message, err := crypto.HashFile(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	leaf := types.Leaf{
		Checksum:  crypto.HashBytes(message[:]),
		Signature: sig,
		KeyHash:   keyHash,
	}

	fmt.Printf("%x\n", leaf.ToHash())
	return nil
}
