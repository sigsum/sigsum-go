package hash

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/types"
)

func Main(args []string, optKeyHash, optSignature string, optShardHint uint64) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %s", strings.Join(args, ", "))
	}
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
	leafHash := merkle.HashLeafNode(leaf.ToBinary())

	fmt.Printf("%s\n", hex.EncodeToString(leafHash[:]))
	return nil
}
