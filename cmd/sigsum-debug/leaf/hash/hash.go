package hash

import (
	"encoding/hex"
	"fmt"
	"strings"

	"sigsum.org/sigsum-go/internal/fmtio"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/types"
)

func Main(args []string, optKeyHash, optSignature string, optShardHint uint64) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %s", strings.Join(args, ", "))
	}
	data, err := fmtio.BytesFromStdin()
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	keyHash, err := fmtio.HashFromHex(optKeyHash)
	if err != nil {
		return fmt.Errorf("parse key hash: %w", err)
	}
	sig, err := fmtio.SignatureFromHex(optSignature)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}

	message := merkle.HashFn(data)
	leaf := types.Leaf{
		Statement: types.Statement{
			ShardHint: optShardHint,
			Checksum:  *merkle.HashFn(message[:]),
		},
		Signature: sig,
		KeyHash:   keyHash,
	}
	leafHash := merkle.HashLeafNode(leaf.ToBinary())

	fmt.Printf("%s\n", hex.EncodeToString(leafHash[:]))
	return nil
}
