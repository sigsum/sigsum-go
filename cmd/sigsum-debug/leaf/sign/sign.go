package sign

import (
	"encoding/hex"
	"fmt"
	"strings"

	"sigsum.org/sigsum-go/internal/fmtio"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

func Main(args []string, optPrivateKey string, optShardHint uint64) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %s", strings.Join(args, ", "))
	}
	data, err := fmtio.BytesFromStdin()
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	priv, err := crypto.SignerFromHex(optPrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	message := crypto.HashBytes(data)
	checksum := crypto.HashBytes(message[:])

	sig, err := types.SignLeafChecksum(priv, &checksum)
	if err != nil {
		fmt.Errorf("sign leaf: %w", err)
	}

	fmt.Printf("%s\n", hex.EncodeToString(sig[:]))
	return nil
}
