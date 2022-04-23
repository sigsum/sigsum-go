package sign

import (
	"fmt"
	"strings"

	"git.sigsum.org/sigsum-go/internal/fmtio"
	"git.sigsum.org/sigsum-go/pkg/hex"
	"git.sigsum.org/sigsum-go/pkg/types"
)

func Main(args []string, optPrivateKey string, optShardHint uint64) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %s", strings.Join(args, ", "))
	}
	data, err := fmtio.BytesFromStdin()
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	priv, err := fmtio.SignerFromHex(optPrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	preimage := types.HashFn(data)
	stm := types.Statement{
		ShardHint: optShardHint,
		Checksum:  *types.HashFn(preimage[:]),
	}
	sig, err := stm.Sign(priv)
	if err != nil {
		fmt.Errorf("sign leaf: %w", err)
	}

	fmt.Printf("%s\n", hex.Serialize(sig[:]))
	return nil
}
