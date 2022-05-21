package sign

import (
	"bytes"
	"fmt"
	"strings"

	"git.sigsum.org/sigsum-go/internal/fmtio"
	"git.sigsum.org/sigsum-go/pkg/hex"
	"git.sigsum.org/sigsum-go/pkg/types"
)

func Main(args []string, optPrivateKey, optKeyHash string) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %s", strings.Join(args, ", "))
	}
	b, err := fmtio.BytesFromStdin()
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	priv, err := fmtio.SignerFromHex(optPrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %v", err)
	}
	keyHash, err := fmtio.HashFromHex(optKeyHash)
	if err != nil {
		return fmt.Errorf("parse key hash: %v", err)
	}

	var input types.SignedTreeHead
	if err := input.FromASCII(bytes.NewBuffer(b)); err != nil {
		return fmt.Errorf("parse signed tree head: %v", err)
	}
	output, err := input.TreeHead.Sign(priv, &keyHash)
	if err != nil {
		return fmt.Errorf("sign tree head: %v", err)
	}

	fmt.Printf("%s\n", hex.Serialize(output.Signature[:]))
	return nil
}
