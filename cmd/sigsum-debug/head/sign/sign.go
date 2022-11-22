package sign

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

func Main(args []string, optPrivateKey, optKeyHash string) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %s", strings.Join(args, ", "))
	}
	priv, err := crypto.SignerFromHex(optPrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %v", err)
	}
	keyHash, err := crypto.HashFromHex(optKeyHash)
	if err != nil {
		return fmt.Errorf("parse key hash: %v", err)
	}

	var input types.SignedTreeHead
	if err := input.FromASCII(os.Stdin); err != nil {
		return fmt.Errorf("parse signed tree head: %v", err)
	}
	signature, err := input.Sign(priv, &keyHash)
	if err != nil {
		return fmt.Errorf("sign tree head: %v", err)
	}

	fmt.Printf("%s\n", hex.EncodeToString(signature[:]))
	return nil
}
