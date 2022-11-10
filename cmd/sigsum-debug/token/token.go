package token

import (
	"fmt"
	"io"
	"os"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/submit-token"
)

const usage = `
sigsum-debug token log-key < privata key
`

func Main(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("required log-key argument missing")
	}
	keyHex, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed reading stdin: %w", err)
	}
	signer, err := crypto.SignerFromHex(strings.TrimSpace(string(keyHex)))
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	logKey, err := crypto.PublicKeyFromHex(args[0])
	if err != nil {
		return fmt.Errorf("invalid log public key: %w", err)
	}
	sig, err := token.MakeToken(signer, &logKey)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}
	fmt.Printf("%x\n", sig)
	return nil
}
