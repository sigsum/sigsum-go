package sign

import (
	"fmt"
	"os"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/types"
)

func Main(args []string, optPrivateKey string) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %s", strings.Join(args, ", "))
	}
	priv, err := readPrivateKeyFile(optPrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	message, err := crypto.HashFile(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	checksum := crypto.HashBytes(message[:])

	sig, err := types.SignLeafChecksum(priv, &checksum)
	if err != nil {
		fmt.Errorf("sign leaf: %w", err)
	}

	fmt.Printf("%x\n", sig)
	return nil
}

func readPrivateKeyFile(fileName string) (crypto.Signer, error) {
	contents, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	signer, err := key.ParsePrivateKey(string(contents))
	if err != nil {
		return nil, fmt.Errorf("parsing file %q failed: %v", fileName, err)
	}
	return signer, nil
}
