package sign

import (
	"fmt"
	"os"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/types"
)

func Main(optPrivateKey, optKeyHash string, timestamp uint64) error {
	priv, err := readPrivateKeyFile(optPrivateKey)
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
	cosignature, err := input.Cosign(priv, &keyHash, timestamp)
	if err != nil {
		return fmt.Errorf("cosign tree head: %v", err)
	}

	fmt.Printf("%x\n", cosignature.Signature)
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
