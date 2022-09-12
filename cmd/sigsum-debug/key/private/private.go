package private

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

const privateKeySize = 64

func Main(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %s", strings.Join(args, ", "))
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	if len(priv) != privateKeySize {
		return fmt.Errorf("invalid key size %d", len(priv))
	}

	fmt.Printf("%s\n", hex.EncodeToString(priv.Seed()))
	return nil
}
