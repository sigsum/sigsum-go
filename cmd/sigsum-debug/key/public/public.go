package public

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	"sigsum.org/sigsum-go/internal/fmtio"
)

func Main(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %s", strings.Join(args, ", "))
	}
	s, err := fmtio.StringFromStdin()
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	priv, err := fmtio.SignerFromHex(s)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("not an ed25519 key")
	}

	fmt.Printf("%s\n", hex.EncodeToString(pub[:]))
	return nil
}
