package public

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"git.sigsum.org/sigsum-go/internal/fmtio"
	"git.sigsum.org/sigsum-go/pkg/hex"
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

	fmt.Printf("%s\n", hex.Serialize(pub[:]))
	return nil
}
