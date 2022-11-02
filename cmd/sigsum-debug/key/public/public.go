package public

import (
	"encoding/hex"
	"fmt"
	"strings"

	"sigsum.org/sigsum-go/internal/fmtio"
	"sigsum.org/sigsum-go/pkg/crypto"
)

func Main(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %s", strings.Join(args, ", "))
	}
	s, err := fmtio.StringFromStdin()
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	priv, err := crypto.SignerFromHex(s)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}
	pub := priv.Public()
	fmt.Printf("%s\n", hex.EncodeToString(pub[:]))
	return nil
}
