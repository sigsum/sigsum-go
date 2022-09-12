package hash

import (
	"encoding/hex"
	"fmt"
	"strings"

	"sigsum.org/sigsum-go/internal/fmtio"
	"sigsum.org/sigsum-go/pkg/merkle"
)

func Main(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("trailing arguments: %s", strings.Join(args, ", "))
	}
	s, err := fmtio.StringFromStdin()
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	pub, err := fmtio.PublicKeyFromHex(s)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}

	keyHash := merkle.HashFn(pub[:])

	fmt.Printf("%s\n", hex.EncodeToString(keyHash[:]))
	return nil
}
