package hash

import (
	"fmt"
	"strings"

	"git.sigsum.org/sigsum-go/internal/fmtio"
	"git.sigsum.org/sigsum-go/pkg/hex"
	"git.sigsum.org/sigsum-go/pkg/types"
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

	keyHash := types.HashFn(pub[:])

	fmt.Printf("%s\n", hex.Serialize(keyHash[:]))
	return nil
}
