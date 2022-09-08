package key

import (
	"flag"
	"fmt"
	"log"

	"sigsum.org/sigsum-go/cmd/sigsum-debug/key/hash"
	"sigsum.org/sigsum-go/cmd/sigsum-debug/key/private"
	"sigsum.org/sigsum-go/cmd/sigsum-debug/key/public"
	"sigsum.org/sigsum-go/internal/options"
)

const usage = `
sigsum-debug key generates private keys, public keys, and key hashes.

Usage:

  sigsum-debug key help     Outputs a usage message
  sigsum-debug key private  Outputs a new private key
  sigsum-debug key public   Outputs a public key for a private key on stdin
  sigsum-debug key hash     Outputs a key hash for a public key on stdin

`

func Main(args []string) error {
	var err error

	opt := options.New(args, func() { log.Printf(usage[1:]) }, func(_ *flag.FlagSet) {})
	switch opt.Name() {
	case "help", "":
		opt.Usage()
	case "private":
		err = private.Main(opt.Args())
	case "public":
		err = public.Main(opt.Args())
	case "hash":
		err = hash.Main(opt.Args())
	default:
		err = fmt.Errorf("invalid command %q, try \"help\"", opt.Name())
	}
	if err != nil {
		format := " %s: %w"
		if len(opt.Name()) == 0 {
			format = "%s: %w"
		}
		err = fmt.Errorf(format, opt.Name(), err)
	}

	return err
}
