package leaf

import (
	"flag"
	"fmt"
	"log"

	"sigsum.org/sigsum-go/cmd/sigsum-debug/leaf/hash"
	"sigsum.org/sigsum-go/cmd/sigsum-debug/leaf/sign"
	"sigsum.org/sigsum-go/internal/options"
)

const usage = `
sigsum-debug leaf signs, verifies, and hashes Merkle tree leaves.

Usage:

  sigsum-debug leaf help
    Outputs a usage message

  sigsum-debug leaf sign -k PRIVATE_KEY
    Reads data from stdin and outputs a signature

  sigsum-debug leaf hash -k KEY_HASH -s SIGNATURE
    Reads data from stdin and outputs a leaf hash
`

var (
	optPrivateKey, optKeyHash, optSignature string
)

func Main(args []string) error {
	var err error

	opt := options.New(args, func() { log.Printf(usage[1:]) }, setOptions)
	err = checkOptions(opt.Name())
	if err == nil {
		switch opt.Name() {
		case "help", "":
			opt.Usage()
		case "sign":
			err = sign.Main(opt.Args(), optPrivateKey)
		case "hash":
			err = hash.Main(opt.Args(), optKeyHash, optSignature)
		default:
			err = fmt.Errorf("invalid command %q, try \"help\"", opt.Name())
		}
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

func setOptions(fs *flag.FlagSet) {
	switch cmd := fs.Name(); cmd {
	case "help":
	case "sign":
		options.AddString(fs, &optPrivateKey, "k", "private-key", options.DefaultString)
	case "hash":
		options.AddString(fs, &optKeyHash, "k", "key-hash", options.DefaultString)
		options.AddString(fs, &optSignature, "s", "signature", options.DefaultString)
	}
}

// checkOptions checks that options with required arguments were set
func checkOptions(cmd string) error {
	var err error

	switch cmd {
	case "help":
	case "sign":
		err = options.CheckString("private key", optPrivateKey, err)
	case "hash":
		err = options.CheckString("key hash", optKeyHash, err)
		err = options.CheckString("signature", optSignature, err)
	}

	return err
}
