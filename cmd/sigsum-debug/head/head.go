package head

import (
	"flag"
	"fmt"
	"log"

	"git.sigsum.org/sigsum-go/cmd/sigsum-debug/head/consistency"
	"git.sigsum.org/sigsum-go/cmd/sigsum-debug/head/sign"
	"git.sigsum.org/sigsum-go/cmd/sigsum-debug/head/verify"
	"git.sigsum.org/sigsum-go/internal/options"
)

const usage = `
sigsum-debug head signs and verifies tree heads.

Usage:

  sigsum-debug head help
    Outputs a usage message

  sigsum-debug head sign -k PRIVATE_KEY -h KEY_HASH
    Reads an ascii signed tree head from stdin and outputs a new signature

  sigsum-debug head verify -k PUBLIC_KEY
    Reads an ascii signed tree head from stdin and verifies it

  sigsum-debug head consistency -n OLD_SIZE -N NEW_SIZE -r OLD_ROOT -R NEW_ROOT
    Reads an ascii consistency proof from stdin and verifies it

`

var (
	optPrivateKey, optPublicKey, optKeyHash, optOldRoot, optNewRoot string
	optOldSize, optNewSize                                          uint64
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
			err = sign.Main(opt.Args(), optPrivateKey, optKeyHash)
		case "verify":
			err = verify.Main(opt.Args(), optPublicKey)
		case "consistency":
			err = consistency.Main(opt.Args(), optOldSize, optNewSize, optOldRoot, optNewRoot)
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
		options.AddString(fs, &optKeyHash, "h", "key-hash", options.DefaultString)
	case "verify":
		options.AddString(fs, &optPublicKey, "k", "public-key", options.DefaultString)
	case "consistency":
		options.AddUint64(fs, &optOldSize, "n", "old-size", options.DefaultUint64)
		options.AddUint64(fs, &optNewSize, "N", "new-size", options.DefaultUint64)
		options.AddString(fs, &optOldRoot, "r", "old-root", options.DefaultString)
		options.AddString(fs, &optNewRoot, "R", "new-root", options.DefaultString)
	}
}

// checkOptions checks that options with required arguments were set
func checkOptions(cmd string) error {
	var err error

	switch cmd {
	case "help":
	case "sign":
		err = options.CheckString("private key", optPrivateKey, err)
		err = options.CheckString("key hash", optKeyHash, err)
	case "verify":
		err = options.CheckString("public key", optPublicKey, err)
	case "consistency":
		err = options.CheckUint64("old size", optOldSize, err)
		err = options.CheckUint64("new size", optNewSize, err)
		err = options.CheckString("old root", optOldRoot, err)
		err = options.CheckString("new root", optNewRoot, err)
	}

	return err
}
