package head

import (
	"flag"
	"fmt"
	"log"
	"time"

	"sigsum.org/sigsum-go/cmd/sigsum-debug/head/sign"
	"sigsum.org/sigsum-go/internal/options"
)

const usage = `
sigsum-debug head signs and verifies tree heads.

Usage:

  sigsum-debug head help
    Outputs a usage message

  sigsum-debug head sign -k PRIVATE_KEY -h KEY_HASH [-t TIMESTAMP]
    Reads an ascii signed tree head from stdin and outputs a new signature
`

var (
	optPrivateKey, optKeyHash string
	optTimestamp              uint64
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
			err = sign.Main(opt.Args(), optPrivateKey, optKeyHash, optTimestamp)
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
		options.AddUint64(fs, &optTimestamp, "t", "timestamp", uint64(time.Now().Unix()))
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
	}

	return err
}
