package leaf

import (
	"flag"
	"fmt"
	"log"

	"sigsum.org/sigsum-go/cmd/sigsum-debug/leaf/hash"
	"sigsum.org/sigsum-go/cmd/sigsum-debug/leaf/inclusion"
	"sigsum.org/sigsum-go/cmd/sigsum-debug/leaf/sign"
	"sigsum.org/sigsum-go/cmd/sigsum-debug/leaf/verify"
	"sigsum.org/sigsum-go/internal/options"
)

const usage = `
sigsum-debug leaf signs, verifies, and hashes Merkle tree leaves.

Usage:

  sigsum-debug leaf help
    Outputs a usage message

  sigsum-debug leaf sign -k PRIVATE_KEY -h SHARD_HINT
    Reads data from stdin and outputs a signature

  sigsum-debug leaf verify -k PUBLIC_KEY -s SIGNATURE -h SHARD_HINT
    Reads data from stdin and verifies its signature

  sigsum-debug leaf hash -k KEY_HASH -s SIGNATURE -h SHARD_HINT
    Reads data from stdin and outputs a leaf hash

  sigsum-debug leaf inclusion -l LEAF_HASH -n TREE_SIZE -r ROOT_HASH
    Reads an inclusion proof from stdin and verifies it

`

var (
	optPrivateKey, optPublicKey, optKeyHash, optLeafHash, optRootHash, optSignature string
	optShardHint, optSize                                                       uint64
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
			err = sign.Main(opt.Args(), optPrivateKey, optShardHint)
		case "verify":
			err = verify.Main(opt.Args(), optPublicKey, optSignature, optShardHint)
		case "hash":
			err = hash.Main(opt.Args(), optKeyHash, optSignature, optShardHint)
		case "inclusion":
			err = inclusion.Main(opt.Args(), optLeafHash, optRootHash, optSize)
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
	case "verify":
		options.AddString(fs, &optPublicKey, "k", "public-key", options.DefaultString)
		options.AddString(fs, &optSignature, "s", "signature", options.DefaultString)
	case "hash":
		options.AddString(fs, &optKeyHash, "k", "key-hash", options.DefaultString)
		options.AddString(fs, &optSignature, "s", "signature", options.DefaultString)
	case "inclusion":
		options.AddString(fs, &optLeafHash, "l", "leaf-hash", options.DefaultString)
		options.AddUint64(fs, &optSize, "n", "size", options.DefaultUint64)
		options.AddString(fs, &optRootHash, "r", "root-hash", options.DefaultString)
	}
}

// checkOptions checks that options with required arguments were set
func checkOptions(cmd string) error {
	var err error

	switch cmd {
	case "help":
	case "sign":
		err = options.CheckString("private key", optPrivateKey, err)
	case "verify":
		err = options.CheckString("public key", optPublicKey, err)
		err = options.CheckString("signature", optSignature, err)
	case "hash":
		err = options.CheckString("key hash", optKeyHash, err)
		err = options.CheckString("signature", optSignature, err)
	case "inclusion":
		err = options.CheckString("leaf hash", optLeafHash, err)
		err = options.CheckUint64("size", optSize, err)
		err = options.CheckString("root hash", optRootHash, err)
	}

	return err
}
