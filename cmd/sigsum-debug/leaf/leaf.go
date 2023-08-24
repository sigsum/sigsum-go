package leaf

import (
	"fmt"
	"log"
	"strings"

	"github.com/pborman/getopt/v2"

	"sigsum.org/sigsum-go/cmd/sigsum-debug/leaf/hash"
	"sigsum.org/sigsum-go/cmd/sigsum-debug/leaf/sign"
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

func Main(args []string) error {
	var err error

	if len(args) < 3 {
		log.Fatal(usage)
	}
	set := getopt.New()
	set.SetUsage(func() { log.Printf(usage[1:]) })
	set.SetParameters("")

	switch args[2] {
	case "help", "--help":
		fmt.Print(usage[1:])
		return nil
	case "sign":
		var optPrivateKey string
		set.Flag(&optPrivateKey, 'k', "private-key").Mandatory()
		set.Parse(args[2:])
		if set.NArgs() > 0 {
			return fmt.Errorf("trailing arguments: %s", strings.Join(set.Args(), ", "))
		}
		err = sign.Main(optPrivateKey)
	case "hash":
		var optKeyHash, optSignature string
		set.Flag(&optKeyHash, 'k', "key-hash").Mandatory()
		set.Flag(&optSignature, 's', "signature").Mandatory()
		set.Parse(args[2:])
		if set.NArgs() > 0 {
			return fmt.Errorf("trailing arguments: %s", strings.Join(set.Args(), ", "))
		}
		err = hash.Main(optKeyHash, optSignature)
	}
	if err != nil {
		err = fmt.Errorf(" %s: %w", args[2], err)
	}

	return err
}
