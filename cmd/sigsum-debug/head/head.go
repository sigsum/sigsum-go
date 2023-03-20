package head

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	getopt "github.com/pborman/getopt/v2"

	"sigsum.org/sigsum-go/cmd/sigsum-debug/head/sign"
)

const usage = `
sigsum-debug head signs and verifies tree heads.

Usage:

  sigsum-debug head help
    Outputs a usage message

  sigsum-debug head sign -k PRIVATE_KEY -h KEY_HASH [-t TIMESTAMP]
    Reads an ascii signed tree head from stdin and outputs a new signature
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
	case "help", "":
		set.PrintUsage(os.Stdout)
		return nil
	case "sign":
		var optPrivateKey, optKeyHash string
		optTimestamp := uint64(time.Now().Unix())
		set.Flag(&optPrivateKey, 'k', "Private key").Mandatory()
		set.Flag(&optKeyHash, 'h', "Key hash").Mandatory()
		set.Flag(&optTimestamp, 't', "timestamp")
		set.Parse(args[2:])
		if set.NArgs() > 0 {
			return fmt.Errorf("trailing arguments: %s", strings.Join(set.Args(), ", "))
		}
		err = sign.Main(optPrivateKey, optKeyHash, optTimestamp)
	default:
		err = fmt.Errorf("invalid command %q, try \"help\"", args[2])
	}

	if err != nil {
		err = fmt.Errorf(" %s: %w", args[2], err)
	}

	return err
}
