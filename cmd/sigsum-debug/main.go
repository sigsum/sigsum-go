// package main provides a tool named sigsum-debug
//
// Install:
//
//     $ go install git.sigsum.org/sigsum-go/cmd/sigsum-debug@latest
//
// Usage:
//
//     $ sigsum-debug help
//
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"git.sigsum.org/sigsum-go/cmd/sigsum-debug/head"
	"git.sigsum.org/sigsum-go/cmd/sigsum-debug/key"
	"git.sigsum.org/sigsum-go/cmd/sigsum-debug/leaf"
	"git.sigsum.org/sigsum-go/cmd/sigsum-debug/spam"
	"git.sigsum.org/sigsum-go/internal/options"
)

const usage = `
sigsum-debug is a tool that helps debug sigsum logs on the command-line

Usage:

  sigsum-debug help  Usage message
  sigsum-debug key   Private and public key utilities
  sigsum-debug leaf  Hash, sign, and verify tree leaves
  sigsum-debug head  Sign and verify tree heads
  sigsum-debug spam  Send many requests to a sigsum log

`

func main() {
	var err error

	log.SetFlags(0)
	opt := options.New(os.Args[1:], func() { log.Printf(usage[1:]) }, func(_ *flag.FlagSet) {})
	switch opt.Name() {
	case "help", "":
		opt.Usage()
	case "key":
		err = key.Main(opt.Args())
	case "leaf":
		err = leaf.Main(opt.Args())
	case "head":
		err = head.Main(opt.Args())
	case "spam":
		err = spam.Main(opt.Args())
	default:
		err = fmt.Errorf(": invalid command %q, try \"help\"", opt.Name())
	}

	if err != nil {
		format := "sigsum-debug %s%s"
		if len(opt.Name()) == 0 {
			format = "sigsum-debug%s%s"
		}

		log.Printf(format, opt.Name(), err.Error())
		os.Exit(1)
	}
}
