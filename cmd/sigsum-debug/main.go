// package main provides a tool named sigsum-debug
//
// Install:
//
//	$ go install sigsum.org/sigsum-go/cmd/sigsum-debug@latest
//
// Usage:
//
//	$ sigsum-debug help
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"sigsum.org/sigsum-go/cmd/sigsum-debug/head"
	"sigsum.org/sigsum-go/cmd/sigsum-debug/leaf"
	"sigsum.org/sigsum-go/internal/options"
)

const usage = `
sigsum-debug is a tool that helps debug sigsum logs on the command-line.
It is meant to be used in conjuction with other utilities such as curl.

Usage:

  sigsum-debug help  Usage message
  sigsum-debug leaf  Hash, sign, and verify tree leaves
  sigsum-debug head  Sign and verify tree heads

`

func main() {
	var err error

	log.SetFlags(0)
	opt := options.New(os.Args[1:], func() { log.Printf(usage[1:]) }, func(_ *flag.FlagSet) {})
	switch opt.Name() {
	case "help", "":
		opt.Usage()
	case "leaf":
		err = leaf.Main(opt.Args())
	case "head":
		err = head.Main(opt.Args())
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
