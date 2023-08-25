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
	"fmt"
	"log"
	"os"

	"sigsum.org/sigsum-go/cmd/sigsum-debug/leaf"
)

const usage = `
sigsum-debug is a tool that helps debug sigsum logs on the command-line.
It is meant to be used in conjuction with other utilities such as curl.

Usage:

  sigsum-debug help  Usage message
  sigsum-debug leaf  Hash, sign, and verify tree leaves

`

func main() {
	var err error

	log.SetFlags(0)

	if len(os.Args) < 2 {
		log.Fatal(usage)
	}

	switch os.Args[1] {
	case "help", "--help":
		fmt.Print(usage)
		os.Exit(0)
	case "leaf":
		err = leaf.Main(os.Args)
	default:
		err = fmt.Errorf(": invalid command %q, try \"help\"", os.Args[1])
	}

	if err != nil {
		log.Printf("sigsum-debug %s%s", os.Args[1], err.Error())
		os.Exit(1)
	}
}
