package main

import (
	"fmt"
	"log"
	"os"

	"sigsum.org/sigsum-go/internal/version"
	"sigsum.org/sigsum-go/pkg/policy"
)

func main() {
	const usage = `
Manage builtin sigsum policies.

Usage: sigsum-policy [--help|help] [--version|version]
   or: sigsum-policy list
   or: sigsum-policy show name
`
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal(usage[1:])
	}

	switch os.Args[1] {
	default:
		log.Fatal(usage[1:])
	case "help", "--help":
		fmt.Print(usage[1:])
		os.Exit(0)
	case "version", "--version", "-v":
		version.DisplayVersion("sigsum-policy")
		os.Exit(0)
	case "list":
		if len(os.Args) != 2 {
			log.Fatal(usage[1:])
		}
		for _, name := range policy.BuiltinList() {
			fmt.Println(name)
		}
	case "show":
		if len(os.Args) != 3 {
			log.Fatal(usage[1:])
		}
		policy, err := policy.BuiltinRead(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		if _, err := os.Stdout.Write(policy); err != nil {
			log.Fatal(err)
		}

	}
}
