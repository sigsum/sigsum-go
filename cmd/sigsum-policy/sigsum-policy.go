package main

import (
	"fmt"
	"log"
	"os"

	"github.com/pborman/getopt/v2"

	"sigsum.org/sigsum-go/internal/version"
	"sigsum.org/sigsum-go/pkg/policy"
)

type listSettings struct {
}

type showSettings struct {
	policyName string
}

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
		// There are no settings for the list command yet, but the settings.parse function can display a help message
		var settings listSettings
		settings.parse(os.Args)
		for _, name := range policy.BuiltinList() {
			fmt.Println(name)
		}
	case "show":
		var settings showSettings
		settings.parse(os.Args)
		policy, err := policy.BuiltinRead(settings.policyName)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := os.Stdout.Write(policy); err != nil {
			log.Fatal(err)
		}

	}
}

func newOptionSet(args []string, parameters string) *getopt.Set {
	set := getopt.New()
	set.SetProgram(os.Args[0] + " " + os.Args[1])
	set.SetParameters(parameters)
	return set
}

// Also adds and processes the help option.
func parseNoArgs(set *getopt.Set, args []string, usage string) {
	help := false
	set.FlagLong(&help, "help", 0, "Display help")
	err := set.Getopt(args[1:], nil)
	// Check help first; if seen, ignore errors about missing mandatory arguments.
	if help {
		fmt.Print(usage[1:] + "\n")
		set.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if err != nil {
		log.Printf("err: %v\n", err)
		set.PrintUsage(log.Writer())
		os.Exit(1)
	}
	if set.NArgs() > 0 {
		log.Fatal("Too many arguments.")
	}
}

func (s *listSettings) parse(args []string) {
	set := newOptionSet(args, "")
	parseNoArgs(set, args, `
List available named policies.
`)
}

func (s *showSettings) parse(args []string) {
	set := newOptionSet(args, "name")
	help := false
	set.FlagLong(&help, "help", 0, "Display help")
	set.Parse(args[1:])
	if help {
		fmt.Print("Show contents of given named policy.\n\n")
		set.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if set.NArgs() < 1 {
		log.Fatal("Missing argument: name")
	}
	if set.NArgs() > 1 {
		log.Fatal("Too many arguments.")
	}
	s.policyName = set.Args()[0]
}
