package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/pborman/getopt/v2"

	"sigsum.org/sigsum-go/internal/ui"
	"sigsum.org/sigsum-go/internal/version"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/types"
)

type listSettings struct {
}

type showSettings struct {
	policyName string
}

type checkSettings struct {
	policyFile, policyName string
}

func main() {
	const usage = `
Manage builtin sigsum policies.

Usage: sigsum-policy [--help|help] [--version|version]
   or: sigsum-policy list
   or: sigsum-policy show name
   or: sigsum-policy check -p file | -P name
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
		// There are no settings for the list command yet, but
		// the settings.parse function can display a help message
		var settings listSettings
		settings.parse(os.Args)
		for _, name := range policy.List() {
			fmt.Println(name)
		}
	case "show":
		var settings showSettings
		settings.parse(os.Args)
		policy, err := policy.ReadByName(settings.policyName)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := os.Stdout.Write(policy); err != nil {
			log.Fatal(err)
		}
	case "check":
		var settings checkSettings
		settings.parse(os.Args)
		policy, err := ui.SelectPolicy(ui.PolicyParams{
			File: settings.policyFile,
			Name: settings.policyName})
		if err != nil {
			log.Fatal(err)
		}
		allOk := true
		// Reconstruct mapping.
		witnesses := make(map[crypto.Hash]crypto.PublicKey)
		for _, w := range policy.GetWitnesses() {
			witnesses[crypto.HashBytes(w.PublicKey[:])] = w.PublicKey
		}

		for _, l := range policy.GetLogs() {
			if len(l.URL) == 0 {
				log.Printf("Missing URL for log key %x", l.PublicKey)
				allOk = false
				continue
			}
			log.Printf("Checking log %q", l.URL)
			origin := types.SigsumCheckpointOrigin(&l.PublicKey)
			cli := client.New(client.Config{
				UserAgent: "sigsum-policy",
				URL:       l.URL,
			})
			cth, err := cli.GetTreeHead(context.Background())
			if err != nil {
				log.Printf("Log failed: %v", err)
				allOk = false
				continue
			}
			if !cth.Verify(&l.PublicKey) {
				log.Printf("Log %q signature invalid", l.URL)
				allOk = false
				continue
			}
			log.Printf("%d cosignatures", len(cth.Cosignatures))
			count := 0
			for kh, key := range witnesses {
				cs, ok := cth.Cosignatures[kh]
				if !ok {
					log.Printf("Missing cosignature for witness %x on log %q", key, l.URL)
					allOk = false
					continue
				}
				if !cs.Verify(&key, origin, &cth.TreeHead) {
					log.Printf("Invalid cosignature for witness %x (kh %s) on log %q", key, kh, l.URL)
					allOk = false
					continue
				}
				count++
			}
			log.Printf("%d valid cosignatures found", count)
		}
		if !allOk {
			os.Exit(1)
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
func parse(set *getopt.Set, args []string, usage string) []string {
	help := false
	set.FlagLong(&help, "help", 0, "Display help")
	err := set.Getopt(args[1:], nil)
	// Check help first; if seen, ignore errors about missing mandatory arguments.
	if help {
		fmt.Print(usage + "\n\n")
		set.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if err != nil {
		log.Printf("err: %v\n", err)
		set.PrintUsage(log.Writer())
		os.Exit(1)
	}
	return set.Args()
}

func (s *listSettings) parse(args []string) {
	set := newOptionSet(args, "")
	finalArgs := parse(set, args, `List available named policies.`)
	if len(finalArgs) > 0 {
		log.Fatal("Too many arguments.")
	}
}

func (s *showSettings) parse(args []string) {
	set := newOptionSet(args, "name")
	finalArgs := parse(set, args, `Show contents of given named policy.`)
	if len(finalArgs) < 1 {
		log.Fatal("Missing argument: name")
	}
	if len(finalArgs) > 1 {
		log.Fatal("Too many arguments.")
	}
	s.policyName = finalArgs[0]
}

func (s *checkSettings) parse(args []string) {
	set := newOptionSet(args, "")
	set.FlagLong(&s.policyFile, "policy", 'p', "Trust policy file defining logs, witnesses, and a quorum rule", "policy-file")
	set.FlagLong(&s.policyName, "named-policy", 'P', "Use a named trust policy defining logs, witnesses, and a quorum rule", "policy-name")
	args = parse(set, args, `Check that logs and witnesses in a policy are online.`)
	if len(s.policyName) > 0 && len(s.policyFile) > 0 {
		log.Fatal("The -P (--named-policy) and -p (--policy) options are mutually exclusive.")
	}

	if len(args) > 0 {
		log.Fatal("Too many arguments.")
	}
}
