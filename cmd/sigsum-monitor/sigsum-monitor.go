package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pborman/getopt/v2"

	"sigsum.org/sigsum-go/internal/ui"
	"sigsum.org/sigsum-go/internal/version"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/monitor"
	"sigsum.org/sigsum-go/pkg/types"
)

type Settings struct {
	policyFile  string
	policyName  string
	keys        []string
	diagnostics string
	interval    time.Duration
}

type callbacks struct{}

func (_ callbacks) NewTreeHead(logKeyHash crypto.Hash, signedTreeHead types.SignedTreeHead) {
	fmt.Printf("New %x tree, size %d\n", logKeyHash, signedTreeHead.Size)
}

func (_ callbacks) NewLeaves(logKeyHash crypto.Hash, numberOfProcessedLeaves uint64, indices []uint64, leaves []types.Leaf) {
	fmt.Printf("New %x leaves, count %d, total processed %d\n", logKeyHash, len(leaves), numberOfProcessedLeaves)
	for i, l := range leaves {
		fmt.Printf("  index %d keyhash %x checksum %x\n", indices[i], l.KeyHash, l.Checksum)
	}
}

func (_ callbacks) Alert(logKeyHash crypto.Hash, e error) {
	log.Fatal("Alert log %x: %v\n", logKeyHash, e)
}

func main() {
	var settings Settings
	settings.parse(os.Args)
	if err := log.SetLevelFromString(settings.diagnostics); err != nil {
		log.Fatal("%v", err)
	}
	config := monitor.Config{
		QueryInterval: settings.interval,
		Callbacks:     callbacks{},
	}
	var policyNamesFromPubKeys []string
	if len(settings.keys) > 0 {
		config.SubmitKeys = make(map[crypto.Hash]crypto.PublicKey)
		for _, f := range settings.keys {
			pub, policyName, err := key.ReadPublicKeyFileWithPolicyName(f)
			if err != nil {
				log.Fatal("Failed reading key: %v", err)
			}
			config.SubmitKeys[crypto.HashBytes(pub[:])] = pub
			policyNamesFromPubKeys = append(policyNamesFromPubKeys, policyName)
		}
	}
	// Require all names in policyNamesFromPubKeys to be identical
	policyNameFromPubKeys := policyNamesFromPubKeys[0]
	for _, name := range policyNamesFromPubKeys {
		if name != policyNameFromPubKeys {
			log.Fatal("Conflicting policy names found in pubkeys: '%q' != '%q'", name, policyNameFromPubKeys)
		}
	}
	policy, err := ui.SelectPolicy(settings.policyFile, settings.policyName, policyNameFromPubKeys)
	if err != nil {
		log.Fatal("Failed to select policy: %v", err)
	}
	if policy == nil {
		log.Fatal("A policy must be specified, either in pubkey file or using -p or -P")
	}
	// TODO: Read state from disk. Also store the list of submit
	// keys, and discard state if keys are added, since whenever
	// new keys are added, the log must be rescanned from the
	// start.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	done := monitor.StartMonitoring(ctx, policy, &config, nil)
	<-done
}

func (s *Settings) parse(args []string) {
	const usage = `
Discover signed checksums for public keys in OpenSSH format.

Be warned: this is a work-in-progress implementation.  Witness
cosignatures are not verified and no state is kept between runs.
`

	set := getopt.New()
	set.SetParameters("key-files")

	help := false
	versionFlag := false
	s.diagnostics = "info"
	s.interval = 10 * time.Minute

	set.FlagLong(&s.policyFile, "policy", 'p', "Trust policy file defining logs, witnesses, and the end-user's quorum rule", "policy-file")
	set.FlagLong(&s.policyName, "named-policy", 'P', "Use a named trust policy defining logs, witnesses, and the end-user's quorum rule", "policy-name")
	set.FlagLong(&s.interval, "interval", 'i', "How often to fetch the latest entries", "interval")
	set.FlagLong(&s.diagnostics, "diagnostics", 0, "Available levels: fatal, error, warning, info, debug", "log-level")
	set.FlagLong(&help, "help", 0, "Show usage message and exit")
	set.FlagLong(&versionFlag, "version", 'v', "Show program version and exit")
	err := set.Getopt(args, nil)
	// Check --help and --version first; if seen, ignore errors
	// about missing mandatory arguments.
	if help {
		fmt.Print(usage[1:] + "\n")
		set.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if versionFlag {
		version.DisplayVersion("sigsum-monitor")
		os.Exit(0)
	}
	if len(s.policyName) > 0 && len(s.policyFile) > 0 {
		log.Fatal("The -P (--named-policy) and -p (--policy) options are mutually exclusive.")
	}

	if err != nil {
		fmt.Printf("err: %v\n", err)
		set.PrintUsage(os.Stderr)
		os.Exit(1)
	}
	s.keys = set.Args()
}
