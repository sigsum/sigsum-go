package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pborman/getopt/v2"

	"sigsum.org/sigsum-go/internal/version"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/monitor"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/types"
)

type Settings struct {
	policyFile  string
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
	policy, err := policy.ReadPolicyFile(settings.policyFile)
	if err != nil {
		log.Fatal("failed to create policy: %v", err)
	}
	config := monitor.Config{
		QueryInterval: settings.interval,
		Callbacks:     callbacks{},
	}
	if len(settings.keys) > 0 {
		config.SubmitKeys = make(map[crypto.Hash]crypto.PublicKey)
		for _, f := range settings.keys {
			pub, err := key.ReadPublicKeyFile(f)
			if err != nil {
				log.Fatal("Failed reading key: %v", err)
			}
			config.SubmitKeys[crypto.HashBytes(pub[:])] = pub
		}
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

	set.FlagLong(&s.policyFile, "policy", 'p', "Trust policy defining logs, witnesses, and the end-user's quorum rule", "policy-file").Mandatory()
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

	if err != nil {
		fmt.Printf("err: %v\n", err)
		set.PrintUsage(os.Stderr)
		os.Exit(1)
	}
	s.keys = set.Args()
}
