package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/pborman/getopt/v2"

	"sigsum.org/sigsum-go/internal/version"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
)

type Settings struct {
	rawHash    bool
	proofFile  string
	submitKey  string
	policyFile string
}

func main() {
	log.SetFlags(0)
	var settings Settings
	settings.parse(os.Args)
	submitKeys, err := key.ReadPublicKeysFile(settings.submitKey)
	if err != nil {
		log.Fatal(err)
	}
	msg, err := readMessage(os.Stdin, settings.rawHash)
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.Open(settings.proofFile)
	if err != nil {
		log.Fatalf("opening file %q failed: %v", settings.proofFile, err)
	}
	var pr proof.SigsumProof
	if err := pr.FromASCII(f); err != nil {
		log.Fatalf("invalid proof: %v", err)
	}
	policy, err := policy.ReadPolicyFile(settings.policyFile)
	if err != nil {
		log.Fatalf("failed to create policy: %v", err)
	}
	if err := pr.Verify(&msg, submitKeys, policy); err != nil {
		log.Fatalf("sigsum proof failed to verify: %v", err)
	}
}

func (s *Settings) parse(args []string) {
	const usage = `
Verify that a message's signed checksum is logged for a given trust
policy.  The message to be verified is read on stdin.
`
	set := getopt.New()
	set.SetParameters("proof-file < input")

	help := false
	versionFlag := false
	set.FlagLong(&s.rawHash, "raw-hash", 0, "Input has already been hashed and formatted as 32 octets or a hex string")
	set.FlagLong(&s.submitKey, "key", 'k', "Submitter public keys, one per line in OpenSSH format", "key-file").Mandatory()
	set.FlagLong(&s.policyFile, "policy", 'p', "Trust policy defining logs, witnesses, and a quorum rule", "policy-file").Mandatory()
	set.FlagLong(&help, "help", 0, "Show usage message and exit")
	set.FlagLong(&versionFlag, "version", 'v', "Show software version and exit")
	err := set.Getopt(args, nil)
	// Check --help and --version first; if seen, ignore errors
	// about missing mandatory arguments.
	if help {
		fmt.Print(usage[1:] + "\n")
		set.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if versionFlag {
		version.DisplayVersion("sigsum-verify")
		os.Exit(0)
	}
	if err != nil {
		fmt.Printf("err: %v\n", err)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
	if set.NArgs() != 1 {
		log.Fatalf("no proof given on command line")
	}
	s.proofFile = set.Arg(0)
}

func readMessage(r io.Reader, rawHash bool) (crypto.Hash, error) {
	if !rawHash {
		return crypto.HashFile(r)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return crypto.Hash{}, err
	}
	if len(data) == crypto.HashSize {
		var msg crypto.Hash
		copy(msg[:], data)
		return msg, nil
	}
	return crypto.HashFromHex(strings.TrimSpace(string(data)))
}
