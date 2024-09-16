package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/pborman/getopt/v2"

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
    Verifies a sigsum proof, as produced by sigsum-submit. The proof
    file is passed on the command line. The message being verified is
    the hash of the data on stdin (or if --raw-hash is given, input is
    the hash value, either exactly 32 octets, or a hex string).
`
	set := getopt.New()
	set.SetParameters("proof < input")

	help := false
	set.FlagLong(&s.rawHash, "raw-hash", 0, "Input is already hashed")
	set.FlagLong(&s.submitKey, "key", 'k', "Submitter public key(s) ", "file").Mandatory()
	set.FlagLong(&s.policyFile, "policy", 'p', "Sigsum policy", "file").Mandatory()
	set.FlagLong(&help, "help", 0, "Display help")
	err := set.Getopt(args, nil)
	// Check help first; if seen, ignore errors about missing mandatory arguments.
	if help {
		set.PrintUsage(os.Stdout)
		fmt.Print(usage)
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
