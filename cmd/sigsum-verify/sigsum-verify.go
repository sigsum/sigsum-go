package main

import (
	"fmt"
	"io"
	"log"
	"os"

	getopt "github.com/pborman/getopt/v2"

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
	const usage = `sigsum-verify [OPTIONS] PROOF < INPUT
    Options:
      -h --help Display this help
      --submit-key SUBMIT-KEY
      --policy POLICY-FILE
      --raw-hash

    Verifies a sigsum proof, as produced by sigsum-submit. Proof file
    specified on command line, data being verified is the hash of the
    data on stdin (or if --raw-hash is given, input is the hash value,
    of size exactly 32 octets).
`
	log.SetFlags(0)
	var settings Settings
	settings.parse(os.Args, usage)
	submitKey, err := key.ReadPublicKeyFile(settings.submitKey)
	if err != nil {
		log.Fatal(err)
	}
	msg := readMessage(os.Stdin, settings.rawHash)

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
	if err := pr.Verify(&msg, &submitKey, policy); err != nil {
		log.Fatalf("sigsum proof failed to verify: %v", err)
	}
}

func (s *Settings) parse(args []string, usage string) {
	set := getopt.New()
	set.SetParameters("")
	set.SetUsage(func() { fmt.Print(usage) })

	help := false
	set.FlagLong(&s.rawHash, "raw-hash", 0, "Use raw hash input")
	set.FlagLong(&s.submitKey, "submit-key", 0, "Public key file").Mandatory()
	set.FlagLong(&s.policyFile, "policy", 0, "Policy file").Mandatory()
	set.FlagLong(&help, "help", 0, "Display help")
	err := set.Getopt(args, nil)
	// Check help first; if seen, ignore errors about missing mandatory arguments.
	if help {
		// TODO: Let getopt package list options, and append further details.
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

func readMessage(r io.Reader, rawHash bool) crypto.Hash {
	readHash := func(r io.Reader) (ret crypto.Hash) {
		// One extra byte, to detect EOF.
		msg := make([]byte, 33)
		if readCount, err := io.ReadFull(os.Stdin, msg); err != io.ErrUnexpectedEOF || readCount != 32 {
			if err != nil && err != io.ErrUnexpectedEOF {
				log.Fatalf("reading message from stdin failed: %v", err)
			}
			log.Fatalf("sigsum message must be exactly 32 bytes, got %d", readCount)
		}
		copy(ret[:], msg)
		return
	}
	if rawHash {
		return readHash(r)
	}
	msg, err := crypto.HashFile(r)
	if err != nil {
		log.Fatal(err)
	}
	return msg
}
