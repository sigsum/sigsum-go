package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/proof"
)

type Settings struct {
	rawHash   bool
	proofFile string
	submitKey string
	logKey    string
}

func main() {
	const usage = `sigsum-verify [OPTIONS] PROOF < INPUT
    Options:
      -h --help Display this help
      --submit-key SUBMIT-KEY
      --log-key LOG-KEY
      --raw-hash

    Verifies a sigsum proof, as produced by sigsum-log. Proof file
    specified on command line, data being verified is the hash of the
    data on stdin (or if --raw-hash is given, input is the hash value,
    of size exactly 32 octets).
`
	log.SetFlags(0)
	var settings Settings
	settings.parse(os.Args[1:], usage)
	submitKey, err := key.ReadPublicKeyFile(settings.submitKey)
	if err != nil {
		log.Fatal(err)
	}
	logKey, err := key.ReadPublicKeyFile(settings.logKey)
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
	if err := pr.VerifyNoCosignatures(&msg, &submitKey, &logKey); err != nil {
		log.Fatalf("sigsum proof failed to verify: %v", err)
	}
}

func (s *Settings) parse(args []string, usage string) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.Usage = func() { fmt.Print(usage) }

	flags.BoolVar(&s.rawHash, "raw-hash", false, "Use raw hash input")
	flags.StringVar(&s.submitKey, "submit-key", "", "Public key file")
	flags.StringVar(&s.logKey, "log-key", "", "Public key file for log")

	flags.Parse(args)
	if flags.NArg() != 1 {
		log.Fatalf("no proof given on command line")
	}
	s.proofFile = flags.Arg(0)
	if len(s.submitKey) == 0 {
		log.Fatalf("--submit-key argument is required")
	}
	if len(s.logKey) == 0 {
		log.Fatalf("--log-key argument is required")
	}
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
