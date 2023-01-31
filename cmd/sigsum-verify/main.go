package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/types"
)

type Settings struct {
	proofFile string
	submitKey string
	logKey    string
}

func main() {
	const usage = `sigsum-verify [OPTIONS] PROOF < MESSAGE
    Options:
      -h --help Display this help
      --submit-key SUBMIT-KEY
      --log-key LOG-KEY

    Verifies a sigsum proof, as produced by sigsum-log. Proof file specified on command line,
    data being verified read from stdin.
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

	// TODO: Optionally create message by hashing stdin.
	msg := readMessage(os.Stdin)

	// TODO: Could use a variant of ascii.Parser that treats empty line as EOF.
	proof, err := os.ReadFile(settings.proofFile)
	if err != nil {
		log.Fatalf("reading proof file %q failed: %v", settings.proofFile, err)
	}
	proofParts := bytes.Split(proof, []byte{'\n', '\n'})
	if len(proofParts) < 3 {
		log.Fatal("invalid proof, too few parts")
	}
	checkProofHeader(proofParts[0], &logKey)
	leafHash := checkProofLeaf(proofParts[1], msg[:], &submitKey)
	var cth types.CosignedTreeHead
	if err := cth.FromASCII(bytes.NewBuffer(proofParts[2])); err != nil {
		log.Fatalf("failed to parse cosigned tree head: %v", err)
	}
	if !cth.Verify(&logKey) {
		log.Fatal("invalid log signature on tree head")
	}
	// TODO: Check cosignatures, process timestamp?

	if cth.Size == 0 {
		log.Fatal("empty tree")
	}
	if cth.Size == 1 {
		if len(proofParts) != 3 {
			log.Fatal("invalid proof, unexpected inclusion part for tree_size 1")
		}
		if cth.RootHash != leafHash {
			log.Fatal("inclusion check failed (for tree_size 1)")
		}
		return
	}
	if len(proofParts) != 4 {
		log.Fatalf("invalid proof, got %d parts, need 4", len(proofParts))
	}
	var inclusion types.InclusionProof
	if err := inclusion.FromASCII(bytes.NewBuffer(proofParts[3]), cth.Size); err != nil {
		log.Fatalf("failed to parse inclusion proof: %v", err)
	}
	if err := merkle.VerifyInclusion(&leafHash, inclusion.LeafIndex, cth.Size, &cth.RootHash, inclusion.Path); err != nil {
		log.Fatalf("inclusion proof invalid: %v", err)
	}
}

func (s *Settings) parse(args []string, usage string) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.Usage = func() { fmt.Print(usage) }

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

func readMessage(r io.Reader) (ret crypto.Hash) {
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

func checkProofHeader(header []byte, logKey *crypto.PublicKey) {
	p := ascii.NewParser(bytes.NewBuffer(header))
	if version, err := p.GetInt("version"); err != nil || version != 0 {
		if err != nil {
			log.Fatalf("invalid version line: %v", err)
		}
		log.Fatalf("unexpected version %d, wanted 0", version)
	}
	if hash, err := p.GetHash("log"); err != nil || hash != crypto.HashBytes(logKey[:]) {
		if err != nil {
			log.Fatalf("invalid log line: %v", err)
		}
		log.Fatalf("proof doesn't match log's public key")
	}
	if err := p.GetEOF(); err != nil {
		log.Fatalf("invalid proof header: %v", err)
	}

}

// On success, returns the leaf hash.
func checkProofLeaf(leaf []byte, msg []byte, submitKey *crypto.PublicKey) crypto.Hash {
	p := ascii.NewParser(bytes.NewBuffer(leaf))
	values, err := p.GetValues("leaf", 2)
	if err != nil {
		log.Fatalf("invalid leaf line: %v", err)
	}
	keyHash, err := crypto.HashFromHex(values[0])
	if err != nil || keyHash != crypto.HashBytes(submitKey[:]) {
		log.Fatalf("unexpected leaf key hash: %q", values[0])
	}
	signature, err := crypto.SignatureFromHex(values[1])
	if err != nil {
		log.Fatalf("failed to parse signature: %v", err)
	}
	if !types.VerifyLeafMessage(submitKey, msg, &signature) {
		log.Fatalf("leaf signature not valid")
	}
	return merkle.HashLeafNode((&types.Leaf{
		Checksum:  crypto.HashBytes(msg[:]),
		KeyHash:   keyHash,
		Signature: signature,
	}).ToBinary())
}
