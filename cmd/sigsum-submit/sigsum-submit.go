package main

import (
	"context"
	"fmt"
	"io"
	"os"

	getopt "github.com/pborman/getopt/v2"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/submit"
	"sigsum.org/sigsum-go/pkg/types"
)

type Settings struct {
	rawHash     bool
	keyFile     string
	policyFile  string
	diagnostics string
	outputFile  string
}

func main() {
	const usage = `sigsum-submit [OPTIONS] < INPUT
    Options:
      -h --help Display this help
      -k PRIVATE-KEY-FILE
      --policy POLICY-FILE
      --diagnostics LEVEL
      --raw-hash
      -o OUTPUT-FILE
    Creates and/or submits an add-leaf request.

    If -k PRIVATE-KEY-FILE is provided, a new request is created based on
    the SHA256 hash of INPUT (or, if --raw-hash is provided, INPUT is
    treated as the hash value to be used, exactly 32 octets long).

    If the -k option is missing, INPUT should instead be the body of an
    add-leaf request, which is then parsed and verified.

    If --policy is provided, the request is submitted to some log
    specified by the policy, and a Sigsum proof is collected and
    written to stdout. If there are multiple logs in the policy, they are
    be tried in randomized order.

    With -k but without --policy, the add-leaf request created is
    written to stdout. With no -k and no --policy, the request syntax
    and signature in INPUT are verified.

    The --diagnostics option specifies level of diagnostig messages,
    one of "fatal", "error", "warning", "info" (default), or "debug".

    If no output file is provided with the -o option, output is sent to stdout.
`
	var settings Settings
	settings.parse(os.Args, usage)
	if len(settings.diagnostics) > 0 {
		if err := log.SetLevelFromString(settings.diagnostics); err != nil {
			log.Fatal("%v", err)
		}
	}
	var leaf requests.Leaf
	if len(settings.keyFile) > 0 {
		signer, err := key.ReadPrivateKeyFile(settings.keyFile)
		if err != nil {
			log.Fatal("%v", err)
		}
		publicKey := signer.Public()

		msg := readMessage(os.Stdin, settings.rawHash)

		signature, err := types.SignLeafMessage(signer, msg[:])
		if err != nil {
			log.Fatal("signing failed: %v", err)
		}
		leaf = requests.Leaf{Message: msg, Signature: signature, PublicKey: publicKey}

		if len(settings.policyFile) == 0 {
			file := os.Stdout
			if len(settings.outputFile) > 0 {
				var err error
				file, err = os.OpenFile(settings.outputFile,
					os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
				if err != nil {
					log.Fatal("failed to open file '%v': %v", settings.outputFile, err)
				}
				defer file.Close()
			}
			if err := leaf.ToASCII(file); err != nil {
				log.Fatal("writing leaf to stdout failed: %v", err)
			}
			return
		}
	} else {
		if err := leaf.FromASCII(os.Stdin); err != nil {
			log.Fatal("parsing leaf request failed: %v", err)
		}
		if !types.VerifyLeafMessage(&leaf.PublicKey, leaf.Message[:], &leaf.Signature) {
			log.Fatal("invalid leaf signature")
		}
	}
	if len(settings.policyFile) > 0 {
		policy, err := policy.ReadPolicyFile(settings.policyFile)
		if err != nil {
			log.Fatal("%v", err)
		}
		proof, err := submit.SubmitLeafRequest(context.Background(), &submit.Config{Policy: policy}, &leaf)
		if err != nil {
			log.Fatal("%v", err)
		}
		file := os.Stdout
		if len(settings.outputFile) > 0 {
			var err error
			file, err = os.OpenFile(settings.outputFile,
				os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatal("failed to open file '%v': %v", settings.outputFile, err)
			}
			defer file.Close()
		}
		proof.ToASCII(file)
	}
}

func (s *Settings) parse(args []string, usage string) {
	set := getopt.New()
	set.SetParameters("")
	set.SetUsage(func() { fmt.Print(usage) })

	help := false
	set.FlagLong(&s.rawHash, "raw-hash", 0, "Use raw hash input")
	set.FlagLong(&s.keyFile, "key", 'k', "Key file")
	set.FlagLong(&s.policyFile, "policy", 0, "Policy file")
	set.FlagLong(&s.outputFile, "output-file", 'o', "Output file")
	set.FlagLong(&s.diagnostics, "diagnostics", 0, "Level of diagnostic messages")
	set.FlagLong(&help, "help", 0, "Display help")
	set.Parse(args)
	if help {
		// TODO: Let getopt package list options, and append further details.
		fmt.Print(usage)
		os.Exit(0)
	}
	if set.NArgs() > 0 {
		log.Fatal("Too many arguments.")
	}
}

func readMessage(r io.Reader, rawHash bool) crypto.Hash {
	readHash := func(r io.Reader) (ret crypto.Hash) {
		// One extra byte, to detect EOF.
		msg := make([]byte, 33)
		if readCount, err := io.ReadFull(os.Stdin, msg); err != io.ErrUnexpectedEOF || readCount != 32 {
			if err != nil && err != io.ErrUnexpectedEOF {
				log.Fatal("reading message from stdin failed: %v", err)
			}
			log.Fatal("sigsum message must be exactly 32 bytes, got %d", readCount)
		}
		copy(ret[:], msg)
		return
	}
	if rawHash {
		return readHash(r)
	}
	msg, err := crypto.HashFile(r)
	if err != nil {
		log.Fatal("%v", err)
	}
	return msg
}
