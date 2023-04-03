package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

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
	var settings Settings
	settings.parse(os.Args)
	if err := log.SetLevelFromString(settings.diagnostics); err != nil {
		log.Fatal("%v", err)
	}
	var leaf requests.Leaf
	if len(settings.keyFile) > 0 {
		signer, err := key.ReadPrivateKeyFile(settings.keyFile)
		if err != nil {
			log.Fatal("reading key file failed: %v", err)
		}
		publicKey := signer.Public()

		msg, err := readMessage(os.Stdin, settings.rawHash)
		if err != nil {
			log.Fatal("reading message (stdin) failed: %v", err)
		}

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

func (s *Settings) parse(args []string) {
	const usage = `
    Creates and/or submits an add-leaf request.

    If a signing key (-k option) is specified, a new request is
    created by signing the the SHA256 hash of the input (or, if
    --raw-hash is given, input is the hash value, either exactly 32
    octets, or a hex string). The key file uses openssh format, it
    must be either an unencrypted private key, or a public key, in
    which case the corresponding private key is accessed via
    ssh-agent.

    If no signing key is provided, input should instead be the body of
    an add-leaf request, which is parsed and verified.

    If a Sigsum policy (-p option) is provided, the request is
    submitted to the log specified by the policy, and a Sigsum proof
    is collected and output. If there are multiple logs in
    the policy, they are tried in randomized order.

    With -k but without -p, the add-leaf request itself is output.
    With no -k and no -p, the request syntax and signature of the
    input request are verified, but there is no output.
`
	s.diagnostics = "info"

	set := getopt.New()
	set.SetParameters(" < input")
	set.SetUsage(func() { fmt.Print(usage) })

	help := false
	set.FlagLong(&s.rawHash, "raw-hash", 0, "Input is already hashed")
	set.FlagLong(&s.keyFile, "signing-key", 'k', "Key for signing the leaf", "file")
	set.FlagLong(&s.policyFile, "policy", 'p', "Sigsum policy", "file")
	set.Flag(&s.outputFile, 'o', "Write output to file, instead of stdout", "file")
	set.FlagLong(&s.diagnostics, "diagnostics", 0, "One of \"fatal\", \"error\", \"warning\", \"info\", or \"debug\"", "level")
	set.FlagLong(&help, "help", 0, "Display help")
	set.Parse(args)
	if help {
		set.PrintUsage(os.Stdout)
		fmt.Print(usage)
		os.Exit(0)
	}
	if set.NArgs() > 0 {
		log.Fatal("Too many arguments.")
	}
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
