package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	getopt "github.com/pborman/getopt/v2"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/submit"
	"sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

type Settings struct {
	rawHash      bool
	keyFile      string
	policyFile   string
	diagnostics  string
	inputFiles   []string
	outputFile   string
	outputDir    string
	tokenDomain  string
	tokenKeyFile string
	timeout      time.Duration
}

// Empty name for stdin
type LeafSink func(name string, leaf *requests.Leaf)
type LeafSkip func(name string, msg *crypto.Hash, publicKey *crypto.PublicKey) bool
type LeafSource func(skip LeafSkip, sink LeafSink)

func main() {
	var settings Settings
	settings.parse(os.Args)
	if err := log.SetLevelFromString(settings.diagnostics); err != nil {
		log.Fatal("%v", err)
	}

	var source LeafSource
	if len(settings.keyFile) > 0 {
		signer, err := key.ReadPrivateKeyFile(settings.keyFile)
		if err != nil {
			log.Fatal("reading key file failed: %v", err)
		}
		publicKey := signer.Public()
		if len(settings.inputFiles) == 0 {
			source = func(_ LeafSkip, sink LeafSink) {
				msg, err := readMessage(os.Stdin, settings.rawHash)
				if err != nil {
					log.Fatal("Reading message from stdin failed: %v", err)
				}
				signature, err := types.SignLeafMessage(signer, msg[:])
				if err != nil {
					log.Fatal("Signing failed: %v", err)
				}
				sink("", &requests.Leaf{Message: msg, Signature: signature, PublicKey: publicKey})
			}
		} else {
			source = func(skip LeafSkip, sink LeafSink) {
				for _, inputFile := range settings.inputFiles {
					msg := readMessageFile(inputFile, settings.rawHash)
					if skip(inputFile, &msg, &publicKey) {
						continue
					}
					signature, err := types.SignLeafMessage(signer, msg[:])
					if err != nil {
						log.Fatal("signing failed: %v", err)
					}
					sink(inputFile, &requests.Leaf{Message: msg, Signature: signature, PublicKey: publicKey})
				}
			}
		}
	} else {
		if len(settings.inputFiles) == 0 {
			source = func(_ LeafSkip, sink LeafSink) {
				leaf, err := readLeafRequest(os.Stdin)
				if err != nil {
					log.Fatal("Leaf request on stdin not valid: %v", err)
				}
				sink("", &leaf)
			}
		} else {
			source = func(skip LeafSkip, sink LeafSink) {
				for _, inputFile := range settings.inputFiles {
					leaf, err := readLeafRequestFile(inputFile)
					if err != nil {
						log.Fatal("Leaf request %q not valid: %v", inputFile, err)
					}
					// Strip suffix.
					inputFile = strings.TrimSuffix(inputFile, ".req")
					if len(inputFile) == 0 {
						log.Fatal("Invalid input file name %q", ".req")
					}
					if !skip(inputFile, &leaf.Message, &leaf.PublicKey) {
						sink(inputFile, &leaf)
					}
				}
			}
		}
	}

	if len(settings.policyFile) > 0 {
		policy, err := policy.ReadPolicyFile(settings.policyFile)
		if err != nil {
			log.Fatal("Invalid policy file: %v", err)
		}
		config := submit.Config{Policy: policy,
			Domain:        settings.tokenDomain,
			PerLogTimeout: settings.timeout,
		}
		ctx := context.Background()

		if len(config.Domain) > 0 {
			var err error
			config.RateLimitSigner, err = key.ReadPrivateKeyFile(settings.tokenKeyFile)
			if err != nil {
				log.Fatal("reading token key file failed: %v", err)
			}
			// Warn if corresponding public key isn't registered for the domain.
			if err := checkTokenDomain(ctx, config.Domain, config.RateLimitSigner.Public()); err != nil {
				log.Warning("warn: token domain and signer does not match DNS records: %v", err)
			}
		}

		skip := func(inputName string, msg *crypto.Hash, publicKey *crypto.PublicKey) bool {
			proofName := settings.getOutputFile(inputName + ".proof")
			f, err := os.Open(proofName)
			if errors.Is(err, fs.ErrNotExist) {
				return false
			}
			if err != nil {
				log.Fatal("Opening proof file %q failed: %v", proofName, err)
			}
			defer f.Close()
			var sigsumProof proof.SigsumProof
			if err := sigsumProof.FromASCII(f); err != nil {
				log.Fatal("Parsing proof file %q failed: %v", proofName, err)
			}
			if err := sigsumProof.Verify(msg, publicKey, policy); err != nil {
				log.Fatal("Existing proof file %q is not valid: %v", proofName, err)
			}
			return true
		}

		// An item to submit.
		type Item struct {
			leaf      requests.Leaf
			inputName string // empty for stdin
		}
		var items []Item
		// TODO: Actually do requests in batch.
		source(skip, func(name string, leaf *requests.Leaf) {
			items = append(items, Item{
				leaf:      *leaf,
				inputName: name,
			})
		})

		for _, item := range items {
			proof, err := submit.SubmitLeafRequest(ctx, &config, &item.leaf)
			if err != nil {
				log.Fatal("Submit failed: %v", err)
			}
			if len(item.inputName) == 0 && len(settings.outputFile) == 0 {
				if err := proof.ToASCII(os.Stdout); err != nil {
					log.Fatal("Writing proof to stdout failed: %v", err)
				}
			} else {
				proofFile := settings.getOutputFile(item.inputName + ".proof")
				if err := withOutputFile(proofFile, proof.ToASCII); err != nil {
					log.Fatal("Writing proof to %q failed: %v", proofFile, err)
				}
			}
		}
	} else {
		// Output created add-leaf requests.
		writeLeafRequest := func(inputFile string, leaf *requests.Leaf) {
			if len(inputFile) == 0 && len(settings.outputFile) == 0 {
				if err := leaf.ToASCII(os.Stdout); err != nil {
					log.Fatal("Writing leaf request to stdout filed: %v", err)
				}
				return
			}
			outputFile := settings.getOutputFile(inputFile + ".req")
			if err := withOutputFile(outputFile, leaf.ToASCII); err != nil {
				log.Fatal("Writing leaf request failed: %v", err)
			}
		}

		source(func(_ string, _ *crypto.Hash, _ *crypto.PublicKey) bool { return false },
			writeLeafRequest)
	}
}

func (s *Settings) parse(args []string) {
	const usage = `
    Create and/or submit add-leaf request(s).

    If no input files are listed on the command line, a single request
    is processed, reading from standard input, and writing to standard
    output (or file specified with the -o option). See further below
    for processing of multiple files.

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

    If input files are provided on the command line, each file
    corresponds to one request, and result is written to a
    corresponding output file, based on these rules:

    1. If there's exactly one input file, and the -o option is used,
       output is written to that file. Any existing file is overwritten.

    2. For a request output, the suffix ".req" is added to the input
       file name.

    3. For a proof output, if the input is a request, any ".req"
       suffix on the input file name is stripped. Then the suffix
       ".proof" is added.

    4. If the --output-dir option is provided, any directory part of
       the input file name is stripped, and the output is written as a
       file in the specified output directory.

    If a corresponding .proof file already exists, that proof is read
    and verified. If the proof is valid, the input file is skipped. If
    the proof is not valid, sigsum-submit exits with an error.

    If a corresponding .req output file already exists, it is
    overwritten (TODO: Figure out if that is the proper behavior).
`
	s.diagnostics = "info"

	set := getopt.New()
	set.SetParameters("[input files]")
	set.SetUsage(func() { fmt.Print(usage) })

	help := false
	set.FlagLong(&s.rawHash, "raw-hash", 0, "Input is already hashed")
	set.FlagLong(&s.keyFile, "signing-key", 'k', "Key for signing the leaf", "file")
	set.FlagLong(&s.policyFile, "policy", 'p', "Sigsum policy", "file")
	set.Flag(&s.outputFile, 'o', "Write output to file, instead of stdout", "file")
	set.FlagLong(&s.outputDir, "output-dir", 0, "Directory for output files", "directory")
	set.FlagLong(&s.diagnostics, "diagnostics", 0, "One of \"fatal\", \"error\", \"warning\", \"info\", or \"debug\"", "level")
	set.FlagLong(&s.tokenDomain, "token-domain", 0, "Create a Sigsum-Token: header for this domain")
	set.FlagLong(&s.tokenKeyFile, "token-key-file", 0, "Key for signing Sigsum-Token: header", "file")
	set.FlagLong(&s.timeout, "timeout", 0, "Per-log submission timeout. Zero means library default, currently 45s", "duration")
	set.FlagLong(&help, "help", 0, "Display help")
	set.Parse(args)
	if help {
		set.PrintUsage(os.Stdout)
		fmt.Print(usage)
		os.Exit(0)
	}
	s.inputFiles = set.Args()
	if len(s.inputFiles) > 1 && len(s.outputFile) > 0 {
		log.Fatal("The -o option is invalid with more than one input file.")
	}
	if len(s.inputFiles) == 0 && len(s.outputDir) > 0 {
		log.Fatal("The --output-dir option is invalid when no input files are provided.")
	}
	if len(s.outputFile) > 0 && len(s.outputDir) > 0 {
		log.Fatal("The -o and the --output-dir options are mutually exclusive.")
	}
	for _, f := range s.inputFiles {
		if len(f) == 0 {
			log.Fatal("Empty string is not a valid input file name.")
		}
	}
}

func (s *Settings) getOutputFile(name string) string {
	if len(s.outputFile) > 0 {
		return s.outputFile
	}
	if len(s.outputDir) > 0 {
		return filepath.Join(s.outputDir, filepath.Base(name))
	}
	return name
}

// Reads the named input file, or stdin if filename is empty.
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

func readMessageFile(name string, rawHash bool) crypto.Hash {
	r, err := os.Open(name)
	if err != nil {
		log.Fatal("Opening %q failed: %v", name, err)
	}
	defer r.Close()
	msg, err := readMessage(r, rawHash)
	if err != nil {
		log.Fatal("Reading %q failed: %v", name, err)
	}
	return msg
}

func readLeafRequest(r io.Reader) (requests.Leaf, error) {
	var leaf requests.Leaf
	if err := leaf.FromASCII(r); err != nil {
		return requests.Leaf{}, err
	}
	if !types.VerifyLeafMessage(&leaf.PublicKey, leaf.Message[:], &leaf.Signature) {
		return requests.Leaf{}, fmt.Errorf("invalid leaf signature")
	}
	return leaf, nil
}

func readLeafRequestFile(name string) (requests.Leaf, error) {
	r, err := os.Open(name)
	if err != nil {
		return requests.Leaf{}, err
	}
	defer r.Close()

	var leaf requests.Leaf
	if err := leaf.FromASCII(r); err != nil {
		return requests.Leaf{}, fmt.Errorf("leaf request %q invalid: %v", name, err)
	}
	return leaf, nil
}

// Create temporary file, and atomically replace.
func withOutputFile(outputFile string, writer func(f io.Writer) error) error {
	tmpFile := outputFile + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile) // Ignore error
	defer f.Close()          // Ignore error, fails if Close was called explicitly.

	if err := writer(f); err != nil {
		return fmt.Errorf("writing to temporary output file %q failed: %v", tmpFile, err)
	}
	// Explicit Close, to check for errors.
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing temporary output file %q failed: %v", tmpFile, err)
	}
	// Atomic move, replacing any existing file.
	return os.Rename(tmpFile, outputFile)
}

// Warn if corresponding public key isn't registered for the domain.
func checkTokenDomain(ctx context.Context, domain string, pubkey crypto.PublicKey) error {
	resolver := net.Resolver{}
	rsps, err := token.LookupDomain(ctx, resolver.LookupTXT, domain)
	if err != nil {
		return err
	}
	var badKeys int
	for _, keyHex := range rsps {
		key, err := crypto.PublicKeyFromHex(keyHex)

		if err != nil {
			badKeys++
			continue
		}
		if key == pubkey {
			return nil
		}
	}
	return fmt.Errorf("key not registered (%d records found, syntactically bad: %d)",
		len(rsps), badKeys)
}
