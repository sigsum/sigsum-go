package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

type Settings struct {
	rawHash     bool
	keyFile     string
	logUrl      string
	logKey      string
	diagnostics string
	outputFile  string
}

func main() {
	const usage = `sigsum-log [OPTIONS] < INPUT
    Options:
      -h --help Display this help
      -k PRIVATE-KEY-FILE
      --log-url LOG-URL
      --log-key LOG-KEY-FILE
      --diagnostics LEVEL
      --raw-hash
      -o OUTPUT-FILE
    Creates and/or submits an add-leaf request.

    If -k PRIVATE-KEY-FILE is provided, a new leaf is created based on
    the SHA256 hash of INPUT (or, if --raw-hash is provided, INPUT is
    treated as the hash value to be used, exactly 32 octets long).

    If the -k option is missing, INPUT should instead be the body of an
    add-leaf request, which is then parsed and verified.

    If --log-url is provided, the request is submitted to the log, and a Sigsum
    proof is collected and written to stdout. A file containing the log's public key
    must be passed with the --log-key option.

    With -k but without --log-url, the add-leaf request created is
    written to stdout. With no -k and no --log-url, the leaf syntax
    and signature in INPUT are verified.

    The --diagnostics option specifies level of diagnostig messages,
    one of "fatal", "error", "warning", "info" (default), or "debug".

    If no output file is provided with the -o option, output is sent to stdout.
`
	// TODO: Witness config/policy.
	var settings Settings
	settings.parse(os.Args[1:], usage)
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

		if len(settings.logUrl) == 0 {
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
	if len(settings.logUrl) > 0 {
		publicKey, err := key.ReadPublicKeyFile(settings.logKey)
		if err != nil {
			log.Fatal("%v", err)
		}
		proof, err := submitLeaf(settings.logUrl, &publicKey, &leaf)
		if err != nil {
			log.Fatal("submitting leaf failed: %v", err)
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
		fmt.Fprint(file, proof)
	}
}

func (s *Settings) parse(args []string, usage string) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.Usage = func() { fmt.Print(usage) }

	flags.BoolVar(&s.rawHash, "raw-hash", false, "Use raw hash input")
	flags.StringVar(&s.keyFile, "k", "", "Key file")
	flags.StringVar(&s.logUrl, "log-url", "", "Log base url")
	flags.StringVar(&s.logKey, "log-key", "", "Public key file for log")
	flags.StringVar(&s.outputFile, "o", "", "Output file")
	flags.StringVar(&s.diagnostics, "diagnostics", "", "Level of diagnostic messages")

	flags.Parse(args)
	if len(s.logUrl) > 0 && len(s.logKey) == 0 {
		log.Fatal("--log-url option requires log's public key (--log-key option)")
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

func submitLeaf(logUrl string, logKey *crypto.PublicKey, req *requests.Leaf) (string, error) {
	leaf, err := req.Verify()
	if err != nil {
		return "", err
	}
	leafHash := leaf.ToHash()

	proof := proof.SigsumProof{
		LogKeyHash: crypto.HashBytes(logKey[:]),
		Leaf:       proof.NewShortLeaf(&leaf),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := client.New(client.Config{
		UserAgent: "sigsum-log",
		LogURL:    logUrl,
	})

	delay := 2 * time.Second

	for {
		persisted, err := c.AddLeaf(ctx, *req)

		if err != nil {
			log.Fatal("%v", err)
		}
		if persisted {
			break
		}
		time.Sleep(delay)
	}
	// Leaf submitted, now get a signed tree head + inclusion proof.
	for {
		var err error
		proof.TreeHead, err = c.GetTreeHead(ctx)
		if err != nil {
			log.Fatal("get-tree-head failed: %v", err)
		}
		if !proof.TreeHead.Verify(logKey) {
			log.Fatal("invalid log signature on tree head")
		}
		// See if we can have an inclusion proof for this tree size.
		if proof.TreeHead.Size == 0 {
			// Certainly not included yet.
			time.Sleep(delay)
			continue
		}
		// Special case for the very first leaf.
		if proof.TreeHead.Size == 1 {
			if proof.TreeHead.RootHash != leafHash {
				// Certainly not included yet.
				time.Sleep(delay)
				continue
			}
		} else {
			proof.Inclusion, err = c.GetInclusionProof(ctx,
				requests.InclusionProof{
					Size:     proof.TreeHead.Size,
					LeafHash: leafHash,
				})
			if err == client.HttpNotFound {
				log.Info("no inclusion proof yet, will retry")
				time.Sleep(delay)
				continue
			}
			if err != nil {
				return "", fmt.Errorf("failed to get inclusion proof: %v", err)
			}
		}

		// Check validity.
		if err = proof.Inclusion.Verify(&leafHash, &proof.TreeHead.TreeHead); err != nil {
			return "", fmt.Errorf("inclusion proof invalid: %v", err)
		}

		// Output collected data.
		buf := bytes.Buffer{}
		if err := proof.ToASCII(&buf); err != nil {
			return "", err
		}
		return buf.String(), nil
	}
}
