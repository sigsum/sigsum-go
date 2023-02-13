package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"bytes"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/merkle"
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
      -k PRIVATE-KEY
      --log-url LOG-URL
      --log-key LOG-KEY
      --diagnostics LEVEL
      --raw-hash
      -o OUTPUT-FILE
    Creates and/or submits an add-leaf request.

    If -k PRIVATE-KEY is provided, a new leaf is created based on the
    SHA256 hash of the input (or if --raw-hash is given, input is the
    hash value, of size exactly 32 octets).

    If -k option is missing, the INPUT should instead be the body of a
    leaf request, which is parsed and verified.

    If --log-url is provided, the leaf is submitted to the log, and a sigsum
    proof is collected and written to the output. The log's public key (file)
    must be passed with the --log-key option.

    With -k and no --log-url, leaf request is written to stdout. With no -k and no
    --log-url, just verifies the leaf syntax and signature.

    The --diagnostics option specifies level of diagnostig messages,
    one of "fatal", "error", "warning", "info" (default), or "debug".

    If no output file is provided with the -o option, output is sent to stdout.
`
	// TODO: Add option to use the hash of the input file as the message.
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
		leaf = requests.Leaf{Signature: signature, PublicKey: publicKey}
		// TODO: Some impedance mismatch;
		// SignLeafMessage wants message as a []byte,
		// but requests.Leaf.Message is a crypto.Hash.
		copy(leaf.Message[:], msg[:])

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

func submitLeaf(logUrl string, logKey *crypto.PublicKey, leaf *requests.Leaf) (string, error) {
	// We need the leaf hash.
	leafHash := leafHash(leaf)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := client.New(client.Config{
		UserAgent: "sigsum-log",
		LogURL:    logUrl,
		LogPub:    *logKey,
	})

	delay := 2 * time.Second

	for {
		// Note that the client package retries on failure.
		persisted, err := c.AddLeaf(ctx, *leaf)

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
		// GetTreeHead fails if log signature is invalid.
		cth, err := c.GetTreeHead(ctx)
		if err != nil {
			log.Fatal("get-tree-head failed: %v", err)
		}
		// See if we can have an inclusion proof for this tree size.
		if cth.Size == 0 {
			// Certainly not included yet.
			time.Sleep(delay)
			continue
		}
		var proof types.InclusionProof
		// Special case for the very first leaf.
		if cth.Size == 1 {
			if cth.RootHash != leafHash {
				// Certainly not included yet.
				time.Sleep(delay)
				continue
			}
			proof.Size = 1
		} else {
			proof, err = c.GetInclusionProof(ctx,
				requests.InclusionProof{
					Size:     cth.Size,
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
		if err = merkle.VerifyInclusion(&leafHash, proof.LeafIndex, cth.Size, &cth.RootHash, proof.Path); err != nil {
			return "", fmt.Errorf("inclusion proof invalid: %v", err)
		}

		// Output collected data.
		buf := bytes.Buffer{}

		fmt.Fprintf(&buf, "version=0\nlog=%x\n\n", crypto.HashBytes(logKey[:]))

		fmt.Fprintf(&buf, "leaf=%x %x\n\n", crypto.HashBytes(leaf.PublicKey[:]), leaf.Signature)

		cth.ToASCII(&buf)

		if cth.Size > 1 {
			fmt.Fprintf(&buf, "\n")
			proof.ToASCII(&buf)
		}
		return string(buf.Bytes()), nil
	}
}

// TODO: There should be some library utility for this.
func leafHash(leaf *requests.Leaf) crypto.Hash {
	return merkle.HashLeafNode((&types.Leaf{
		Checksum:  crypto.HashBytes(leaf.Message[:]),
		KeyHash:   crypto.HashBytes(leaf.PublicKey[:]),
		Signature: leaf.Signature,
	}).ToBinary())
}
