package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"bytes"
	"net/url"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

type Settings struct {
	keyFile    string
	logUrl     string
	logKey     string
	outputFile string
}

func main() {
	const usage = `sigsum-log [OPTIONS] < INPUT
    Options:
      -h --help Display this help
      -k PRIVATE-KEY
      --log-url LOG-URL
      --log-key LOG-KEY
      -o OUTPUT-FILE
    Creates and/or submits an add-leaf request.

    If -k PRIVATE-KEY is provided, a new leaf is created based on the
    INPUT message (note that it's size must be exactly 32 octets).

    If -k option is missing, the INPUT should instead be the body of a
    leaf request, which is parsed and verified.

    If --log-url is provided, the leaf is submitted to the log, and a sigsum
    proof is collected and written to the output. The log's public key (file)
    must be passed with the --log-key option.

    With -k and no --log-url, leaf request is written to stdout. With no -k and no
    --log-url, just verifies the leaf syntax and signature.

    If no output file is provided with the -o option, output is sent to stdout.
`
	log.SetFlags(0)
	// TODO: Add option to use the hash of the input file as the message.
	// TODO: Witness config/policy.
	var settings Settings
	settings.parse(os.Args[1:], usage)
	var leaf requests.Leaf
	if len(settings.keyFile) > 0 {
		signer, err := key.ReadPrivateKeyFile(settings.keyFile)
		if err != nil {
			log.Fatal(err)
		}
		publicKey := signer.Public()

		// TODO: Optionally create message by hashing stdin.
		msg := readMessage(os.Stdin)

		signature, err := types.SignLeafMessage(signer, msg[:])
		if err != nil {
			log.Fatalf("signing failed: %v", err)
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
					log.Fatalf("failed to open file '%v': %v", settings.outputFile, err)
				}
				defer file.Close()
			}
			if err := leaf.ToASCII(file); err != nil {
				log.Fatalf("writing leaf to stdout failed: %v", err)
			}
			return
		}
	} else {
		if err := leaf.FromASCII(os.Stdin); err != nil {
			log.Fatalf("parsing leaf request failed: %v", err)
		}
		if !types.VerifyLeafMessage(&leaf.PublicKey, leaf.Message[:], &leaf.Signature) {
			log.Fatalf("invalid leaf signature")
		}
	}
	if len(settings.logUrl) > 0 {
		publicKey, err := key.ReadPublicKeyFile(settings.logKey)
		if err != nil {
			log.Fatal(err)
		}
		proof, err := submitLeaf(settings.logUrl, &publicKey, &leaf)
		if err != nil {
			log.Fatalf("submitting leaf failed: %v", err)
		}
		file := os.Stdout
		if len(settings.outputFile) > 0 {
			var err error
			file, err = os.OpenFile(settings.outputFile,
				os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatalf("failed to open file '%v': %v", settings.outputFile, err)
			}
			defer file.Close()
		}
		fmt.Fprint(file, proof)
	}
}

func (s *Settings) parse(args []string, usage string) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.Usage = func() { fmt.Print(usage) }

	flags.StringVar(&s.keyFile, "k", "", "Key file")
	flags.StringVar(&s.logUrl, "log-url", "", "Log base url")
	flags.StringVar(&s.logKey, "log-key", "", "Public key file for log")
	flags.StringVar(&s.outputFile, "o", "", "Output file")

	flags.Parse(args)
	if len(s.logUrl) > 0 && len(s.logKey) == 0 {
		log.Fatalf("--log-url option requires log's public key (--log-key option)")
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

func submitLeaf(logUrl string, logKey *crypto.PublicKey, leaf *requests.Leaf) (string, error) {
	// We need the leaf hash.
	leafHash := leafHash(leaf)

	// TODO: should use sigsum-go's Client.AddLeaf, but that's not yet implemented.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := http.Client{}
	delay := 2 * time.Second

	for {
		addLeafUrl := types.EndpointAddLeaf.Path(logUrl)
		buf := bytes.Buffer{}
		leaf.ToASCII(&buf)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, addLeafUrl, &buf)
		if err != nil {
			return "", fmt.Errorf("creating the add-leaf request faild: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			// TODO: Should probably terminate on these errors.
			if err, ok := err.(*url.Error); ok && err.Timeout() {
				log.Fatalf("timed out: %v", err)
			}
			log.Printf("add-leaf request failed, will retry: %v", err)
			time.Sleep(delay)
			continue
		}
		// Don't care about body
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			break
		}
		time.Sleep(delay)
	}
	// Leaf submitted, now get a signed tree head + inclusion proof.
	for {
		getTreeHeadUrl := types.EndpointGetTreeHead.Path(logUrl)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, getTreeHeadUrl, nil)
		if err != nil {
			return "", fmt.Errorf("creating the get tree request faild: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to get tree head: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return "", fmt.Errorf("get tree head gave response %q", resp.Status)
		}
		var cth types.CosignedTreeHead
		err = cth.FromASCII(resp.Body)
		resp.Body.Close()
		if err != nil {
			return "", fmt.Errorf("failed to parse tree head: %v", err)
		}
		if !cth.Verify(logKey) {
			return "", fmt.Errorf("log's tree head signature is invalid: %v", err)
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
			getInclusionProofUrl := fmt.Sprintf("%s%d/%x",
				types.EndpointGetInclusionProof.Path(logUrl), cth.Size, leafHash)
			req, err = http.NewRequestWithContext(ctx, http.MethodGet, getInclusionProofUrl, nil)
			if err != nil {
				return "", fmt.Errorf("creating the get-inclusion-proof request failed: %v", err)
			}
			resp, err = client.Do(req)
			if err != nil {
				return "", fmt.Errorf("failed to get inclusion proof: %v", err)
			}
			if resp.StatusCode == http.StatusNotFound {
				log.Printf("no inclusion proof yet (url %q), will retry: %v", req.URL, resp.Status)
				time.Sleep(delay)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				errorBody, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					return "", fmt.Errorf("getting inclusion proof failed: %v, no server response: %v",
						resp.Status, err)
				}
				return "", fmt.Errorf("getting inclusion proof failed: %v, server said: %q",
					resp.Status, errorBody)
			}
			err = proof.FromASCII(resp.Body, cth.Size)
			resp.Body.Close()
			if err != nil {
				return "", fmt.Errorf("failed to parse inclusion proof: %v", err)
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
