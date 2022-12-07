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
	"sigsum.org/sigsum-go/pkg/ascii"
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
	// TODO: Add option to use the hash of the input file as the message.
	// TODO: Witness config/policy.
	settings := parseSettings(os.Args[1:], usage)
	var leaf requests.Leaf
	if len(settings.keyFile) > 0 {
		signer := readPrivateKeyFile(settings.keyFile)
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
		publicKey := readPublicKeyFile(settings.logKey)
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

func parseSettings(args []string, usage string) Settings {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.Usage = func() { fmt.Print(usage) }

	keyFile := flags.String("k", "", "Key file")
	logUrl := flags.String("log-url", "", "Log base url")
	logKey := flags.String("log-key", "", "Public key file for log")
	outputFile := flags.String("o", "", "Output file")

	flags.Parse(args)
	if len(*logUrl) > 0 && len(*logKey) == 0 {
		log.Fatalf("--log-url option requires log's public key (--log-key option)")
	}
	return Settings{
		keyFile:    *keyFile,
		logUrl:     *logUrl,
		logKey:     *logKey,
		outputFile: *outputFile,
	}
}

func readPublicKeyFile(fileName string) crypto.PublicKey {
	contents, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatalf("reading file %q failed: %v", fileName, err)
	}
	key, err := key.ParsePublicKey(string(contents))
	if err != nil {
		log.Fatalf("parsing file %q failed: %v", fileName, err)
	}
	return key
}

func readPrivateKeyFile(fileName string) crypto.Signer {
	contents, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatalf("reading file %q failed: %v", fileName, err)
	}
	signer, err := key.ParsePrivateKey(string(contents))
	if err != nil {
		log.Fatalf("parsing file %q failed: %v", fileName, err)
	}
	return signer
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
		getTreeHeadUrl := types.EndpointGetTreeHeadCosigned.Path(logUrl)
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
		if !cth.SignedTreeHead.VerifyLogSignature(logKey) {
			return "", fmt.Errorf("log's tree head signature is invalid: %v", err)
		}

		// See if we can have an inclusion proof for this tree size.
		if cth.TreeSize == 0 {
			// Certainly not included yet.
			time.Sleep(delay)
			continue
		}
		var proof types.InclusionProof
		// Special case for the very first leaf.
		if cth.TreeSize == 1 {
			if cth.RootHash != leafHash {
				// Certainly not included yet.
				time.Sleep(delay)
				continue
			}
			proof.TreeSize = 1
		} else {
			getInclusionProofUrl := fmt.Sprintf("%s/%d/%x",
				types.EndpointGetInclusionProof.Path(logUrl), cth.TreeSize, leafHash)
			req, err = http.NewRequestWithContext(ctx, http.MethodGet, getInclusionProofUrl, nil)
			if err != nil {
				return "", fmt.Errorf("creating the get-inclusion-proof request faild: %v", err)
			}
			resp, err = client.Do(req)
			if err != nil {
				return "", fmt.Errorf("failed to get inclusion proof: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				log.Printf("no inclusion proof yet, will retry: %v", resp.Status)
				time.Sleep(delay)
				continue
			}
			err = proof.FromASCII(resp.Body, cth.TreeSize)
			resp.Body.Close()
			if err != nil {
				return "", fmt.Errorf("failed to parse inclusion proof: %v", err)
			}
		}

		// Check validity.
		if err = merkle.VerifyInclusion(&leafHash, proof.LeafIndex, cth.TreeSize, &cth.RootHash, proof.Path); err != nil {
			return "", fmt.Errorf("inclusion proof invalid: %v", err)
		}

		// Output collected data.
		buf := bytes.Buffer{}

		fmt.Fprintf(&buf, "version=0\nlog=%x\n\n", crypto.HashBytes(logKey[:]))

		fmt.Fprintf(&buf, "leaf=%x %x\n\n", crypto.HashBytes(leaf.PublicKey[:]), leaf.Signature)

		cth.ToASCII(&buf)

		if cth.TreeSize > 1 {
			fmt.Fprintf(&buf, "\n")
			proof.ToASCII(&buf)
		}
		return string(buf.Bytes()), nil
	}
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
		log.Fatalf("failed to perse signature: %v", err)
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

// TODO: There should be some library utility for this.
func leafHash(leaf *requests.Leaf) crypto.Hash {
	return merkle.HashLeafNode((&types.Leaf{
		Checksum:  crypto.HashBytes(leaf.Message[:]),
		KeyHash:   crypto.HashBytes(leaf.PublicKey[:]),
		Signature: leaf.Signature,
	}).ToBinary())
}
