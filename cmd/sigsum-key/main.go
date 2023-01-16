package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
)

type GenSettings struct {
	outputFile string
}

type VerifySettings struct {
	keyFile       string
	signatureFile string
	namespace     string
}

type SignSettings struct {
	keyFile    string
	outputFile string
	namespace  string
	sshFormat  bool
}

type ExportSettings struct {
	keyFile string
}

func main() {
	const usage = `sigsum-key sub commands:

  sigsum-key help 
    Display this help.

  sigsum-key gen -o KEY-FILE
    Generate a new key pair. Private key is stored in the given
    KEY-FILE, hex-encoded. Corresponding public key file gets a ".pub"
    suffix, and is written in OpenSSH format.

  sigsum-key verify -k KEY -s SIGNATURE [-n NAMESPACE] < MSG
    KEY and SIGNATURE are file names.
    NAMESPACE is a string, default being "signed-tree-head:v0@sigsum.org"

  sigsum-key sign -k KEY [-o SIGNATURE] [-n NAMESPACE] [--ssh] < MSG
    KEY and SIGNATURE are file names (by default, signature is written
    to stdout). NAMESPACE is a string, default being
    "tree-leaf:v0@sigsum.org". If --ssh is provided, produce an ssh
    signature file, otherwise raw hex.

  sigsum-key hash -k KEY
    KEY is filename of a public key. Outputs hex-encoded key hash.

  sigsum-key hex -k KEY
    KEY is filename of a public key. Outputs hex-encoded raw key.
`
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal(usage)
	}

	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	default:
		log.Fatal(usage)
	case "help":
		log.Print(usage)
		os.Exit(0)
	case "gen":
		settings := parseGenSettings(args)
		pub, signer, err := crypto.NewKeyPair()
		if err != nil {
			log.Fatalf("generating key failed: %v\n", err)
		}
		writeKeyFiles(settings.outputFile, &pub, signer)
	case "verify":
		settings := parseVerifySettings(args)
		publicKey := readPublicKeyFile(settings.keyFile)
		signature := readSignatureFile(settings.signatureFile,
			&publicKey, settings.namespace)
		hash, err := crypto.HashFile(os.Stdin)
		if err != nil {
			log.Fatalf("failed to read stdin: %v\n", err)
		}

		if !crypto.Verify(&publicKey,
			ssh.SignedDataFromHash(settings.namespace, &hash),
			&signature) {
			log.Fatalf("signature is not valid\n")
		}
	case "sign":
		settings := parseSignSettings(args)
		signer := readPrivateKeyFile(settings.keyFile)
		hash, err := crypto.HashFile(os.Stdin)
		if err != nil {
			log.Fatalf("failed to read stdin: %v\n", err)
		}
		signature, err := signer.Sign(ssh.SignedDataFromHash(settings.namespace, &hash))
		if err != nil {
			log.Fatalf("signing failed: %v", err)
		}
		public := signer.Public()
		writeSignatureFile(settings.outputFile, settings.sshFormat,
			&public, settings.namespace, &signature)
	case "hash":
		settings := parseExportSettings(args)
		publicKey := readPublicKeyFile(settings.keyFile)
		fmt.Printf("%x\n", crypto.HashBytes(publicKey[:]))
	case "hex":
		settings := parseExportSettings(args)
		publicKey := readPublicKeyFile(settings.keyFile)
		fmt.Printf("%x\n", publicKey[:])
	}
}

func parseGenSettings(args []string) GenSettings {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	outputFile := flags.String("o", "", "Output file")

	flags.Parse(args)

	if len(*outputFile) == 0 {
		log.Printf("output file (-o option) missing")
		os.Exit(1)
	}
	return GenSettings{*outputFile}
}

func parseVerifySettings(args []string) VerifySettings {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	keyFile := flags.String("k", "", "Key file")
	signatureFile := flags.String("s", "", "Signature file")
	namespace := flags.String("n", "signed-tree-head:v0@sigsum.org", "Signature namespace")

	flags.Parse(args)

	if len(*keyFile) == 0 {
		log.Printf("key file (-k option) missing")
		os.Exit(1)
	}
	if len(*signatureFile) == 0 {
		log.Printf("signature file (-s option) missing")
		os.Exit(1)
	}
	return VerifySettings{
		keyFile:       *keyFile,
		signatureFile: *signatureFile,
		namespace:     *namespace,
	}
}

func parseSignSettings(args []string) SignSettings {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	keyFile := flags.String("k", "", "Key file")
	outputFile := flags.String("o", "", "Signature output file")
	namespace := flags.String("n", "tree-leaf:v0@sigsum.org", "Signature namespace")
	sshFormat := flags.Bool("ssh", false, "Use OpenSSH format for public key")

	flags.Parse(args)

	if len(*keyFile) == 0 {
		log.Fatalf("key file (-k option) missing")
	}
	return SignSettings{
		keyFile:    *keyFile,
		outputFile: *outputFile,
		namespace:  *namespace,
		sshFormat:  *sshFormat,
	}
}

func parseExportSettings(args []string) ExportSettings {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	keyFile := flags.String("k", "", "Key file")

	flags.Parse(args)

	if len(*keyFile) == 0 {
		log.Printf("key file (-k option) missing")
		os.Exit(1)
	}
	return ExportSettings{*keyFile}
}

// If outputFile is non-empty: open file, pass to f, and automatically
// close it after f returns. Otherwise, just pass os.Stdout to f. Also
// exit program on error from f.
func withOutput(outputFile string, mode os.FileMode, f func(io.Writer) error) {
	file := os.Stdout
	if len(outputFile) > 0 {
		var err error
		file, err = os.OpenFile(outputFile,
			os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			log.Fatalf("failed to open file '%v': %v", outputFile, err)
		}
		defer file.Close()
	}
	err := f(file)
	if err != nil {
		log.Fatalf("writing output failed: %v", err)
	}
}

func writeKeyFiles(outputFile string, pub *crypto.PublicKey, signer *crypto.Ed25519Signer) {
	withOutput(outputFile, 0600, func(f io.Writer) error {
		return ssh.WritePrivateKeyFile(f, signer)
	})
	if len(outputFile) > 0 {
		// Openssh insists that also public key files have
		// restrictive permissions.
		withOutput(outputFile+".pub", 0600,
			func(f io.Writer) error {
				_, err := io.WriteString(f, ssh.FormatPublicEd25519(pub))
				return err
			})
	}
}

func writeSignatureFile(outputFile string, sshFormat bool,
	public *crypto.PublicKey, namespace string, signature *crypto.Signature) {
	withOutput(outputFile, 0644, func(f io.Writer) error {
		if sshFormat {
			return ssh.WriteSignatureFile(f, public, namespace, signature)
		} else {
			_, err := fmt.Fprintf(f, "%x\n", signature[:])
			return err
		}
	})
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

func readSignatureFile(fileName string,
	pub *crypto.PublicKey, namespace string) crypto.Signature {
	contents, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatalf("reading file %q failed: %v", fileName, err)
	}
	signature, err := ssh.ParseSignatureFile(contents, pub, namespace)
	if err == ssh.NoPEMError {
		signature, err = crypto.SignatureFromHex(strings.TrimSpace(string(contents)))
	}
	if err != nil {
		log.Fatal(err)
	}
	return signature
}
