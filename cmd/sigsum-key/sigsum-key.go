package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	getopt "github.com/pborman/getopt/v2"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/types"
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
	keyFile    string
	outputFile string
}

func main() {
	const usage = `sigsum-key sub commands:

  sigsum-key help | --help
    Display this help. All the below sub commands also accept the --help
    option, to display help for that sub command.

  sigsum-key gen -o file
    Generate a new key pair. Private key is stored in the given
    file, in OpenSSH private key format. Corresponding public key
    file gets a ".pub" suffix, and is written in OpenSSH public
    key format.

  sigsum-key verify [options] < msg
    Verify a signature. For option details, see sigsum-key verify --help.

  sigsum-key sign [options] < msg
    Create a signature. For option details, see sigsum-key sign --help.

  sigsum-key hash [-k file] [-o output]
    Reads public key from file (by default, stdin) and writes key hash
    to output (by default, stdout).

  sigsum-key hex [-k file] [-o output]
    Reads public key from file (by default, stdin) and writes hex key
    to output (by default, stdout).

  sigsum-key hex-to-pub [-k file] [-o output]
    Reads hex public key from file (by default, stdin) and writes
    OpenSSH format public key to output (by default, stdout).
`
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal(usage)
	}

	switch os.Args[1] {
	default:
		log.Fatal(usage)
	case "help", "--help":
		fmt.Print(usage)
		os.Exit(0)
	case "gen":
		var settings GenSettings
		settings.parse(os.Args)
		pub, signer, err := crypto.NewKeyPair()
		if err != nil {
			log.Fatalf("generating key failed: %v\n", err)
		}
		writeKeyFiles(settings.outputFile, &pub, signer)
	case "verify":
		var settings VerifySettings
		settings.parse(os.Args)
		publicKey, err := key.ReadPublicKeyFile(settings.keyFile)
		if err != nil {
			log.Fatal(err)
		}
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
		var settings SignSettings
		settings.parse(os.Args)
		signer, err := key.ReadPrivateKeyFile(settings.keyFile)
		if err != nil {
			log.Fatal(err)
		}
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

		// TODO: Change all subcommands hash, hex, hex-to-pub
		// to take an optional filename arguments for input
		// and output, and by default read stdin and write to
		// stdout.
	case "hash":
		var settings ExportSettings
		settings.parse(os.Args, false)
		publicKey, err := key.ParsePublicKey(readInput(settings.keyFile))
		if err != nil {
			log.Fatal(err)
		}
		withOutput(settings.outputFile, 0660, func(f io.Writer) error {
			_, err := fmt.Fprintf(f, "%x\n", crypto.HashBytes(publicKey[:]))
			return err
		})
	case "hex":
		var settings ExportSettings
		settings.parse(os.Args, false)
		publicKey, err := key.ParsePublicKey(readInput(settings.keyFile))
		if err != nil {
			log.Fatal(err)
		}
		withOutput(settings.outputFile, 0660, func(f io.Writer) error {
			_, err := fmt.Fprintf(f, "%x\n", publicKey[:])
			return err
		})
	case "hex-to-pub":
		var settings ExportSettings
		settings.parse(os.Args, true)
		pub, err := crypto.PublicKeyFromHex(strings.TrimSpace(readInput(settings.keyFile)))
		if err != nil {
			log.Fatalf("invalid key: %v", err)
		}
		withOutput(settings.outputFile, 0660, func(f io.Writer) error {
			_, err := fmt.Fprint(f, ssh.FormatPublicEd25519(&pub))
			return err
		})
	}
}

func newOptionSet(args []string) *getopt.Set {
	set := getopt.New()
	set.SetProgram(args[0] + " " + args[1])
	set.SetParameters("")
	return set
}

// Also adds and processes the help option.
func parseNoArgs(set *getopt.Set, args []string) {
	help := false
	set.FlagLong(&help, "help", 0, "Display help")
	err := set.Getopt(args[1:], nil)
	// Check help first; if seen, ignore errors about missing mandatory arguments.
	if help {
		set.PrintUsage(os.Stdout)
		fmt.Printf("\nFor general information on this tool, see %s help.", args[0])
		os.Exit(0)
	}
	if err != nil {
		log.Printf("err: %v\n", err)
		set.PrintUsage(log.Writer())
		os.Exit(1)
	}
	if set.NArgs() > 0 {
		log.Fatal("Too many arguments.")
	}
}

func (s *GenSettings) parse(args []string) {
	set := newOptionSet(args)
	set.Flag(&s.outputFile, 'o', "Output", "file").Mandatory()
	parseNoArgs(set, args)
}

func (s *VerifySettings) parse(args []string) {
	// Default value.
	s.namespace = types.TreeLeafNamespace

	set := newOptionSet(args)
	set.FlagLong(&s.keyFile, "key", 'k', "Public key", "file").Mandatory()
	set.FlagLong(&s.signatureFile, "signature", 's', "Signature", "file").Mandatory()
	set.FlagLong(&s.namespace, "namespace", 'n', "Signature namespace")
	parseNoArgs(set, args)
}

func (s *SignSettings) parse(args []string) {
	// Default value.
	s.namespace = types.TreeLeafNamespace

	set := newOptionSet(args)
	set.FlagLong(&s.keyFile, "key", 'k', "Public key", "file").Mandatory()
	set.Flag(&s.outputFile, 'o', "Signature output", "file")
	set.FlagLong(&s.namespace, "namespace", 'n', "Signature namespace")
	set.FlagLong(&s.sshFormat, "ssh", 0, "Use OpenSSH format for output signature")
	parseNoArgs(set, args)
}

func (s *ExportSettings) parse(args []string, hex bool) {
	set := newOptionSet(args)
	if hex {
		set.FlagLong(&s.keyFile, "key", 'k', "Hex public key", "file")
	} else {
		set.FlagLong(&s.keyFile, "key", 'k', "Public key", "file")
	}
	set.Flag(&s.outputFile, 'o', "Output", "file")
	parseNoArgs(set, args)
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
		}
		_, err := fmt.Fprintf(f, "%x\n", signature[:])
		return err
	})
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

// Reads given file, or stdin.
func readInput(fileName string) string {
	var contents []byte
	var err error
	if len(fileName) > 0 {
		contents, err = os.ReadFile(fileName)
	} else {
		contents, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		log.Fatalf("Reading input failed: %v", err)
	}
	return string(contents)
}
