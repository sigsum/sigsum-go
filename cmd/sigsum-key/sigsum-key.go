package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/pborman/getopt/v2"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/internal/version"
	"sigsum.org/sigsum-go/pkg/checkpoint"
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
}

type ExportSettings struct {
	keyFile    string
	outputFile string
}

type VkeyImportSettings struct {
	keyFile    string
	outputFile string
	verbose    bool
}

type VkeyExportSettings struct {
	keyFile    string
	outputFile string
	name       string
	keyType    checkpoint.SignatureType
}

func main() {
	const usage = `sigsum-key sub commands:

sigsum-key help | --help
  Display this help. All the below sub commands also accept the --help
  option, to display help for that sub command.

sigsum-key version | --version | -v
  Display software version.

sigsum-key generate -o file
  Generate a new key pair. Private key is stored in the given
  file, in OpenSSH private key format. Corresponding public key
  file gets a ".pub" suffix, and is written in OpenSSH public
  key format. Abbreviation "gen" is also recognized.

sigsum-key verify [options] < msg
  Verify a signature. For option details, see sigsum-key verify --help.

sigsum-key sign [options] < msg
  Create a signature. For option details, see sigsum-key sign --help.

sigsum-key to-hash [-k file] [-o output]
  Reads public key from file (by default, stdin) and writes key hash
  to output (by default, stdout).

sigsum-key to-hex [-k file] [-o output]
  Reads public key from file (by default, stdin) and writes hex key
  to output (by default, stdout).

sigsum-key to-vkey [-n name] [-k file] [-t type] [-o output]
  Reads public key from file (by default, stdin) and writes a signed
  note verifier line. By default, creates a vkey for a Sigsum log.

sigsum-key from-hex [-k file] [-o output]
  Reads hex public key from file (by default, stdin) and writes
  OpenSSH format public key to output (by default, stdout).

sigsum-key from-vkey [--verbose] [-k file] [-o output]
  Reads a vkey from file (by default, stdin) and writes the
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
	case "version", "--version", "-v":
		version.DisplayVersion("sigsum-key")
		os.Exit(0)
	case "generate", "gen":
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
		signature := readSignatureFile(settings.signatureFile)
		msg := readMessage(settings.namespace)
		if !crypto.Verify(&publicKey, msg, &signature) {
			log.Fatalf("signature is not valid\n")
		}
	case "sign":
		var settings SignSettings
		settings.parse(os.Args)
		signer, err := key.ReadPrivateKeyFile(settings.keyFile)
		if err != nil {
			log.Fatal(err)
		}
		msg := readMessage(settings.namespace)
		signature, err := signer.Sign(msg)
		if err != nil {
			log.Fatalf("signing failed: %v", err)
		}
		writeSignatureFile(settings.outputFile, &signature)

	case "to-hash":
		var settings ExportSettings
		settings.parse(os.Args, "")
		publicKey, err := key.ParsePublicKey(readInput(settings.keyFile))
		if err != nil {
			log.Fatal(err)
		}
		withOutput(settings.outputFile, 0660, func(f io.Writer) error {
			_, err := fmt.Fprintf(f, "%x\n", crypto.HashBytes(publicKey[:]))
			return err
		})
	case "to-hex":
		var settings ExportSettings
		settings.parse(os.Args, "")
		publicKey, err := key.ParsePublicKey(readInput(settings.keyFile))
		if err != nil {
			log.Fatal(err)
		}
		withOutput(settings.outputFile, 0660, func(f io.Writer) error {
			_, err := fmt.Fprintf(f, "%x\n", publicKey[:])
			return err
		})
	case "to-vkey":
		var settings VkeyExportSettings
		settings.parse(os.Args)
		publicKey, err := key.ParsePublicKey(readInput(settings.keyFile))
		if err != nil {
			log.Fatalf("invalid key: %v", err)
		}
		name := settings.name
		if name == "" {
			if settings.keyType != checkpoint.SigTypeEd25519 {
				log.Fatal("Key name (-n) option is required for cosignature/v1 keys")
			}
			name = types.SigsumCheckpointOrigin(&publicKey)
		}
		nv := checkpoint.NewNoteVerifier(name, settings.keyType, &publicKey)
		withOutput(settings.outputFile, 0660, func(f io.Writer) error {
			_, err := fmt.Fprintln(f, nv.String())
			return err
		})
	case "from-hex":
		var settings ExportSettings
		settings.parse(os.Args, "Hex public key")
		pub, err := crypto.PublicKeyFromHex(strings.TrimSpace(readInput(settings.keyFile)))
		if err != nil {
			log.Fatalf("invalid key: %v", err)
		}
		withOutput(settings.outputFile, 0660, func(f io.Writer) error {
			_, err := fmt.Fprint(f, ssh.FormatPublicEd25519(&pub))
			return err
		})
	case "from-vkey":
		var settings VkeyImportSettings
		settings.parse(os.Args)
		var nv checkpoint.NoteVerifier
		if err := nv.FromString(strings.TrimSpace(readInput(settings.keyFile))); err != nil {
			log.Fatal(err)
		}
		if settings.verbose {
			var keyType string
			switch nv.Type {
			case checkpoint.SigTypeEd25519:
				keyType = "ed25519"
			case checkpoint.SigTypeCosignature:
				keyType = "cosignature/v1"
			default:
				keyType = "unknown"
			}
			log.Printf("Key name %q, key type: 0x%02x (%s)", nv.Name, nv.Type, keyType)
		}
		if want := checkpoint.NewKeyId(nv.Name, nv.Type, &nv.PublicKey); nv.KeyId != want {
			// TODO: Add --force to proceeed regardless.
			log.Fatalf("Verifier Key id %x is inconsistent with name and public key, expected %x", nv.KeyId, want)
		}
		withOutput(settings.outputFile, 0660, func(f io.Writer) error {
			_, err := fmt.Fprint(f, ssh.FormatPublicEd25519(&nv.PublicKey))
			return err
		})
	}
}

func newOptionSet(args []string, params string) *getopt.Set {
	set := getopt.New()
	set.SetProgram(args[0] + " " + args[1])
	set.SetParameters(params)
	return set
}

// Also adds and processes the help option.
func parseArgs(set *getopt.Set, args []string, maxArgs int) {
	help := false
	set.FlagLong(&help, "help", 0, "Display help")
	err := set.Getopt(args[1:], nil)
	// Check help first; if seen, ignore errors about missing mandatory arguments.
	if help {
		set.PrintUsage(os.Stdout)
		fmt.Printf("\nFor general information on this tool, see %s help.\n", args[0])
		os.Exit(0)
	}
	if err != nil {
		log.Printf("err: %v\n", err)
		set.PrintUsage(log.Writer())
		os.Exit(1)
	}
	if set.NArgs() > maxArgs {
		log.Fatal("Too many arguments.")
	}
}

func parseNoArgs(set *getopt.Set, args []string) {
	parseArgs(set, args, 0)
}

func (s *GenSettings) parse(args []string) {
	set := newOptionSet(args, "")
	set.Flag(&s.outputFile, 'o', "Output", "file").Mandatory()
	parseNoArgs(set, args)
}

func (s *VerifySettings) parse(args []string) {
	// By default, no namespace.
	s.namespace = ""

	set := newOptionSet(args, "< msg")
	set.FlagLong(&s.keyFile, "key", 'k', "Public key", "file").Mandatory()
	set.FlagLong(&s.signatureFile, "signature", 's', "Signature", "file").Mandatory()
	set.FlagLong(&s.namespace, "namespace", 'n', "Signature namespace")
	parseNoArgs(set, args)
}

func (s *SignSettings) parse(args []string) {
	// By default, no namespace.
	s.namespace = ""

	set := newOptionSet(args, "< msg")
	set.FlagLong(&s.keyFile, "signing-key", 'k', "Private key for signing", "file").Mandatory()
	set.Flag(&s.outputFile, 'o', "Signature output", "file")
	set.FlagLong(&s.namespace, "namespace", 'n', "Signature namespace")
	parseNoArgs(set, args)
}

func (s *ExportSettings) parse(args []string, keyHelp string) {
	set := newOptionSet(args, "")
	if keyHelp == "" {
		keyHelp = "Public key"
	}
	set.FlagLong(&s.keyFile, "key", 'k', keyHelp, "file")
	set.Flag(&s.outputFile, 'o', "Output", "file")
	parseNoArgs(set, args)
}

func (s *VkeyImportSettings) parse(args []string) {
	set := newOptionSet(args, "")
	set.FlagLong(&s.keyFile, "key", 'k', "Signed note verifier (vkey)", "file")
	set.Flag(&s.outputFile, 'o', "Output", "file")
	set.FlagLong(&s.verbose, "verbose", 'v', "Display name and type of the key")
	parseNoArgs(set, args)
}

func (s *VkeyExportSettings) parse(args []string) {
	set := newOptionSet(args, "")
	keyType := ""
	set.FlagLong(&s.keyFile, "key", 'k', "Public key", "file")
	set.Flag(&s.outputFile, 'o', "Output", "file")
	set.Flag(&s.name, 'n', "Key name (defaults to the origin line of a Sigsum log server)", "name")
	set.Flag(&keyType, 't', "Signature type. 'ed25519' (default) or 'cosignature/v1'", "type")
	parseNoArgs(set, args)
	switch keyType {
	default:
		log.Fatalf("Unknown signature type %q, must be 'ed25519' or 'cosignature/v1'", keyType)
	case "", "ed25519":
		s.keyType = checkpoint.SigTypeEd25519
	case "cosignature/v1":
		s.keyType = checkpoint.SigTypeCosignature
	}
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

func writeSignatureFile(outputFile string, signature *crypto.Signature) {
	withOutput(outputFile, 0644, func(f io.Writer) error {
		_, err := fmt.Fprintf(f, "%x\n", signature[:])
		return err
	})
}

func readSignatureFile(fileName string) crypto.Signature {
	contents, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatalf("reading file %q failed: %v", fileName, err)
	}
	signature, err := crypto.SignatureFromHex(strings.TrimSpace(string(contents)))
	if err != nil {
		log.Fatal(err)
	}
	return signature
}

// Read message being signed from stdin. Prepend namespace if it is nonempty.
func readMessage(namespace string) []byte {
	var buf bytes.Buffer
	if len(namespace) > 0 {
		buf.Write(crypto.AttachNamespace(namespace, []byte{}))
	}

	_, err := io.Copy(&buf, os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	return buf.Bytes()
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
