package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/submit-token"
)

type createSettings struct {
	keyFile    string
	outputFile string
	logKeyFile string
	domain     string
}

type recordSettings struct {
	keyFile    string
	outputFile string
}

type verifySettings struct {
	keyFile    string
	logKeyFile string
	domain     string
	quiet      bool
}

func main() {
	const usage = `sigsum-token sub commands:

  sigsum-token create -k KEY-FILE --log PUBKEY [--domain DOMAIN] [-o OUTPUT-FILE]
    Create a token for submissions to the the given log, essentially
    a signature using the given private key. If --domain is given, output
    a complete HTTP header.

  sigsum-token record -k PUBKEY-FILE [-o OUTPUT-FILE]
    Format the public key as a TXT record in zone file format.

  sigsum-token verify --log PUBKEY [-k PUBKEY] [--domain DOMAIN] [-q] < TOKEN
    Verifies a submit token. The input on stdin is either a raw hex
    token or a HTTP header. For a raw token, one of -k or --domain is required. For
    a HTTP header --key and --domain are optional, but validation
    fails if they are inconsistent with what{s looked up from the HTTP
    header. The -q (quiet) option suppresses output on validation
    errors, with result only reflected in the exit code.

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
	case "create":
		var settings createSettings
		settings.parse(args)
		signer := readPrivateKeyFile(settings.keyFile)
		logKey := readPublicKeyFile(settings.logKeyFile)
		signature, err := token.MakeToken(signer, &logKey)
		if err != nil {
			log.Fatalf("signing failed: %v", err)
		}
		withOutput(settings.outputFile, func(w io.Writer) error {
			if len(settings.domain) > 0 {
				_, err := fmt.Fprintf(w, "sigsum-token: %s %x\n", settings.domain, signature)
				return err
			}
			_, err := fmt.Fprintf(w, "%x\n", signature)
			return err
		})
	case "record":
		var settings recordSettings
		settings.parse(args)
		logKey := readPublicKeyFile(settings.keyFile)
		withOutput(settings.outputFile, func(w io.Writer) error {
			_, err := fmt.Fprintf(w, "%s IN TXT \"%x\"\n", token.Label, logKey)
			return err
		})
	case "verify":
		var settings verifySettings
		settings.parse(args)
		if settings.quiet {
			log.SetOutput(nil)
		}
		logKey := readPublicKeyFile(settings.logKeyFile)
		contents, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("Reading input failed: %v", err)
		}
		input := string(contents)
		var domain *string
		var signatureHex string

		if colon := strings.Index(input, ":"); colon >= 0 {
			if !strings.EqualFold(input[:colon], token.HeaderName) {
				log.Fatalf("Invalid header, expected a %s:-line", token.HeaderName)
			}
			headerValue := strings.TrimLeft(input[colon+1:], " \t")
			parts := strings.Split(headerValue, " ")
			if len(parts) != 2 {
				log.Fatalf("Invalid Sigsum-Token value: %q", headerValue)
			}
			domain = &parts[0]
			if len(settings.domain) > 0 && !strings.EqualFold(*domain, settings.domain) {
				log.Fatalf("Unexpected domain: %q", *domain)
			}
			signatureHex = strings.TrimSuffix(parts[1], "\n")
		} else {
			signatureHex = strings.TrimSpace(input)
			if len(settings.domain) > 0 {
				domain = &settings.domain
			}
		}
		if domain != nil {
			if err := token.NewDnsVerifier(&logKey).Verify(
				context.Background(), *domain, signatureHex); err != nil {
				log.Fatalf("Verifying with domain %q failed: %v", *domain, err)
			}
		}
		if len(settings.keyFile) > 0 {
			key := readPublicKeyFile(settings.keyFile)
			if err := token.VerifyToken(&key, &logKey, signatureHex); err != nil {
				log.Fatalf("Verifying using given key failed: %v", err)
			}
		}
	}
}

func (s *createSettings) parse(args []string) {
	flags := flag.NewFlagSet("", flag.ExitOnError)

	flags.StringVar(&s.keyFile, "k", "", "Private key file")
	flags.StringVar(&s.outputFile, "o", "", "Output file")
	flags.StringVar(&s.logKeyFile, "log", "", "Log public key file")
	flags.StringVar(&s.domain, "domain", "", "Domain")

	flags.Parse(args)

	if len(s.keyFile) == 0 {
		log.Fatalf("key file (-k option) missing")
	}
	if len(s.logKeyFile) == 0 {
		log.Fatalf("log public key file (--log option) missing")
	}
}

func (s *recordSettings) parse(args []string) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.StringVar(&s.keyFile, "k", "", "Private key file")
	flags.StringVar(&s.outputFile, "o", "", "Output file")

	flags.Parse(args)

	if len(s.keyFile) == 0 {
		log.Fatalf("key file (-k option) missing")
	}
}

func (s *verifySettings) parse(args []string) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.StringVar(&s.keyFile, "k", "", "Private key file")
	flags.StringVar(&s.logKeyFile, "log", "", "Log public key file")
	flags.StringVar(&s.domain, "domain", "", "Domain")
	flags.BoolVar(&s.quiet, "q", false, "Quiet mode")

	flags.Parse(args)

	if len(s.logKeyFile) == 0 {
		log.Fatalf("log public key file (---log option) missing")
	}
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

// If outputFile is non-empty: open file, pass to f, and automatically
// close it after f returns. Otherwise, just pass os.Stdout to f. Also
// exit program on error from f.
func withOutput(outputFile string, f func(io.Writer) error) {
	file := os.Stdout
	if len(outputFile) > 0 {
		var err error
		file, err = os.OpenFile(outputFile,
			os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
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
