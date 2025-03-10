package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/pborman/getopt/v2"

	"sigsum.org/sigsum-go/internal/version"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	token "sigsum.org/sigsum-go/pkg/submit-token"
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
	const usage = `
Utility commands that help configure DNS and create/verify tokens.
Such setup allows log servers to apply rate-limits per domain name.

Note that sigsum-submit can create tokens on-the-fly.  As a user you
mainly need to setup a DNS TXT record, see the record subcommand.

Usage: sigsum-token [--help|help] [--version|version]
   or: sigsum-token create [options]
   or: sigsum-token record [options]
   or: sigsum-token verify [options] < token

Options:
      --help     Show usage message and exit
  -v, --version  Show program version and exit
`
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal(usage)
	}

	switch os.Args[1] {
	default:
		log.Fatal(usage[1:])
	case "help", "--help":
		fmt.Print(usage[1:])
		os.Exit(0)
	case "version", "--version", "-v":
		version.DisplayVersion("sigsum-token")
		os.Exit(0)
	case "create":
		var settings createSettings
		settings.parse(os.Args)
		signer, err := key.ReadPrivateKeyFile(settings.keyFile)
		if err != nil {
			log.Fatal(err)
		}
		logKey, err := key.ReadPublicKeyFile(settings.logKeyFile)
		if err != nil {
			log.Fatal(err)
		}

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
		settings.parse(os.Args)
		logKey, err := key.ReadPublicKeyFile(settings.keyFile)
		if err != nil {
			log.Fatal(err)
		}
		withOutput(settings.outputFile, func(w io.Writer) error {
			_, err := fmt.Fprintf(w, "%s IN TXT \"%x\"\n", token.Label, logKey)
			return err
		})
	case "verify":
		var settings verifySettings
		settings.parse(os.Args)
		if settings.quiet {
			log.SetOutput(io.Discard)
		}
		logKey, err := key.ReadPublicKeyFile(settings.logKeyFile)
		if err != nil {
			log.Fatal(err)
		}
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
		signature, err := crypto.SignatureFromHex(signatureHex)
		if err != nil {
			log.Fatalf("Invalid hex signature: %v", err)
		}
		if domain != nil {
			if err := token.NewDnsVerifier(&logKey).Verify(
				context.Background(),
				&token.SubmitHeader{Domain: *domain, Token: signature}); err != nil {
				log.Fatalf("Verifying with domain %q failed: %v", *domain, err)
			}
		}
		if len(settings.keyFile) > 0 {
			key, err := key.ReadPublicKeyFile(settings.keyFile)
			if err != nil {
				log.Fatal(err)
			}
			if err := token.VerifyToken(&key, &logKey, &signature); err != nil {
				log.Fatalf("Verifying using given key failed: %v", err)
			}
		}
	}
}

func newOptionSet(args []string, parameters string) *getopt.Set {
	set := getopt.New()
	set.SetProgram(os.Args[0] + " " + os.Args[1])
	set.SetParameters(parameters)
	return set
}

// Also adds and processes the help option.
func parseNoArgs(set *getopt.Set, args []string, usage string) {
	help := false
	set.FlagLong(&help, "help", 0, "Display help")
	err := set.Getopt(args[1:], nil)
	// Check help first; if seen, ignore errors about missing mandatory arguments.
	if help {
		fmt.Print(usage[1:] + "\n")
		set.PrintUsage(os.Stdout)
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

func (s *createSettings) parse(args []string) {
	set := newOptionSet(args, "")
	set.FlagLong(&s.keyFile, "signing-key", 'k', "Private key in OpenSSH format to sign the token with; or a corresponding public key where the private part is accessed using the SSH agent protocol", "key-file").Mandatory()
	set.FlagLong(&s.outputFile, "output", 'o', "Store output in a file", "output-file")
	set.FlagLong(&s.logKeyFile, "log-key", 'l', "The log's public key in OpenSSH format", "key-file").Mandatory()
	set.FlagLong(&s.domain, "domain", 'd', "Domain name where the rate-limit public-key is available as a TXT record; without any \"_sigsum_v1.\" prefix", "domain-name")
	parseNoArgs(set, args, `
Create a token for submissions to the the given log.  This is
essentially a signature on the log's public key.  Outputs a complete
HTTP header if a domain name is provided (-d option).
`)
}

func (s *recordSettings) parse(args []string) {
	set := newOptionSet(args, "")
	set.FlagLong(&s.keyFile, "key", 'k', "Rate-limit public-key in OpenSSH format", "key-file").Mandatory()
	set.FlagLong(&s.outputFile, "output", 'o', "Store output in a file", "output-file")
	parseNoArgs(set, args, `
Format the rate-limit key as a TXT record in zone-file format.
`)
}

func (s *verifySettings) parse(args []string) {
	set := newOptionSet(args, "<token")
	set.FlagLong(&s.keyFile, "key", 'k', "Rate-limit public-key in OpenSSH format", "key-file")
	set.FlagLong(&s.logKeyFile, "log-key", 'l', "Log public-key in OpenSSH format", "key-file").Mandatory()
	set.FlagLong(&s.domain, "domain", 'd', "Domain name where the rate-limit key is available as a TXT record; without any \"_sigsum_v1.\" prefix", "domain-name")
	set.FlagLong(&s.quiet, "quiet", 'q', "Quiet mode")
	parseNoArgs(set, args, `
Verify a submit token.  The input on stdin is either a raw hex token
or an HTTP header.  For a raw token, one of --key or --domain is
required.  For an HTTP header, --key and --domain are optional, but
validation fails if they are inconsistent with what's looked up from
the HTTP header.  The -q (quiet) option suppresses output on
validation errors, with result only reflected in the exit code.
`)
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
