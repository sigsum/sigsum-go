package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
)

type GenSettings struct {
	outputFile string
	sshFormat  bool
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

func main() {
	const usage = `sigsum key sub commands:

  sigsum-key help 
    Display this help.

  sigsum-key gen -o KEY-FILE [--ssh] Generate a new key pair.
    Private key is stored in the given KEY-FILE, hex-encoded.
    Corresponding public key file gets a ".pub" suffix.
    If --ssh option is used, the public file is written in
    OpenSSH format, otherwise raw hex.

  sigsum-key verify -k KEY -s SIGNATURE [-n NAMESPACE] < MSG
    KEY and SIGNATURE are file names.
    NAMESPACE is a string, default being "tree_head:v0@sigsum.org"

  sigsum-key sign --ssh -k KEY [-n NAMESPACE] [-o SIGNATURE] < MSG
    KEY and SIGNATURE are file names.
    NAMESPACE is a string, default being "tree-leaf:v0@sigsum.org"
    If --ssh is provided, produce an ssh signature file, otherwise raw hex.
`
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
		priv := signer.Private()
		writeKeyFile(settings.outputFile, settings.sshFormat,
			&pub, &priv)
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
	}
}

func parseGenSettings(args []string) GenSettings {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	outputFile := flags.String("o", "", "Output file")
	sshFormat := flags.Bool("ssh", false, "Use OpenSSH format for public key")

	flags.Parse(args)

	if len(*outputFile) == 0 {
		log.Printf("output file (-o option) missing")
		os.Exit(1)
	}
	return GenSettings{*outputFile, *sshFormat}
}

func parseVerifySettings(args []string) VerifySettings {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	keyFile := flags.String("k", "", "Key file")
	signatureFile := flags.String("s", "", "Signature file")
	namespace := flags.String("n", "tree-head:v0@sigsum.org", "Signature namespace")

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

func writeToFile(fileName string, data string, mode os.FileMode) {
	file, err := os.OpenFile(fileName,
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		log.Fatalf("failed to open file '%v': %v", fileName, err)
	}
	defer file.Close()
	_, err = fmt.Fprint(file, data)
	if err != nil {
		log.Fatalf("write failed to file '%v': %v", fileName, err)
	}
}

func writeKeyFile(outputFile string, sshFormat bool,
	pub *crypto.PublicKey, priv *crypto.PrivateKey) {
	writeToFile(outputFile, hex.EncodeToString(priv[:]), 0600)

	var serializedPub string
	if sshFormat {
		serializedPub = ssh.FormatPublicEd25519(pub)
	} else {
		serializedPub = hex.EncodeToString(pub[:])
	}
	// Openssh insists that also public key files have
	// restrictive permissions.
	writeToFile(outputFile+".pub", serializedPub, 0600)
}

func writeSignatureFile(outputFile string, sshFormat bool,
	public *crypto.PublicKey, namespace string, signature *crypto.Signature) {
	file := os.Stdout
	var err error
	if len(outputFile) > 0 {
		file, err = os.OpenFile(outputFile,
			os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("failed to open file '%v': %v", outputFile, err)
		}
		defer file.Close()
	}
	if sshFormat {
		err = ssh.WriteSignatureFile(file, public, namespace, signature)
	} else {
		_, err = fmt.Fprintf(file, "%x\n", signature[:])
	}
	if err != nil {
		log.Fatalf("writing signature output failed: %v", err)
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
