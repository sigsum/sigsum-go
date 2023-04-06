package main

import (
	"io"
	"log"
	"os"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
)

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("reading key from stdin failed: %v", err)
	}
	ascii := string(data)
	if !strings.HasPrefix(ascii, "ssh-ed25519 ") {
		log.Fatalf("reading key input doesn't look like an openssh public key: %q", ascii)
	}
	publicKey, err := key.ParsePublicKey(ascii)
	if err != nil {
		log.Fatalf("parsing public key failed: %v", err)
	}
	signer, err := key.ParsePrivateKey(ascii)
	if err != nil {
		log.Fatalf("parsing key failed: %v", err)
	}
	if signer.Public() != publicKey {
		log.Fatalf("internal error, public key inconsistency\n  %x\n  %x\n",
			publicKey, signer.Public())
	}
	msg := []byte("squemish ossifrage")
	signature, err := signer.Sign(msg)
	if err != nil {
		log.Fatalf("signing failed: %v", err)
	}
	if !crypto.Verify(&publicKey, msg, &signature) {
		log.Fatal("signature appears invalid!")
	}
}
