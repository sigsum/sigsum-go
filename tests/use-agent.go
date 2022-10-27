package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"io"
	"log"
	"os"
	"strings"

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
	pubKey, err := key.ParsePublicKey(ascii)
	if err != nil {
		log.Fatalf("parsing public key failed: %v", err)
	}
	signer, err := key.ParsePrivateKey(ascii)
	if err != nil {
		log.Fatalf("parsing key failed: %v", err)
	}
	if !bytes.Equal(signer.Public().(ed25519.PublicKey), pubKey[:]) {
		log.Fatalf("internal error, public key inconsistency\n  %x\n  %x\n",
			pubKey, signer.Public().(ed25519.PublicKey))
	}
	msg := []byte("squemish ossifrage")
	signature, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		log.Fatalf("signing failed: %v", err)
	}
	if !ed25519.Verify(pubKey[:], msg, signature) {
		log.Fatal("signature appears invalid!")
	}
}
