package main

import (
	"crypto"
	"crypto/ed25519"
	"io"
	"log"
	"os"

	"sigsum.org/sigsum-go/internal/ssh"
)

func main() {
	ascii, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("reading key from stdin failed: %v", err)
	}
	pubKey, err := ssh.ParsePublicEd25519(string(ascii))
	if err != nil {
		log.Fatalf("bad public key: %v", err)
	}

	agent, err := ssh.Connect()
	if err != nil {
		log.Fatalf("connecting to ssh agent failed: %v", err)
	}

	var signer crypto.Signer
	signer, err = agent.NewSigner(pubKey)
	if err != nil {
		log.Fatalf("creating signer failed: %v", err)
	}

	msg := []byte("squemish ossifrage")
	signature, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		log.Fatalf("signing failed: %v", err)
	}
	if !ed25519.Verify(pubKey, msg, signature) {
		log.Fatal("signature appears invalid!")
	}
}
