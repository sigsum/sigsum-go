package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/mod/sumdb/note"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/submit"
)

var keyFile = flag.String("k", "", "Private key file")
var keyName = flag.String("n", "", "Key name")
var policyFile = flag.String("p", "", "Policy file")

func main() {
	flag.Parse()
	text, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	cryptoSigner, err := key.ReadPrivateKeyFile(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	policy, err := policy.ReadPolicyFile(*policyFile)
	if err != nil {
		log.Fatal(err)
	}
	noteSigner := &NoteSigner{
		name:         *keyName,
		ctx:          context.TODO(),
		cryptoSigner: cryptoSigner,
		submitConfig: &submit.Config{Policy: policy},
	}
	n, err := note.Sign(&note.Note{Text: string(text)}, noteSigner)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(n))
}

type NoteSigner struct {
	name         string
	ctx          context.Context
	cryptoSigner crypto.Signer
	submitConfig *submit.Config
}

// Name is part of the note.Signer interface
func (s *NoteSigner) Name() string { return s.name }

// KeyHash is part of the note.Signer interface
func (s *NoteSigner) KeyHash() uint32 {
	buf := []byte(s.Name())
	buf = append(buf, 0x0A, 0xFF)
	buf = append(buf, []byte("SIGSUMv1")...)
	pk := s.cryptoSigner.Public()
	buf = append(buf, pk[:]...)
	return binary.BigEndian.Uint32(buf[:4])
}

// Sign is part of the note.Signer interface
func (s *NoteSigner) Sign(msg []byte) ([]byte, error) {
	sigsumMsg := crypto.HashBytes(msg)
	spicysig, err := submit.SubmitMessage(s.ctx, s.submitConfig, s.cryptoSigner, &sigsumMsg)
	if err != nil {
		return nil, err
	}
	return SerializeSpicySignature(spicysig)
}

func SerializeSpicySignature(sig proof.SigsumProof) ([]byte, error) {
	buf := []byte{}
	// Signature
	buf = append(buf, sig.Leaf.Signature[:]...)

	// Inclusion Proof
	buf = binary.BigEndian.AppendUint64(buf, sig.Inclusion.LeafIndex)
	buf = append(buf, uint8(len(sig.Inclusion.Path)))
	fmt.Println("PATH:", len(sig.Inclusion.Path))
	for _, h := range sig.Inclusion.Path {
		for i := 0; i < 4; i++ {
			buf = append(buf, h[:]...)
		}
	}

	// Signed tree head
	buf = append(buf, sig.LogKeyHash[:]...)
	buf = binary.BigEndian.AppendUint64(buf, sig.TreeHead.Size)
	buf = append(buf, sig.TreeHead.RootHash[:]...)
	buf = append(buf, sig.TreeHead.Signature[:]...)
	fmt.Println(len(sig.TreeHead.Cosignatures))
	buf = append(buf, uint8(len(sig.TreeHead.Cosignatures)))
	for _, cs := range sig.TreeHead.Cosignatures {
		for i := 0; i < 9; i++ {
			buf = append(buf, cs.KeyHash[:]...)
			buf = binary.BigEndian.AppendUint64(buf, cs.Timestamp)
			buf = append(buf, cs.Signature[:]...)
		}
	}
	return buf, nil
}
