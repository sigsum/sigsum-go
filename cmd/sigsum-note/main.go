package main

import (
	"bytes"
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
	"sigsum.org/sigsum-go/pkg/types"
)

var keyFile = flag.String("k", "", "Private key file")
var keyName = flag.String("n", "", "Key name")
var policyFile = flag.String("p", "", "Policy file")
var signFlag = flag.Bool("sign", false, "Sign")
var verifyFlag = flag.Bool("verify", false, "Verify")

func main() {
	flag.Parse()
	if *signFlag == *verifyFlag {
		log.Fatal("Pass -sign or -verify, but not both")
	} else if *signFlag {
		sign()
	} else if *verifyFlag {
		verify()
	}
}

func sign() {
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
	return keyid(s.name, s.cryptoSigner.Public())
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
	for _, h := range sig.Inclusion.Path {
		buf = append(buf, h[:]...)
	}

	// Signed tree head
	buf = append(buf, sig.LogKeyHash[:]...)
	buf = binary.BigEndian.AppendUint64(buf, sig.TreeHead.Size)
	buf = append(buf, sig.TreeHead.RootHash[:]...)
	buf = append(buf, sig.TreeHead.Signature[:]...)
	buf = append(buf, uint8(len(sig.TreeHead.Cosignatures)))
	for _, cs := range sig.TreeHead.Cosignatures {
		buf = append(buf, cs.KeyHash[:]...)
		buf = binary.BigEndian.AppendUint64(buf, cs.Timestamp)
		buf = append(buf, cs.Signature[:]...)
	}
	return buf, nil
}

func verify() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	pubkey, err := key.ReadPublicKeyFile(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	pol, err := policy.ReadPolicyFile(*policyFile)
	if err != nil {
		log.Fatal(err)
	}
	verifier := NoteVerifier{
		name:   *keyName,
		pubkey: pubkey,
		pol:    pol,
	}
	n, err := note.Open(input, note.VerifierList(&verifier))
	// n, err := note.Open(input, note.VerifierList())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(n.Text)
}

type NoteVerifier struct {
	name   string
	pubkey crypto.PublicKey
	pol    *policy.Policy
}

func (v *NoteVerifier) Name() string { return v.name }

func (v *NoteVerifier) KeyHash() uint32 { return keyid(v.name, v.pubkey) }

func (v *NoteVerifier) Verify(msg, sig []byte) bool {
	sigsumMsg := crypto.HashBytes(msg)
	p, _ := DeserializeSpicySignature(sig)
	checksum := crypto.HashBytes(sigsumMsg[:])
	copy(p.Leaf.ShortChecksum[:], checksum[:proof.ShortChecksumSize])
	p.Leaf.KeyHash = crypto.HashBytes(v.pubkey[:])
	err := p.Verify(&sigsumMsg, &v.pubkey, v.pol)
	return err == nil
}

func DeserializeSpicySignature(spicy []byte) (proof.SigsumProof, error) {
	buf := bytes.NewBuffer(spicy)
	var result proof.SigsumProof
	// Signature
	copy(result.Leaf.Signature[:], buf.Next(crypto.SignatureSize))

	// Inclusion proof
	result.Inclusion.LeafIndex = binary.BigEndian.Uint64(buf.Next(8))
	pathlen, _ := buf.ReadByte()
	result.Inclusion.Path = make([]crypto.Hash, pathlen)
	for i := 0; i < int(pathlen); i++ {
		copy(result.Inclusion.Path[i][:], buf.Next(crypto.HashSize))
	}

	// Signed tree head
	copy(result.LogKeyHash[:], buf.Next(crypto.HashSize))
	result.TreeHead.Size = binary.BigEndian.Uint64(buf.Next(8))
	copy(result.TreeHead.RootHash[:], buf.Next(crypto.HashSize))
	copy(result.TreeHead.Signature[:], buf.Next(crypto.SignatureSize))
	cosiglen, _ := buf.ReadByte()
	result.TreeHead.Cosignatures = make([]types.Cosignature, cosiglen)
	for i := 0; i < int(cosiglen); i++ {
		copy(result.TreeHead.Cosignatures[i].KeyHash[:], buf.Next(crypto.HashSize))
		result.TreeHead.Cosignatures[i].Timestamp = binary.BigEndian.Uint64(buf.Next(8))
		copy(result.TreeHead.Cosignatures[i].Signature[:], buf.Next(crypto.SignatureSize))
	}

	return result, nil
}

func keyid(name string, pubkey crypto.PublicKey) uint32 {
	buf := []byte(name)
	buf = append(buf, 0x0A, 0xFF)
	buf = append(buf, []byte("SIGSUMv1")...)
	buf = append(buf, pubkey[:]...)
	return binary.BigEndian.Uint32(buf[:4])
}
