package types

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
)

const (
	CosignatureNamespace = "cosignature/v1"
	CheckpointNamePrefix = "sigsum.org/v1/tree/"
)

type TreeHead struct {
	Size     uint64
	RootHash crypto.Hash
}

type SignedTreeHead struct {
	TreeHead
	Signature crypto.Signature
}

type Cosignature struct {
	KeyHash   crypto.Hash
	Timestamp uint64
	Signature crypto.Signature
}

type CosignedTreeHead struct {
	SignedTreeHead
	Cosignatures []Cosignature
}

func NewEmptyTreeHead() TreeHead {
	return TreeHead{Size: 0, RootHash: merkle.HashEmptyTree()}
}

func (th *TreeHead) formatCheckpoint(prefix string, keyHash *crypto.Hash) string {
	return fmt.Sprintf("%s%x\n%d\n%s\n",
		prefix,
		*keyHash, th.Size,
		base64.StdEncoding.EncodeToString(th.RootHash[:]))
}

func (th *TreeHead) toCheckpoint(keyHash *crypto.Hash) string {
	return th.formatCheckpoint(CheckpointNamePrefix, keyHash)
}

func (th *TreeHead) Sign(signer crypto.Signer) (SignedTreeHead, error) {
	pub := signer.Public()
	keyHash := crypto.HashBytes(pub[:])
	sig, err := signer.Sign([]byte(th.toCheckpoint(&keyHash)))
	if err != nil {
		return SignedTreeHead{}, fmt.Errorf("failed signing tree head: %w", err)
	}

	return SignedTreeHead{
		TreeHead:  *th,
		Signature: sig,
	}, nil
}

// TODO: Should the Cosign method be attached to SignedTreeHead instead?
func (th *TreeHead) toCosignedData(logKeyHash *crypto.Hash, timestamp uint64) string {
	return fmt.Sprintf("%s\ntime %d\n%s",
		CosignatureNamespace, timestamp,
		th.toCheckpoint(logKeyHash))
}

func (th *TreeHead) Cosign(signer crypto.Signer, logKeyHash *crypto.Hash, timestamp uint64) (Cosignature, error) {
	signature, err := signer.Sign([]byte(th.toCosignedData(logKeyHash, timestamp)))
	if err != nil {
		return Cosignature{}, fmt.Errorf("failed co-signing tree head: %w", err)
	}
	pub := signer.Public()
	return Cosignature{
		KeyHash:   crypto.HashBytes(pub[:]),
		Timestamp: timestamp,
		Signature: signature,
	}, nil
}

func (th *TreeHead) ToASCII(w io.Writer) error {
	if err := ascii.WriteInt(w, "size", th.Size); err != nil {
		return err
	}
	return ascii.WriteHash(w, "root_hash", &th.RootHash)
}

// Doesn't require EOF, so it can be used for parsing a tree head
// embedded in a larger struct.
func (th *TreeHead) Parse(p *ascii.Parser) error {
	var err error
	th.Size, err = p.GetInt("size")
	if err != nil {
		return err
	}
	th.RootHash, err = p.GetHash("root_hash")
	return err
}

func (th *TreeHead) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	err := th.Parse(&p)
	if err != nil {
		return err
	}
	return p.GetEOF()
}

func (sth *SignedTreeHead) ToASCII(w io.Writer) error {
	if err := sth.TreeHead.ToASCII(w); err != nil {
		return err
	}
	return ascii.WriteSignature(w, "signature", &sth.Signature)
}

func (sth *SignedTreeHead) Parse(p *ascii.Parser) error {
	err := sth.TreeHead.Parse(p)
	if err != nil {
		return err
	}
	sth.Signature, err = p.GetSignature("signature")
	return err
}

func (sth *SignedTreeHead) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	err := sth.Parse(&p)
	if err != nil {
		return err
	}
	return p.GetEOF()
}

func (sth *SignedTreeHead) Verify(key *crypto.PublicKey) bool {
	keyHash := crypto.HashBytes(key[:])
	return crypto.Verify(key, []byte(sth.toCheckpoint(&keyHash)), &sth.Signature)
}

func (sth *SignedTreeHead) VerifyVersion0(key *crypto.PublicKey) bool {
	// Prefix used temporarily, for version v0.1.15 and v0.2.0.
	keyHash := crypto.HashBytes(key[:])
	if crypto.Verify(key, []byte(sth.formatCheckpoint("sigsum.org/v1/", &keyHash)), &sth.Signature) {
		return true
	}
	b := make([]byte, 40)
	binary.BigEndian.PutUint64(b[:8], sth.Size)
	copy(b[8:40], sth.RootHash[:])
	return crypto.Verify(key, ssh.SignedData("signed-tree-head:v0@sigsum.org", b),
		&sth.Signature)
}

func (cs *Cosignature) Verify(key *crypto.PublicKey, logKeyHash *crypto.Hash, th *TreeHead) bool {
	return crypto.Verify(key, []byte(th.toCosignedData(logKeyHash, cs.Timestamp)), &cs.Signature)
}

func (cs *Cosignature) ToASCII(w io.Writer) error {
	return ascii.WriteLine(w, "cosignature", cs.KeyHash[:], cs.Timestamp, cs.Signature[:])
}

func (cs *Cosignature) Parse(p *ascii.Parser) error {
	v, err := p.GetValues("cosignature", 3)
	if err != nil {
		return err
	}
	cs.KeyHash, err = crypto.HashFromHex(v[0])
	if err != nil {
		return err
	}
	cs.Timestamp, err = ascii.IntFromDecimal(v[1])
	if err != nil {
		return err
	}
	cs.Signature, err = crypto.SignatureFromHex(v[2])
	return err
}

func (cs *Cosignature) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	err := cs.Parse(&p)
	if err != nil {
		return err
	}
	return p.GetEOF()
}

func (cth *CosignedTreeHead) ToASCII(w io.Writer) error {
	if err := cth.SignedTreeHead.ToASCII(w); err != nil {
		return err
	}
	for _, cs := range cth.Cosignatures {
		if err := cs.ToASCII(w); err != nil {
			return err
		}
	}
	return nil
}

func ParseCosignatures(p *ascii.Parser) ([]Cosignature, error) {
	var cosignatures []Cosignature
	for {
		var cs Cosignature
		err := cs.Parse(p)
		if err == io.EOF {
			return cosignatures, nil
		}
		if err != nil {
			return nil, err
		}
		cosignatures = append(cosignatures, cs)
	}
}

func (cth *CosignedTreeHead) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	err := cth.SignedTreeHead.Parse(&p)
	if err != nil {
		return err
	}
	cth.Cosignatures, err = ParseCosignatures(&p)
	return err
}
