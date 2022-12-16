package types

import (
	"encoding/binary"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
)

const (
	TreeHeadNamespace = "tree-head:v0@sigsum.org"
)

type TreeHead struct {
	Size     uint64
	RootHash crypto.Hash
}

type SignedTreeHead struct {
	TreeHead
	Timestamp uint64
	Signature crypto.Signature
}

type Cosignature struct {
	KeyHash   crypto.Hash
	Signature crypto.Signature
}

type CosignedTreeHead struct {
	SignedTreeHead
	Cosignatures []Cosignature
}

func (th *TreeHead) toSignedData(keyHash *crypto.Hash, timestamp uint64) []byte {
	b := make([]byte, 80)
	binary.BigEndian.PutUint64(b[0:8], timestamp)
	binary.BigEndian.PutUint64(b[8:16], th.Size)
	copy(b[16:48], th.RootHash[:])
	copy(b[48:80], keyHash[:])
	return ssh.SignedData(TreeHeadNamespace, b)
}

func (th *TreeHead) Sign(signer crypto.Signer, kh *crypto.Hash, timestamp uint64) (*SignedTreeHead, error) {
	sig, err := signer.Sign(th.toSignedData(kh, timestamp))
	if err != nil {
		return nil, fmt.Errorf("types: failed signing tree head")
	}

	return &SignedTreeHead{
		TreeHead:  *th,
		Timestamp: timestamp,
		Signature: sig,
	}, nil
}

func (th *TreeHead) Verify(key *crypto.PublicKey, signature *crypto.Signature,
	kh *crypto.Hash, timestamp uint64) bool {
	return crypto.Verify(key, th.toSignedData(kh, timestamp), signature)
}

func (th *TreeHead) ToASCII(w io.Writer) error {
	if err := ascii.WriteInt(w, "size", th.Size); err != nil {
		return err
	}
	return ascii.WriteHash(w, "root_hash", &th.RootHash)
}

// Doesn't require EOF, so it can be used also with (co)signatures.
func (th *TreeHead) fromASCII(p *ascii.Parser) error {
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
	err := th.fromASCII(&p)
	if err != nil {
		return err
	}
	return p.GetEOF()
}

func (sth *SignedTreeHead) ToASCII(w io.Writer) error {
	if err := ascii.WriteInt(w, "timestamp", sth.Timestamp); err != nil {
		return err
	}
	if err := sth.TreeHead.ToASCII(w); err != nil {
		return err
	}
	return ascii.WriteSignature(w, "signature", &sth.Signature)
}

func (sth *SignedTreeHead) fromASCII(p *ascii.Parser) error {
	var err error
	sth.Timestamp, err = p.GetInt("timestamp")
	if err != nil {
		return err
	}
	err = sth.TreeHead.fromASCII(p)
	if err != nil {
		return err
	}
	sth.Signature, err = p.GetSignature("signature")
	return err
}

func (sth *SignedTreeHead) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	err := sth.fromASCII(&p)
	if err != nil {
		return err
	}
	return p.GetEOF()
}

func (sth *SignedTreeHead) Sign(signer crypto.Signer, kh *crypto.Hash) (crypto.Signature, error) {
	return signer.Sign(sth.TreeHead.toSignedData(kh, sth.Timestamp))
}

func (sth *SignedTreeHead) Verify(key *crypto.PublicKey, signature *crypto.Signature, logKeyHash *crypto.Hash) bool {
	return sth.TreeHead.Verify(key, signature, logKeyHash, sth.Timestamp)
}

func (sth *SignedTreeHead) VerifyLogSignature(key *crypto.PublicKey) bool {
	keyHash := crypto.HashBytes(key[:])
	return sth.Verify(key, &sth.Signature, &keyHash)
}

func (cs *Cosignature) ToASCII(w io.Writer) error {
	return ascii.WriteLine(w, "cosignature", cs.KeyHash[:], cs.Signature[:])
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

func cosignaturesFromASCII(p *ascii.Parser) ([]Cosignature, error) {
	var cosignatures []Cosignature
	for {
		v, err := p.GetValues("cosignature", 2)
		if err == io.EOF {
			return cosignatures, nil
		}
		if err != nil {
			return nil, err
		}

		keyHash, err := crypto.HashFromHex(v[0])
		if err != nil {
			return nil, err
		}
		signature, err := crypto.SignatureFromHex(v[1])
		if err != nil {
			return nil, err
		}
		cosignatures = append(cosignatures, Cosignature{
			KeyHash:   keyHash,
			Signature: signature,
		})
	}
}

func (cth *CosignedTreeHead) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	err := cth.SignedTreeHead.fromASCII(&p)
	if err != nil {
		return err
	}
	cth.Cosignatures, err = cosignaturesFromASCII(&p)
	return err
}
