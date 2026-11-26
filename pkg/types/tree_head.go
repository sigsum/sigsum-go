package types

import (
	"encoding/base64"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/v2/pkg/ascii"
	"sigsum.org/sigsum-go/v2/pkg/crypto"
	"sigsum.org/sigsum-go/v2/pkg/merkle"
)

const (
	CosignatureNamespace = "cosignature/v1"
	CheckpointNamePrefix = "sigsum.org/v1/tree/"
)

type SignedTreeHead struct {
	merkle.TreeHead
	Signature crypto.Ed25519Signature
}

type Cosignature struct {
	Timestamp uint64
	Signature crypto.Ed25519Signature
}

type CosignedTreeHead struct {
	SignedTreeHead
	Cosignatures map[crypto.Hash]Cosignature
}

// Produces the checkpoint body, i.e., the data to be signed when
// represented as a "signed note".
func FormatCheckpointBody(origin string, th *merkle.TreeHead) string {
	return fmt.Sprintf("%s\n%d\n%s\n",
		origin, th.Size,
		base64.StdEncoding.EncodeToString(th.RootHash[:]))
}

func SigsumCheckpointOrigin(publicKey crypto.PublicKey) string {
	return fmt.Sprintf("%s%x", CheckpointNamePrefix, publicKey.Hash())
}

func signEd25519(signer crypto.Signer, msg []byte) (crypto.Ed25519Signature, error) {
	sig, err := signer.Sign(msg)
	if err != nil {
		return crypto.Ed25519Signature{}, err
	}
	if len(sig) != crypto.Ed25519SignatureSize {
		return crypto.Ed25519Signature{}, fmt.Errorf("unexpected signature size %d: ", len(sig))
	}
	return crypto.Ed25519Signature(sig), nil
}

func SignTreeHead(signer crypto.Signer, th *merkle.TreeHead) (SignedTreeHead, error) {
	pub := signer.Public()
	sig, err := signEd25519(signer, []byte(FormatCheckpointBody(SigsumCheckpointOrigin(pub), th)))
	if err != nil {
		return SignedTreeHead{}, fmt.Errorf("failed signing tree head: %w", err)
	}

	return SignedTreeHead{
		TreeHead:  *th,
		Signature: sig,
	}, nil
}

func toCosignedData(origin string, th *merkle.TreeHead, timestamp uint64) string {
	return fmt.Sprintf("%s\ntime %d\n%s",
		CosignatureNamespace, timestamp,
		FormatCheckpointBody(origin, th))
}

func CosignTreeHead(signer crypto.Signer, origin string, th *merkle.TreeHead, timestamp uint64) (Cosignature, error) {
	signature, err := signEd25519(signer, []byte(toCosignedData(origin, th, timestamp)))
	if err != nil {
		return Cosignature{}, fmt.Errorf("failed co-signing tree head: %w", err)
	}
	return Cosignature{
		Timestamp: timestamp,
		Signature: signature,
	}, nil
}

func (sth *SignedTreeHead) ToASCII(w io.Writer) error {
	if err := ascii.WriteInt(w, "size", sth.Size); err != nil {
		return err
	}
	if err := ascii.WriteHash(w, "root_hash", &sth.RootHash); err != nil {
		return err
	}
	return ascii.WriteSignature(w, "signature", &sth.Signature)
}

// Doesn't require EOF, so it can be used for parsing a signed tree
// head embedded in a larger struct.
func (sth *SignedTreeHead) Parse(p *ascii.Parser) error {
	var err error
	sth.Size, err = p.GetInt("size")
	if err != nil {
		return err
	}
	sth.RootHash, err = p.GetHash("root_hash")
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

func (sth *SignedTreeHead) Verify(key *crypto.Ed25519PublicKey) bool {
	return key.Verify([]byte(FormatCheckpointBody(SigsumCheckpointOrigin(key), &sth.TreeHead)), sth.Signature[:])
}

func (cs *Cosignature) Verify(key *crypto.Ed25519PublicKey, origin string, th *merkle.TreeHead) bool {
	return key.Verify([]byte(toCosignedData(origin, th, cs.Timestamp)), cs.Signature[:])
}

func (cs *Cosignature) ToASCII(w io.Writer, keyHash *crypto.Hash) error {
	return ascii.WriteLine(w, "cosignature", keyHash[:], cs.Timestamp, cs.Signature[:])
}

func (cs *Cosignature) Parse(p *ascii.Parser) (crypto.Hash, error) {
	v, err := p.GetValues("cosignature", 3)
	if err != nil {
		return crypto.Hash{}, err
	}
	keyHash, err := crypto.HashFromHex(v[0])
	if err != nil {
		return crypto.Hash{}, err
	}
	cs.Timestamp, err = ascii.IntFromDecimal(v[1])
	if err != nil {
		return crypto.Hash{}, err
	}
	cs.Signature, err = crypto.Ed25519SignatureFromHex(v[2])
	if err != nil {
		return crypto.Hash{}, err
	}
	return keyHash, nil
}

func (cs *Cosignature) FromASCII(r io.Reader) (crypto.Hash, error) {
	p := ascii.NewParser(r)
	keyHash, err := cs.Parse(&p)
	if err != nil {
		return crypto.Hash{}, err
	}
	return keyHash, p.GetEOF()
}

func (cth *CosignedTreeHead) ToASCII(w io.Writer) error {
	if err := cth.SignedTreeHead.ToASCII(w); err != nil {
		return err
	}
	// Note that this produces the cosignature lines in a
	// non-deterministic order.
	for key, cs := range cth.Cosignatures {
		if err := cs.ToASCII(w, &key); err != nil {
			return err
		}
	}
	return nil
}

// Second return value is true if list was terminated by an empty
// line, false if terminated by EOF.
func ParseCosignatures(p *ascii.Parser) (map[crypto.Hash]Cosignature, bool, error) {
	cosignatures := make(map[crypto.Hash]Cosignature)
	for {
		var cs Cosignature
		keyHash, err := cs.Parse(p)
		if err == io.EOF {
			return cosignatures, false, nil
		}
		if err == ascii.ErrEmptyLine {
			return cosignatures, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		if _, ok := cosignatures[keyHash]; ok {
			return nil, false, fmt.Errorf("duplicate cosignature keyhash")
		}
		cosignatures[keyHash] = cs
	}
}

// First return value is true if list was terminated by an empty
// line, false if terminated by EOF.
func (cth *CosignedTreeHead) Parse(p *ascii.Parser) (bool, error) {
	err := cth.SignedTreeHead.Parse(p)
	if err != nil {
		return false, err
	}
	var emptyLine bool
	cth.Cosignatures, emptyLine, err = ParseCosignatures(p)
	return emptyLine, err
}

func (cth *CosignedTreeHead) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	emptyLine, err := cth.Parse(&p)
	if err != nil {
		return err
	}
	if emptyLine {
		return ascii.ErrEmptyLine
	}
	return err
}
