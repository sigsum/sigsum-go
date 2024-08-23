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

type TreeHead struct {
	Size     uint64
	RootHash crypto.Hash
}

type SignedTreeHead struct {
	TreeHead
	Signature crypto.Signature
}

type Cosignature struct {
	Timestamp uint64
	Signature crypto.Signature
}

type CosignedTreeHead struct {
	SignedTreeHead
	Cosignatures map[crypto.Hash]Cosignature
}

func NewEmptyTreeHead() TreeHead {
	return TreeHead{Size: 0, RootHash: merkle.HashEmptyTree()}
}

// Produces the checkpoint body, i.e., the data to be signed when
// represented as a "signed note".
func (th *TreeHead) FormatCheckpoint(origin string) string {
	return fmt.Sprintf("%s\n%d\n%s\n",
		origin, th.Size,
		base64.StdEncoding.EncodeToString(th.RootHash[:]))
}

func sigsumCheckpointOrigin(keyHash *crypto.Hash) string {
	return fmt.Sprintf("%s%x", CheckpointNamePrefix, *keyHash)
}

func (th *TreeHead) toCheckpoint(keyHash *crypto.Hash) string {
	return th.FormatCheckpoint(sigsumCheckpointOrigin(keyHash))
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
func (th *TreeHead) toCosignedData(origin string, timestamp uint64) string {
	return fmt.Sprintf("%s\ntime %d\n%s",
		CosignatureNamespace, timestamp,
		th.FormatCheckpoint(origin))
}

func (th *TreeHead) CosignOrigin(signer crypto.Signer, origin string, timestamp uint64) (Cosignature, error) {
	signature, err := signer.Sign([]byte(th.toCosignedData(origin, timestamp)))
	if err != nil {
		return Cosignature{}, fmt.Errorf("failed co-signing tree head: %w", err)
	}
	return Cosignature{
		Timestamp: timestamp,
		Signature: signature,
	}, nil
}

func (th *TreeHead) Cosign(signer crypto.Signer, logKeyHash *crypto.Hash, timestamp uint64) (Cosignature, error) {
	return th.CosignOrigin(signer, sigsumCheckpointOrigin(logKeyHash), timestamp)
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

// See https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md for
// specification.
func (sth *SignedTreeHead) ToCheckpoint(w io.Writer, logKey *crypto.PublicKey) error {
	keyHash := crypto.HashBytes(logKey[:])
	origin := sigsumLogOrigin(&keyHash)

	if _, err := fmt.Fprintf(w, "%s\n", sth.formatCheckpoint(origin)); err != nil {
		return err
	}

	// TODO: Constructs origin string twice. Should have some
	// object to cache origin and key id.
	return WriteNoteLogSignature(w, origin, CheckpointLogKeyId(logKey), &sth.Signature)
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

// Deprecated: This backwards compatibility function should be deleted.
func (sth *SignedTreeHead) VerifyVersion0(key *crypto.PublicKey) bool {
	// Prefix used temporarily, for version v0.1.15 and v0.2.0.
	keyHash := crypto.HashBytes(key[:])
	if crypto.Verify(key, []byte(sth.FormatCheckpoint(fmt.Sprintf("sigsum.org/v1/%x", &keyHash))), &sth.Signature) {
		return true
	}
	b := make([]byte, 40)
	binary.BigEndian.PutUint64(b[:8], sth.Size)
	copy(b[8:40], sth.RootHash[:])
	return crypto.Verify(key, ssh.SignedData("signed-tree-head:v0@sigsum.org", b),
		&sth.Signature)
}

func (cs *Cosignature) VerifyOrigin(key *crypto.PublicKey, origin string, th *TreeHead) bool {
	return crypto.Verify(key, []byte(th.toCosignedData(origin, cs.Timestamp)), &cs.Signature)
}

func (cs *Cosignature) Verify(key *crypto.PublicKey, logKeyHash *crypto.Hash, th *TreeHead) bool {
	return cs.VerifyOrigin(key, sigsumCheckpointOrigin(logKeyHash), th)
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
	cs.Signature, err = crypto.SignatureFromHex(v[2])
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

func ParseCosignatures(p *ascii.Parser) (map[crypto.Hash]Cosignature, error) {
	cosignatures := make(map[crypto.Hash]Cosignature)
	for {
		var cs Cosignature
		keyHash, err := cs.Parse(p)
		if err == io.EOF {
			return cosignatures, nil
		}
		if err != nil {
			return nil, err
		}
		if _, ok := cosignatures[keyHash]; ok {
			return nil, fmt.Errorf("duplicate cosignature keyhash")
		}
		cosignatures[keyHash] = cs
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
