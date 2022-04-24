package types

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"git.sigsum.org/sigsum-go/pkg/hex"
	"git.sigsum.org/sigsum-go/pkg/types/ascii"
	"git.sigsum.org/sigsum-go/pkg/types/binary/ssh"
	"git.sigsum.org/sigsum-go/pkg/types/binary/trunnel"
)

// Hash is a SHA256 hash, see §XXX:
//
//     u8 Hash[32];
//
type Hash [HashSize]byte

const HashSize = 32

func HashFn(b []byte) Hash {
	return sha256.Sum256(b)
}

// Signature is an Ed25519 signature, see §XXX:
//
//     u8 Signature[64];
//
type Signature [SignatureSize]byte

const SignatureSize = 64

// PublicKey is an Ed25519 public key, see §XXX:
//
//     u8 public_key[32];
//
type PublicKey [PublicKeySize]byte

const PublicKeySize = 32

func (k *PublicKey) Verify(msg []byte, sig Signature) error {
	if !ed25519.Verify(ed25519.PublicKey(k[:]), msg, sig[:]) {
		return fmt.Errorf("invalid ed25519 signature")
	}
	return nil
}

// PrivateKey provides access to the private part of an Ed25519 key-pair
type PrivateKey struct {
	crypto.Signer
}

func (k *PrivateKey) Sign(message []byte) (s Signature, err error) {
	sig, err := k.Signer.Sign(nil, message, crypto.Hash(0))
	if err != nil {
		return s, fmt.Errorf("sign: %w", err)
	}
	if n := len(sig); n != SignatureSize {
		return s, fmt.Errorf("invalid signature size %d", n)
	}
	copy(s[:], sig)
	return s, nil
}

// TreeHead is a Merkle tree head, see §2.3.1:
//
//     struct tree_head {
//         u64  timestamp;
//         u64  tree_size;
//         hash root_hash;
//     };
//
type TreeHead struct {
	Timestamp uint64
	TreeSize  uint64
	RootHash  Hash
}

func (th *TreeHead) ToTrunnel() []byte {
	buf := bytes.NewBuffer(nil)

	trunnel.AddUint64(buf, th.Timestamp)
	trunnel.AddUint64(buf, th.TreeSize)
	buf.Write(th.RootHash[:])

	return buf.Bytes()
}

// ToSSH serialization is defined in §2.3.2
func (th *TreeHead) ToSSH(keyHash Hash) []byte {
	namespace := fmt.Sprintf("tree_head:v0:%s@sigsum.org", hex.Serialize(keyHash[:]))
	return ssh.ToSignBlob(namespace, th.ToTrunnel())
}

func (th *TreeHead) Sign(k PrivateKey, logKeyHash Hash) (Signature, error) {
	return k.Sign(th.ToSSH(logKeyHash))
}

func (th *TreeHead) Verify(k PublicKey, logKeyHash Hash, sig Signature) error {
	return k.Verify(th.ToSSH(logKeyHash), sig)
}

// Checksum is a checksum, see §XXX:
//
//     hash checksum;
//
type Checksum Hash

// ToSSH serialization is defined in §2.3.3
func (c *Checksum) ToSSH(shardHint uint64) []byte {
	namespace := fmt.Sprintf("tree_leaf:v0:%d@sigsum.org", shardHint)
	return ssh.ToSignBlob(namespace, c[:])
}

func (c *Checksum) Sign(k PrivateKey, shardHint uint64) (Signature, error) {
	return k.Sign(c.ToSSH(shardHint))
}

func (c *Checksum) Verify(k PublicKey, shardHint uint64, sig Signature) error {
	return k.Verify(c.ToSSH(shardHint), sig)
}

// TreeLeaf is a Merkle tree leaf, see §2.3.3:
//
//     struct tree_leaf {
//         u64       shard_hint;
//         checksum  checksum;
//         signature signature;
//         hash      key_hash;
//     };
//
type TreeLeaf struct {
	ShardHint uint64
	Checksum  Checksum
	Signature Signature
	KeyHash   Hash
}

func (tl *TreeLeaf) ToTrunnel() []byte {
	buf := bytes.NewBuffer(nil)

	trunnel.AddUint64(buf, tl.ShardHint)
	buf.Write(tl.Checksum[:])
	buf.Write(tl.Signature[:])
	buf.Write(tl.KeyHash[:])

	return buf.Bytes()
}

func (tl *TreeLeaf) FromTrunnel(buf *bytes.Buffer) error {
	if err := trunnel.Uint64(buf, &tl.ShardHint); err != nil {
		return fmt.Errorf("tree_leaf.shard_hint: %w", err)
	}
	if err := trunnel.Array(buf, tl.Checksum[:]); err != nil {
		return fmt.Errorf("tree_leaf.checksum: %w", err)
	}
	if err := trunnel.Array(buf, tl.Signature[:]); err != nil {
		return fmt.Errorf("tree_leaf.signature: %w", err)
	}
	if err := trunnel.Array(buf, tl.KeyHash[:]); err != nil {
		return fmt.Errorf("tree_leaf.key_hash: %w", err)
	}
	if rest, err := io.ReadAll(buf); err != nil || len(rest) != 0 {
		return fmt.Errorf("invalid remainder: rest is %x and err %v", rest, err)
	}
	return nil
}

// Endpoint is named log endpoint, see §3.1 - §3.7
type Endpoint string

const (
	EndpointAddLeaf             = Endpoint("add-leaf")
	EndpointAddCosignature      = Endpoint("add-cosignature")
	EndpointGetTreeHeadToCosign = Endpoint("get-tree-head-to-sign")
	EndpointGetTreeHeadCosigned = Endpoint("get-tree-head-cosigned")
	EndpointGetInclusionProof   = Endpoint("get-inclusion-proof")
	EndpointGetConsistencyProof = Endpoint("get-consistency-proof")
	EndpointGetLeaves           = Endpoint("get-leaves")
)

// Path returns a complete endpoint URL for a given log URL.  The format of a
// log's URL is defined in §3, e.g., "https://log.example.com/sigsum/v0".
func (e Endpoint) URL(logURL string) string {
	return logURL + "/" + string(e)
}

const (
	asciiError           = "error" // XXX: update s/E/e in api.md
	asciiTimestamp       = "timestamp"
	asciiTreeSize        = "tree_size"
	asciiRootHash        = "root_hash"
	asciiSignature       = "signature"
	asciiCosignature     = "cosignature"
	asciiKeyHash         = "key_hash"
	asciiLeafIndex       = "leaf_index"
	asciiInclusionPath   = "inclusion_path"
	asciiConsistencyPath = "consistency_path"
	asciiShardHint       = "shard_hint"
	asciiChecksum        = "checksum"
	asciiMessage         = "message"    // XXX: update s/preimage/message in api.md
	asciiPublicKey       = "public_key" // XXX: update s/verification_key/public_key in api.md
	asciiDomainHint      = "domain_hint"
)

// Error is an error mesage, see §3
type Error string

func (e *Error) ToASCII(w io.Writer) error {
	if strings.Contains(string(*e), ascii.EndOfValue) {
		return fmt.Errorf("string contains end-of-value pattern") // XXX: in ascii package instead?
	}
	if err := ascii.WritePair(w, asciiError, string(*e)); err != nil {
		fmt.Errorf("%s: %w", asciiError, err)
	}
	return nil
}

func (e *Error) FromASCII(r io.Reader) error {
	return ascii.ReadPairs(r, func(m *ascii.Map) error {
		if err := m.DequeueString(asciiError, (*string)(e)); err != nil {
			return fmt.Errorf("%s: %w", asciiError, err)
		}
		return nil
	})
}

// SignedTreeHead is the output of get-tree-head-to-cosign, see §3.1
type SignedTreeHead struct {
	TreeHead
	Signature Signature
}

func (sth *SignedTreeHead) ToASCII(w io.Writer) error {
	if err := ascii.WritePair(w, asciiTimestamp, fmt.Sprintf("%d", sth.Timestamp)); err != nil {
		return fmt.Errorf("%s: %w", asciiTimestamp, err)
	}
	if err := ascii.WritePair(w, asciiTreeSize, fmt.Sprintf("%d", sth.TreeSize)); err != nil {
		return fmt.Errorf("%s: %w", asciiTreeSize, err)
	}
	if err := ascii.WritePair(w, asciiRootHash, hex.Serialize(sth.RootHash[:])); err != nil {
		return fmt.Errorf("%s: %w", asciiRootHash, err)
	}
	if err := ascii.WritePair(w, asciiSignature, hex.Serialize(sth.Signature[:])); err != nil {
		return fmt.Errorf("%s: %w", asciiSignature, err)
	}
	return nil
}

func (sth *SignedTreeHead) FromASCII(r io.Reader) error {
	return ascii.ReadPairs(r, func(m *ascii.Map) (err error) {
		*sth, err = sthFromASCII(m)
		return err
	})
}

// CosignedTreeHead is the output of get-tree-head-cosigned, see §3.2
type CosignedTreeHead struct {
	SignedTreeHead
	Cosignatures []Cosignature
}

func (cth *CosignedTreeHead) ToASCII(w io.Writer) error {
	if len(cth.Cosignatures) == 0 {
		return fmt.Errorf("no cosignatures")
	}

	for i, c := range cth.Cosignatures {
		if err := c.ToASCII(w); err != nil {
			return fmt.Errorf("%d: %w", i+1, err)
		}
	}
	return cth.SignedTreeHead.ToASCII(w)
}

func (cth *CosignedTreeHead) FromASCII(r io.Reader) error {
	return ascii.ReadPairs(r, func(m *ascii.Map) (err error) {
		n := m.NumValues(asciiCosignature)
		if n == 0 {
			return fmt.Errorf("no cosignatures")
		}

		cth.Cosignatures = make([]Cosignature, 0, n)
		for i := uint64(0); i < n; i++ {
			c, err := cosignatureFromASCII(m)
			if err != nil {
				return fmt.Errorf("%d: %w", i+1, err)
			}
			cth.Cosignatures = append(cth.Cosignatures, c)
		}
		cth.SignedTreeHead, err = sthFromASCII(m)
		return err
	})
}

type Cosignature struct {
	KeyHash   Hash
	Signature Signature
}

func (c *Cosignature) ToASCII(w io.Writer) error {
	if err := ascii.WritePair(w, asciiKeyHash, hex.Serialize(c.KeyHash[:])); err != nil {
		return fmt.Errorf("%s: %w", asciiKeyHash, err)
	}
	if err := ascii.WritePair(w, asciiCosignature, hex.Serialize(c.Signature[:])); err != nil {
		return fmt.Errorf("%s: %w", asciiCosignature, err)
	}
	return nil
}

func (c *Cosignature) FromASCII(r io.Reader) error {
	return ascii.ReadPairs(r, func(m *ascii.Map) (err error) {
		*c, err = cosignatureFromASCII(m)
		return err
	})
}

// InclusionProof is the output of get-inclusion-proof, see §3.3
type InclusionProof struct {
	LeafIndex     uint64
	InclusionPath []Hash
}

func (p *InclusionProof) ToASCII(w io.Writer) error {
	if len(p.InclusionPath) == 0 {
		return fmt.Errorf("no inclusion path")
	}

	for i, h := range p.InclusionPath {
		if err := ascii.WritePair(w, asciiInclusionPath, hex.Serialize(h[:])); err != nil {
			return fmt.Errorf("%d: %s: %w", i+1, asciiInclusionPath, err)
		}
	}
	if err := ascii.WritePair(w, asciiLeafIndex, fmt.Sprintf("%d", p.LeafIndex)); err != nil {
		return fmt.Errorf("%s: %w", asciiLeafIndex, err)
	}
	return nil
}

func (p *InclusionProof) FromASCII(r io.Reader) error {
	return ascii.ReadPairs(r, func(m *ascii.Map) error {
		n := m.NumValues(asciiInclusionPath)
		if n == 0 {
			return fmt.Errorf("no inclusion path")
		}

		p.InclusionPath = make([]Hash, 0, n)
		for i := uint64(0); i < n; i++ {
			var h Hash
			if err := m.DequeueArray(asciiInclusionPath, h[:]); err != nil {
				return fmt.Errorf("%d: %s: %w", i+1, asciiInclusionPath, err)
			}
			p.InclusionPath = append(p.InclusionPath, h)
		}
		if err := m.DequeueUint64(asciiLeafIndex, &p.LeafIndex); err != nil {
			return fmt.Errorf("%s: %w", asciiLeafIndex, err)
		}
		return nil
	})
}

// ConsistencyProof is the output of get-consistency proof, see §3.4
type ConsistencyProof struct {
	ConsistencyPath []Hash
}

func (p *ConsistencyProof) ToASCII(w io.Writer) error {
	if len(p.ConsistencyPath) == 0 {
		return fmt.Errorf("no consistency path")
	}

	for i, h := range p.ConsistencyPath {
		if err := ascii.WritePair(w, asciiConsistencyPath, hex.Serialize(h[:])); err != nil {
			return fmt.Errorf("%d: %s: %w", i+1, asciiConsistencyPath, err)
		}
	}
	return nil
}

func (p *ConsistencyProof) FromASCII(r io.Reader) error {
	return ascii.ReadPairs(r, func(m *ascii.Map) error {
		n := m.NumValues(asciiConsistencyPath)
		if n == 0 {
			return fmt.Errorf("no inclusion path")
		}

		p.ConsistencyPath = make([]Hash, 0, n)
		for i := uint64(0); i < n; i++ {
			var h Hash
			if err := m.DequeueArray(asciiConsistencyPath, h[:]); err != nil {
				return fmt.Errorf("%d: %s: %w", i+1, asciiConsistencyPath, err)
			}
			p.ConsistencyPath = append(p.ConsistencyPath, h)
		}
		return nil
	})
}

// Leaves is the output of get-leaves, see §3.5
type Leaves []TreeLeaf

func (l *Leaves) ToASCII(w io.Writer) error {
	if len(*l) == 0 {
		return fmt.Errorf("no leaves")
	}

	for i, leaf := range *l {
		if err := leaf.ToASCII(w); err != nil {
			return fmt.Errorf("%d: %w", i+1, err)
		}
	}
	return nil
}

func (l *Leaves) FromASCII(r io.Reader) error {
	return ascii.ReadPairs(r, func(m *ascii.Map) error {
		n := m.NumValues(asciiShardHint)
		if n == 0 {
			return fmt.Errorf("no leaves")
		}

		*l = make([]TreeLeaf, 0, n)
		for i := uint64(0); i < n; i++ {
			var leaf TreeLeaf
			if err := m.DequeueUint64(asciiShardHint, &leaf.ShardHint); err != nil {
				return fmt.Errorf("%s: %w", asciiShardHint, err)
			}
			if err := m.DequeueArray(asciiChecksum, leaf.Checksum[:]); err != nil {
				return fmt.Errorf("%s: %w", asciiChecksum, err)
			}
			if err := m.DequeueArray(asciiSignature, leaf.Signature[:]); err != nil {
				return fmt.Errorf("%s: %w", asciiSignature, err)
			}
			if err := m.DequeueArray(asciiKeyHash, leaf.KeyHash[:]); err != nil {
				return fmt.Errorf("%s: %w", asciiKeyHash, err)
			}
			*l = append(*l, leaf)
		}
		return nil
	})
}

func (l *TreeLeaf) ToASCII(w io.Writer) error {
	if err := ascii.WritePair(w, asciiShardHint, fmt.Sprintf("%d", l.ShardHint)); err != nil {
		return fmt.Errorf("%s: %w", asciiShardHint, err)
	}
	if err := ascii.WritePair(w, asciiChecksum, hex.Serialize(l.Checksum[:])); err != nil {
		return fmt.Errorf("%s: %w", asciiChecksum, err)
	}
	if err := ascii.WritePair(w, asciiSignature, hex.Serialize(l.Signature[:])); err != nil {
		return fmt.Errorf("%s: %w", asciiSignature, err)
	}
	if err := ascii.WritePair(w, asciiKeyHash, hex.Serialize(l.KeyHash[:])); err != nil {
		return fmt.Errorf("%s: %w", asciiKeyHash, err)
	}
	return nil
}

// RequestInclusionProof is the input of get-inclusion-proof, see §3.3
type RequestInclusionProof struct {
	TreeSize uint64
	LeafHash Hash
}

func (req *RequestInclusionProof) ToURL(logURL string) string {
	return "TODO"
}

func (req *RequestInclusionProof) FromURL(url string) error {
	return nil // TODO
}

// RequestConsistencyProof is the input of get-consistency-proof, see §3.4
type RequestConsistencyProof struct {
	OldSize uint64
	NewSize uint64
}

func (req *RequestConsistencyProof) ToURL(logURL string) string {
	return "TODO"
}

func (req *RequestConsistencyProof) FromURL(url string) error {
	return nil // TODO
}

// RequestLeaves is the input of a get-leaves, see §3.5
type RequestLeaves struct {
	OldSize uint64
	NewSize uint64
}

func (req *RequestLeaves) ToURL(logURL string) string {
	return "TODO"
}

func (req *RequestLeaves) FromURL(url string) error {
	return nil // TODO
}

// RequestLeaf is the input of add-leaf, see §3.6
type RequestLeaf struct {
	ShardHint  uint64
	Message    Hash
	Signature  Signature
	PublicKey  PublicKey
	DomainHint string
}

func (req *RequestLeaf) ToASCII(w io.Writer) error {
	if err := ascii.WritePair(w, asciiShardHint, fmt.Sprintf("%d", req.ShardHint)); err != nil {
		return fmt.Errorf("%s: %w", asciiShardHint, err)
	}
	if err := ascii.WritePair(w, asciiMessage, hex.Serialize(req.Message[:])); err != nil {
		return fmt.Errorf("%s: %w", asciiMessage, err)
	}
	if err := ascii.WritePair(w, asciiSignature, hex.Serialize(req.Signature[:])); err != nil {
		return fmt.Errorf("%s: %w", asciiSignature, err)
	}
	if err := ascii.WritePair(w, asciiPublicKey, hex.Serialize(req.PublicKey[:])); err != nil {
		return fmt.Errorf("%s: %w", asciiPublicKey, err)
	}
	if err := ascii.WritePair(w, asciiDomainHint, req.DomainHint); err != nil {
		return fmt.Errorf("%s: %w", asciiDomainHint, err)
	}
	return nil
}

func (req *RequestLeaf) FromASCII(r io.Reader) error {
	return ascii.ReadPairs(r, func(m *ascii.Map) (err error) {
		if err := m.DequeueUint64(asciiShardHint, &req.ShardHint); err != nil {
			return fmt.Errorf("%s: %w", asciiShardHint, err)
		}
		if err := m.DequeueArray(asciiMessage, req.Message[:]); err != nil {
			return fmt.Errorf("%s: %w", asciiMessage, err)
		}
		if err := m.DequeueArray(asciiSignature, req.Signature[:]); err != nil {
			return fmt.Errorf("%s: %w", asciiSignature, err)
		}
		if err := m.DequeueArray(asciiPublicKey, req.PublicKey[:]); err != nil {
			return fmt.Errorf("%s: %w", asciiPublicKey, err)
		}
		if err := m.DequeueString(asciiDomainHint, &req.DomainHint); err != nil {
			return fmt.Errorf("%s: %w", asciiDomainHint, err)
		}
		return nil
	})
}

// RequestCosignature is the input of add-cosignature, see §3.7
type RequestCosignature Cosignature

func (req *RequestCosignature) ToASCII(w io.Writer) error {
	return (*Cosignature)(req).ToASCII(w)
}

func (req *RequestCosignature) FromASCII(r io.Reader) error {
	return (*Cosignature)(req).FromASCII(r)
}

func sthFromASCII(m *ascii.Map) (sth SignedTreeHead, err error) {
	if m.DequeueUint64(asciiTimestamp, &sth.Timestamp); err != nil {
		return sth, fmt.Errorf("%s: %w", asciiTimestamp, err)
	}
	if m.DequeueUint64(asciiTreeSize, &sth.TreeSize); err != nil {
		return sth, fmt.Errorf("%s: %w", asciiTreeSize, err)
	}
	if m.DequeueArray(asciiRootHash, sth.RootHash[:]); err != nil {
		return sth, fmt.Errorf("%s: %w", asciiRootHash, err)
	}
	if m.DequeueArray(asciiSignature, sth.Signature[:]); err != nil {
		return sth, fmt.Errorf("%s: %w", asciiSignature, err)
	}
	return sth, nil
}

func cosignatureFromASCII(m *ascii.Map) (c Cosignature, err error) {
	if err := m.DequeueArray(asciiCosignature, c.Signature[:]); err != nil {
		return c, fmt.Errorf("%s: %w", asciiCosignature, err)
	}
	if err := m.DequeueArray(asciiKeyHash, c.KeyHash[:]); err != nil {
		return c, fmt.Errorf("%s: %w", asciiCosignature, err)
	}
	return c, nil
}
