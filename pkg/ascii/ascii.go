// package ascii implements an ASCII key-value parser.
//
// The top-most (de)serialize must operate on a struct pointer.  A struct may
// contain other structs, in which case all tag names should be unique.  Public
// fields without tag names are ignored.  Private fields are also ignored.
//
// The supported field types are:
// - struct
// - string (no empty strings)
// - uint64 (only digits in ASCII representation)
// - byte array (only lower-case hex in ASCII representation)
// - slice of uint64 (no empty slices)
// - slice of byte array (no empty slices)
//
// A key must not contain an encoding's end-of-key value.
// A value must not contain an encoding's end-of-value value.
//
// For additional details, please refer to the Sigsum v0 API documentation.
package ascii

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/types"
)

// Basic value types
func IntFromDecimal(s string) (uint64, error) {
	// Use ParseUint, to not accept leading +/-.
	i, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if i < 0 || i >= (1<<63) {
		return 0, fmt.Errorf("integer %d is out of range", i)
	}
	return i, nil
}

func decodeHex(s string, size int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, fmt.Errorf("unexpected length of hex data, expected %d, got %d", size, len(b))
	}
	return b, nil
}

func HashFromHex(s string) (h merkle.Hash, err error) {
	var b []byte
	b, err = decodeHex(s, merkle.HashSize)
	copy(h[:], b)
	return
}

func PublicKeyFromHex(s string) (pub types.PublicKey, err error) {
	var b []byte
	b, err = decodeHex(s, types.PublicKeySize)
	copy(pub[:], b)
	return
}

func SignatureFromHex(s string) (sig types.Signature, err error) {
	var b []byte
	b, err = decodeHex(s, types.SignatureSize)
	copy(sig[:], b)
	return
}

func split(s string, n int) ([]string, error) {
	values := []string{}

	for i := 0; i < n-1; i++ {
		space := strings.Index(s, " ")
		if space < 0 {
			return nil, fmt.Errorf("too few values, expected %d", n)
		}
		values = append(values, s[:space])
		s = s[space+1:]
	}
	if strings.Index(s, " ") >= 0 {
		return nil, fmt.Errorf("too many values, expected %d", n)
	}
	return append(values, s), nil
}

func parseLeaf(s string) (types.Leaf, error) {
	values, err := split(s, 3)
	var leaf types.Leaf
	if err != nil {
		return leaf, fmt.Errorf("invalid leaf: %v", err)
	}
	leaf.Checksum, err = HashFromHex(values[0])
	if err != nil {
		return leaf, fmt.Errorf("invalid leaf checksum: %v", err)
	}
	leaf.Signature, err = SignatureFromHex(values[1])
	if err != nil {
		return leaf, fmt.Errorf("invalid leaf signature: %v", err)
	}
	leaf.KeyHash, err = HashFromHex(values[2])
	if err != nil {
		return leaf, fmt.Errorf("invalid leaf key hash: %v", err)
	}
	return leaf, nil
}

func parseCosignature(s string) (types.Cosignature, error) {
	values, err := split(s, 2)
	var cosignature types.Cosignature
	if err != nil {
		return cosignature, fmt.Errorf("invalid cosignature: %v", err)
	}
	cosignature.KeyHash, err = HashFromHex(values[0])
	if err != nil {
		return cosignature, fmt.Errorf("invalid cosignature key hash: %v", err)
	}
	cosignature.Signature, err = SignatureFromHex(values[1])
	if err != nil {
		return cosignature, fmt.Errorf("invalid cosignature signature: %v", err)
	}
	return cosignature, nil
}

type Parser struct {
	scanner *bufio.Scanner
}

func NewParser(input io.Reader) Parser {
	// By default, scans by lines
	return Parser{bufio.NewScanner(input)}
}

func (p *Parser) GetEOF() error {
	if p.scanner.Scan() {
		return fmt.Errorf("garbage at end of message: %q",
			p.scanner.Text())
	}
	return nil
}

func (p *Parser) Next(name string) (string, error) {
	if !p.scanner.Scan() {
		return "", io.EOF
	}
	line := p.scanner.Text()
	equals := strings.Index(line, "=")
	if equals < 0 {
		return "", fmt.Errorf("invalid input line: %q", line)
	}
	key, value := line[:equals], line[equals+1:]
	if key != name {
		return "", fmt.Errorf("invalid input line, expected %v, got key: %q", name, key)
	}

	return value, nil
}

func (p *Parser) GetInt(name string) (uint64, error) {
	v, err := p.Next(name)
	if err != nil {
		return 0, err
	}
	return IntFromDecimal(v)
}

func (p *Parser) GetHash(name string) (merkle.Hash, error) {
	v, err := p.Next(name)
	if err != nil {
		return merkle.Hash{}, err
	}
	return HashFromHex(v)
}

func (p *Parser) GetPublicKey(name string) (types.PublicKey, error) {
	v, err := p.Next(name)
	if err != nil {
		return types.PublicKey{}, err
	}
	return PublicKeyFromHex(v)
}

func (p *Parser) GetSignature(name string) (types.Signature, error) {
	v, err := p.Next(name)
	if err != nil {
		return types.Signature{}, err
	}
	return SignatureFromHex(v)
}

// TODO: Add EOF check here?
func (p *Parser) GetCosignature() (types.Cosignature, error) {
	v, err := p.Next("cosignature")
	if err != nil {
		return types.Cosignature{}, err
	}
	cosignature, err := parseCosignature(v)
	if err == nil {
		err = p.GetEOF()
	}
	return cosignature, err
}

func (p *Parser) getCosignatures() ([]types.Cosignature, error) {
	var cosignatures []types.Cosignature
	for {
		v, err := p.Next("cosignature")
		if err == io.EOF {
			return cosignatures, nil
		}
		if err != nil {
			return nil, err
		}
		cosignature, err := parseCosignature(v)
		if err != nil {
			return nil, err
		}
		cosignatures = append(cosignatures, cosignature)
	}
}

func (p *Parser) GetLeaves() ([]types.Leaf, error) {
	var leaves []types.Leaf
	for {
		v, err := p.Next("leaf")
		if err == io.EOF {
			return leaves, nil
		}
		if err != nil {
			return nil, err
		}
		leaf, err := parseLeaf(v)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, leaf)
	}
}

// Doesn't require EOF, so it can be used also with (co)signatures.
func (p *Parser) getTreeHead() (types.TreeHead, error) {
	timestamp, err := p.GetInt("timestamp")
	if err != nil {
		return types.TreeHead{}, err
	}
	treeSize, err := p.GetInt("tree_size")
	if err != nil {
		return types.TreeHead{}, err
	}
	rootHash, err := p.GetHash("root_hash")
	if err != nil {
		return types.TreeHead{}, err
	}
	return types.TreeHead{
		Timestamp: timestamp,
		TreeSize:  treeSize,
		RootHash:  rootHash,
	}, nil
}

func (p *Parser) GetTreeHead() (types.TreeHead, error) {
	th, err := p.getTreeHead()
	if err == nil {
		err = p.GetEOF()
	}
	return th, err
}

// Doesn't require EOF, so it can be used also with cosignatures.
func (p *Parser) getSignedTreeHead() (types.SignedTreeHead, error) {
	th, err := p.getTreeHead()
	if err != nil {
		return types.SignedTreeHead{}, err
	}
	signature, err := p.GetSignature("signature")
	if err != nil {
		return types.SignedTreeHead{}, err
	}
	return types.SignedTreeHead{
		TreeHead:  th,
		Signature: signature}, nil
}

func (p *Parser) GetSignedTreeHead() (types.SignedTreeHead, error) {
	sth, err := p.getSignedTreeHead()
	if err == nil {
		err = p.GetEOF()
	}
	return sth, err
}

func (p *Parser) GetCosignedTreeHead() (types.CosignedTreeHead, error) {
	sth, err := p.getSignedTreeHead()
	if err != nil {
		return types.CosignedTreeHead{}, err
	}
	cosignatures, err := p.getCosignatures()
	if err != nil {
		return types.CosignedTreeHead{}, err
	}
	return types.CosignedTreeHead{
		SignedTreeHead: sth,
		Cosignatures:   cosignatures,
	}, nil
}

// Treats empty list as an error.
func (p *Parser) getHashes(name string) ([]merkle.Hash, error) {
	var hashes []merkle.Hash
	for {
		v, err := p.Next(name)
		if err == io.EOF {
			if len(hashes) == 0 {
				return nil, fmt.Errorf("invalid path, empty")
			}

			return hashes, nil
		}
		if err != nil {
			return nil, err
		}
		hash, err := HashFromHex(v)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
}

func (p *Parser) GetInclusionProof(treeSize uint64) (types.InclusionProof, error) {
	leafIndex, err := p.GetInt("leaf_index")
	if err != nil {
		return types.InclusionProof{}, err
	}
	if leafIndex >= treeSize {
		return types.InclusionProof{}, fmt.Errorf("leaf_index out of range")
	}
	hashes, err := p.getHashes("inclusion_path")
	if err != nil {
		return types.InclusionProof{}, err
	}
	return types.InclusionProof{
		TreeSize:  treeSize,
		LeafIndex: leafIndex,
		Path:      hashes,
	}, nil
}

func (p *Parser) GetConsistencyProof() (types.ConsistencyProof, error) {
	hashes, err := p.getHashes("consistency_path")
	if err != nil {
		return types.ConsistencyProof{}, err
	}
	return types.ConsistencyProof{
		Path: hashes,
	}, nil
}

func WriteLine(w io.Writer, key, value string) error {
	_, err := fmt.Fprintf(w, "%s=%s\n", key, value)
	return err
}

func WriteLineHex(w io.Writer, key string, first []byte, rest ...[]byte) error {
	_, err := fmt.Fprintf(w, "%s=%s", key, hex.EncodeToString(first))
	if err != nil {
		return err
	}
	for _, b := range rest {
		_, err := fmt.Fprintf(w, " %s", hex.EncodeToString(b))
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(w, "\n")
	return err
}

func WriteInt(w io.Writer, name string, i uint64) error {
	if i >= (1 << 63) {
		return fmt.Errorf("out of range negative number: %d", i)
	}
	return WriteLine(w, name, strconv.FormatUint(i, 10))
}

func WriteHash(w io.Writer, name string, h *merkle.Hash) error {
	return WriteLineHex(w, name, (*h)[:])
}

func WritePublicKey(w io.Writer, name string, k *types.PublicKey) error {
	return WriteLineHex(w, name, (*k)[:])
}

func WriteSignature(w io.Writer, name string, s *types.Signature) error {
	return WriteLineHex(w, name, (*s)[:])
}

func WriteCosignature(w io.Writer, c *types.Cosignature) error {
	return WriteLineHex(w, "cosignature", c.KeyHash[:], c.Signature[:])
}

func WriteLeaf(w io.Writer, l *types.Leaf) error {
	return WriteLineHex(w, "leaf", l.Checksum[:], l.Signature[:], l.KeyHash[:])
}

func WriteTreeHead(w io.Writer, h *types.TreeHead) error {
	if err := WriteInt(w, "timestamp", h.Timestamp); err != nil {
		return err
	}
	if err := WriteInt(w, "tree_size", h.TreeSize); err != nil {
		return err
	}
	return WriteHash(w, "root_hash", &h.RootHash)
}

func WriteSignedTreeHead(w io.Writer, h *types.SignedTreeHead) error {
	if err := WriteTreeHead(w, &h.TreeHead); err != nil {
		return err
	}
	return WriteSignature(w, "signature", &h.Signature)
}

func WriteCosignedTreeHead(w io.Writer, h *types.CosignedTreeHead) error {
	if err := WriteSignedTreeHead(w, &h.SignedTreeHead); err != nil {
		return err
	}
	for _, cosignature := range h.Cosignatures {
		if err := WriteCosignature(w, &cosignature); err != nil {
			return err
		}
	}
	return nil
}

func writeHashes(w io.Writer, name string, hashes []merkle.Hash) error {
	for _, hash := range hashes {
		err := WriteHash(w, name, &hash)
		if err != nil {
			return err
		}
	}
	return nil
}

// Note the tree_size is not included on the wire.
func WriteInclusionProof(w io.Writer, p *types.InclusionProof) error {
	if err := WriteInt(w, "leaf_index", p.LeafIndex); err != nil {
		return err
	}
	return writeHashes(w, "inclusion_path", p.Path)
}

// Note the tree sizes are not included on the wire.
func WriteConsistencyProof(w io.Writer, p *types.ConsistencyProof) error {
	return writeHashes(w, "consistency_path", p.Path)
}
