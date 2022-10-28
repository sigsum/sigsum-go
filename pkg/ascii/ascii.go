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

type Value struct {
	s string
}

// Basic value types
func (v Value) ToInt() (int64, error) {
	// Use ParseUint, to not accept leading +/-.
	i, err := strconv.ParseUint(v.s, 10, 64)
	if err != nil {
		return 0, err
	}
	if i < 0 || i >= (1<<63) {
		return 0, fmt.Errorf("integer %d is out of range", i)
	}
	return int64(i), nil
}

func (v Value) decodeHex(size int) ([]byte, error) {
	b, err := hex.DecodeString(v.s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		err = fmt.Errorf("unexpected length of hex data, expected %d, got %d", size, len(b))
	}
	return b, nil
}

func (v Value) ToHash() (out merkle.Hash, err error) {
	var b []byte
	b, err = v.decodeHex(merkle.HashSize)
	copy(out[:], b)
	return
}

func (v Value) ToPublicKey() (out types.PublicKey, err error) {
	var b []byte
	b, err = v.decodeHex(types.PublicKeySize)
	copy(out[:], b)
	return
}

func (v Value) ToSignature() (out types.Signature, err error) {
	var b []byte
	b, err = v.decodeHex(types.SignatureSize)
	copy(out[:], b)
	return
}

func (v Value) Split(n int) ([]Value, error) {
	values := []Value{}
	s:= v.s
	for i := 0; i < n - 1; i++ {
		space := strings.Index(s, " ")
		if space < 0 {
			return nil, fmt.Errorf("too few values, expected %d", n)
		}
		values = append(values, Value{s[:space]})
		s = s[space+1:]
	}
	if strings.Index(s, " ") >= 0 {
		return nil, fmt.Errorf("too many values, expected %d", n)
	}
	return append(values, Value{s}), nil
}

func (v Value) ToLeaf() (types.Leaf, error) {
	values, err := v.Split(3)
	
	if err != nil { 
		fmt.Errorf("invalid leaf: %v", err);
	}
	checksum, err := values[0].ToHash()
	if err != nil { 
		fmt.Errorf("invalid leaf checksum: %v", err);
	}
	keyHash, err := values[1].ToHash()
	if err != nil { 
		fmt.Errorf("invalid leaf key hash: %v", err);
	}
	signature, err := values[2].ToSignature()
	if err != nil { 
		fmt.Errorf("invalid leaf signature: %v", err);
	}
	return types.Leaf{
		Checksum: checksum,
		KeyHash: keyHash,
		Signature : signature,
	}, nil
}

func (v Value) ToCosignature() (types.Cosignature, error) {
	values, err := v.Split(2)
	
	if err != nil { 
		fmt.Errorf("invalid cosignature: %v", err);
	}
	keyHash, err := values[0].ToHash()
	if err != nil { 
		fmt.Errorf("invalid cosignature key hash: %v", err);
	}
	signature, err := values[1].ToSignature()
	if err != nil { 
		fmt.Errorf("invalid cosignature signature: %v", err);
	}
	return types.Cosignature{
		KeyHash: keyHash,
		Signature : signature,
	}, nil
}

type Parser struct {
	scanner *bufio.Scanner
}

func NewParser(input io.Reader) Parser {
	// By default, scans by lines
	return Parser{bufio.NewScanner(input)}
}

func (p *Parser) Next(name string) (Value, error) {
	if !p.scanner.Scan() {
		return Value{}, io.EOF
	}
	line := p.scanner.Text()
	equals := strings.Index(line, "=")
	if equals < 0 {
		return Value{}, fmt.Errorf("invalid input line: %q", line)
	}
	key, value := line[:equals], line[equals+1:]
	if key != name {
		return Value{}, fmt.Errorf("invalid input line, expected %v, got key: %q", name, key)
	}

	return Value{value}, nil
}

func (p *Parser) GetInt(name string) (int64, error) {
	v, err := p.Next(name)
	if err != nil {
		return 0, err
	}
	return v.ToInt()
}

func (p *Parser) GetHash(name string) (merkle.Hash, error) {
	v, err := p.Next(name)
	if err != nil {
		return merkle.Hash{}, err
	}
	return v.ToHash()
}

func (p *Parser) GetPublicKey(name string) (types.PublicKey, error) {
	v, err := p.Next(name)
	if err != nil {
		return types.PublicKey{}, err
	}
	return v.ToPublicKey()
}

func (p *Parser) GetSignature(name string) (types.Signature, error) {
	v, err := p.Next(name)
	if err != nil {
		return types.Signature{}, err
	}
	return v.ToSignature()
}

func (p *Parser) GetCosignature(name string) (types.Cosignature, error) {
	v, err := p.Next(name)
	if err != nil {
		return types.Cosignature{}, err
	}
	return v.ToCosignature()
}

func (p *Parser) GetLeaf(name string) (types.Leaf, error) {
	v, err := p.Next(name)
	if err != nil {
		return types.Leaf{}, err
	}
	return v.ToLeaf()
}

func WriteLine(w io.Writer, key, value string) error {
	_, err := fmt.Fprintf(w, "%s=%s\n", key, value)
	return err
}

func WriteLineHex(w io.Writer, key string, first []byte, rest... []byte) error {
	_, err := fmt.Fprintf(w, "%s=%s", key, hex.EncodeToString(first))
	if err != nil {
		return err
	}
	for _, b := range rest {
		_, err :=fmt.Fprintf(w, " %s", hex.EncodeToString(b))
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(w, "\n")
	return err
}

func WriteInt(w io.Writer, name string, i int64) error {
	if i < 0 {
		return fmt.Errorf("invalid negative number: %d", i)
	}
	return WriteLine(w, name, strconv.FormatUint(uint64(i), 10))
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

func WriteCosignature(w io.Writer, name string, c *types.Cosignature) error {
	return WriteLineHex(w, name, c.KeyHash[:], c.Signature[:])
}

func WriteLeaf(w io.Writer, name string, l *types.Leaf) error {
	return WriteLineHex(w, name, l.Checksum[:], l.KeyHash[:], l.Signature[:])
}	
