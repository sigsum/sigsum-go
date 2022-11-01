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

	"sigsum.org/sigsum-go/pkg/crypto"
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

func HashFromHex(s string) (h crypto.Hash, err error) {
	var b []byte
	b, err = decodeHex(s, crypto.HashSize)
	copy(h[:], b)
	return
}

func PublicKeyFromHex(s string) (pub crypto.PublicKey, err error) {
	var b []byte
	b, err = decodeHex(s, crypto.PublicKeySize)
	copy(pub[:], b)
	return
}

func SignatureFromHex(s string) (sig crypto.Signature, err error) {
	var b []byte
	b, err = decodeHex(s, crypto.SignatureSize)
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

func (p *Parser) next(name string) (string, error) {
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
	v, err := p.next(name)
	if err != nil {
		return 0, err
	}
	return IntFromDecimal(v)
}

func (p *Parser) GetHash(name string) (crypto.Hash, error) {
	v, err := p.next(name)
	if err != nil {
		return crypto.Hash{}, err
	}
	return HashFromHex(v)
}

func (p *Parser) GetPublicKey(name string) (crypto.PublicKey, error) {
	v, err := p.next(name)
	if err != nil {
		return crypto.PublicKey{}, err
	}
	return PublicKeyFromHex(v)
}

func (p *Parser) GetSignature(name string) (crypto.Signature, error) {
	v, err := p.next(name)
	if err != nil {
		return crypto.Signature{}, err
	}
	return SignatureFromHex(v)
}

func (p *Parser) GetValues(name string, count int) ([]string, error) {
	v, err := p.next(name)
	if err != nil {
		return nil, err
	}
	return split(v, count)
}

// Treats empty list as an error.
func (p *Parser) GetHashes(name string) ([]crypto.Hash, error) {
	var hashes []crypto.Hash
	for {
		v, err := p.next(name)
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

func WriteHash(w io.Writer, name string, h *crypto.Hash) error {
	return WriteLineHex(w, name, (*h)[:])
}

func WritePublicKey(w io.Writer, name string, k *crypto.PublicKey) error {
	return WriteLineHex(w, name, (*k)[:])
}

func WriteSignature(w io.Writer, name string, s *crypto.Signature) error {
	return WriteLineHex(w, name, (*s)[:])
}
