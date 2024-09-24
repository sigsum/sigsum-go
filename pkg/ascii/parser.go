// Package ascii implements an ASCII key-value parser and writer.
package ascii

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
)

var ErrEmptyLine = errors.New("encountered an empty line")

func IntFromDecimal(s string) (uint64, error) {
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("invalid decimal number %q, must be no leading zeros", s)
	}
	// Use ParseUint, to not accept leading +/-.
	return strconv.ParseUint(s, 10, 63)
}

type Parser struct {
	reader LineReader
}

func NewParser(input io.Reader) Parser {
	return Parser{NewLineReader(input)}
}

func (p *Parser) GetEOF() error {
	return p.reader.GetEOF()
}

func (p *Parser) GetEmptyLine() error {
	return p.reader.GetEmptyLine()
}

// next scans the next line, expecting it to contain a key/value pair
// separated by =, where the key is name. It returns the value. In
// case line is completely empty (which sometimes terminates a list of
// values), returns ErrEmptyLine.
func (p *Parser) next(name string) (string, error) {
	line, err := p.reader.GetLine()
	if err != nil {
		return "", err
	}
	if line == "" {
		return "", ErrEmptyLine
	}
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		return "", fmt.Errorf("invalid input line: %q", line)
	}
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
	return crypto.HashFromHex(v)
}

func (p *Parser) GetPublicKey(name string) (crypto.PublicKey, error) {
	v, err := p.next(name)
	if err != nil {
		return crypto.PublicKey{}, err
	}
	return crypto.PublicKeyFromHex(v)
}

func (p *Parser) GetSignature(name string) (crypto.Signature, error) {
	v, err := p.next(name)
	if err != nil {
		return crypto.Signature{}, err
	}
	return crypto.SignatureFromHex(v)
}

func (p *Parser) GetValues(name string, count int) ([]string, error) {
	v, err := p.next(name)
	if err != nil {
		return nil, err
	}
	values := strings.Split(v, " ")

	if len(values) != count {
		return nil, fmt.Errorf("bad number of values, got %d, expected %d",
			len(values), count)
	}
	return values, nil
}
