// Package ascii implements an ASCII key-value parser and writer.
package ascii

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func IntFromDecimal(s string) (uint64, error) {
	// Use ParseUint, to not accept leading +/-.
	return strconv.ParseUint(s, 10, 63)
}

type Parser struct {
	scanner *bufio.Scanner
}

func NewParser(input io.Reader) Parser {
	p := Parser{bufio.NewScanner(input)}
	// This is like bufio.ScanLines but it doesn't strip CRs
	// and fails on final unterminated lines.
	p.scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[0:i], nil
		}
		if atEOF {
			if len(data) > 0 {
				return 0, nil, io.ErrUnexpectedEOF
			}
			return 0, nil, io.EOF
		}
		return 0, nil, nil
	})
	return p
}

func (p *Parser) GetEOF() error {
	if p.scanner.Scan() {
		return fmt.Errorf("garbage at end of message: %q",
			p.scanner.Text())
	}
	return p.scanner.Err()
}

// next scans the next line, expecting it to contain a key/value pair separated
// by =, where the key is name. It returns the value.
func (p *Parser) next(name string) (string, error) {
	if !p.scanner.Scan() {
		if err := p.scanner.Err(); err != nil {
			return "", err
		}
		return "", io.EOF
	}
	line := p.scanner.Text()
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

// Splits into at most n parts, separated by double new line
// (paragraph separator), keeping a single newline at end of parts.
func SplitParts(data []byte, n int) [][]byte {
	if n <= 0 {
		panic("invalid argument: SplitParts count must be > 0")
	}

	parts := make([][]byte, n)
	i := 0
	for ; i < n-1; i++ {
		end := bytes.Index(data, []byte{'\n', '\n'})
		if end < 0 {
			break
		}
		// Include the first newline character in this part.
		// Like bytes.Split, also trim capacity so range can't
		// be extended.
		parts[i] = data[: end+1 : end+1]
		data = data[end+2:]
	}
	parts[i] = data
	return parts[:i+1]
}
