// package ascii implements an ASCII key-value parser and writer
package ascii

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
)

// Basic value types
func intFromDecimal(s string) (uint64, error) {
	// Use ParseUint, to not accept leading +/-.
	i, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if i >= (1 << 63) {
		return 0, fmt.Errorf("integer %d is out of range", i)
	}
	return i, nil
}

func split(s string, n int) ([]string, error) {
	values := strings.Split(s, " ")

	if len(values) != n {
		return nil, fmt.Errorf("bad number of values, got %d, expected %d",
			len(values), n)
	}
	return values, nil
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
	return intFromDecimal(v)
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
	return split(v, count)
}
