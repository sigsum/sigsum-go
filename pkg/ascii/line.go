package ascii

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
)

type LineReader struct {
	scanner *bufio.Scanner
}

func NewLineReader(input io.Reader) LineReader {
	scanner := bufio.NewScanner(input)
	// This is like bufio.ScanLines but it doesn't strip CRs
	// and fails on final unterminated lines.
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
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
	return LineReader{scanner}
}

func (lr *LineReader) GetLine() (string, error) {
	if lr.scanner.Scan() {
		return lr.scanner.Text(), nil
	}
	if err := lr.scanner.Err(); err != nil {
		return "", err
	}
	return "", io.EOF
}

// Returns nil if there's no more data available.
func (lr *LineReader) GetEOF() error {
	if lr.scanner.Scan() {
		return fmt.Errorf("garbage line at end of data: %q",
			lr.scanner.Text())
	}
	// Returns nil at EOF.
	return lr.scanner.Err()
}

func (lr *LineReader) GetEmptyLine() error {
	line, err := lr.GetLine()
	if err != nil {
		return err
	}
	if line != "" {
		return fmt.Errorf("garbage data where line should be empty: %q", line)
	}
	return nil
}
