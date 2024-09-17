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

func (lr *LineReader) GetEOF() error {
	if lr.scanner.Scan() {
		return fmt.Errorf("garbage at end of data: %q",
			lr.scanner.Text())
	}
	return lr.scanner.Err()
}
