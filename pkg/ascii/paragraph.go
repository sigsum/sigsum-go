package ascii

import (
	"bytes"
	"fmt"
	"io"
)

const (
	// To limit the amount of data we may to store a copy of.
	maxParagraphBufferSize = 1024
)

// Make a slice copy, reusing b's underlying array, if possible.
func copySlice(b []byte, s []byte) []byte {
	if len(s) > cap(b) {
		// Allocate a new slice.
		return append([]byte{}, s...)
	}
	b = b[:len(s)]
	copy(b, s)
	return b
}

// Implements io.Reader, wrapping an underlying io.Reader. Returns EOF
// when encountering a paragraph separator (double newline), passing
// on only the first newline to the reader.
type ParagraphReader struct {
	// Underlying reader.
	r io.Reader
	// Encountered end of paragraph, Read returns EOF, and
	// NextParagraph can be used to continue reading next
	// paragraph.
	atEnd bool
	// Last read character was a newline.
	atEndOfLine bool
	// Error (possibly EOF) from underlying reader.
	err error
	// Buffered left-over data.
	buf []byte
}

// If a double newline is found, return the index of the
// second newline character, otherwise returns -1.
func findEndOfParagraph(atEndOfLine bool, p []byte) int {
	if atEndOfLine && len(p) > 0 && p[0] == '\n' {
		return 0
	}
	end := bytes.Index(p, []byte{'\n', '\n'})
	if end >= 0 {
		return end + 1
	}
	return -1
}

func (pr *ParagraphReader) Read(p []byte) (int, error) {
	if pr.atEnd {
		return 0, io.EOF
	}
	n := len(p)
	if len(pr.buf) > 0 {
		if n > len(pr.buf) {
			n = len(pr.buf)
		}
		end := findEndOfParagraph(pr.atEndOfLine, pr.buf[:n])
		if end >= 0 {
			copy(p[:end], pr.buf[:end])
			pr.buf = pr.buf[end+1:]
			pr.atEnd = true
			return end, io.EOF
		}
		pr.atEndOfLine = (pr.buf[n-1] == '\n')
		copy(p[:n], pr.buf[:n])
		pr.buf = pr.buf[n:]
		return n, nil
	}
	if pr.err != nil {
		return 0, pr.err
	}
	if n > maxParagraphBufferSize {
		n = maxParagraphBufferSize
	}
	n, pr.err = pr.r.Read(p[:n])
	if n == 0 {
		return 0, pr.err
	}
	end := findEndOfParagraph(pr.atEndOfLine, p[:n])
	if end >= 0 {
		pr.buf = copySlice(pr.buf, p[end+1:n])
		pr.atEnd = true
		return end, io.EOF
	}

	pr.atEndOfLine = (p[n-1] == '\n')
	return n, pr.err
}

// Advances to next paragraph, if at a paragraph separator. Should be
// called only after encountering EOF from Read. If at the end of the
// data from the underlying io.Reader, returns the corresponding
// error, in particular, io.EOF means that the last paragraph has been
// read.
func (pr *ParagraphReader) NextParagraph() error {
	if pr.atEnd {
		pr.atEnd = false
		pr.atEndOfLine = false
		if len(pr.buf) == 0 {
			return pr.err
		}
		return nil
	}

	if len(pr.buf) == 0 && pr.err != nil {
		// At end of underlying reader.
		return pr.err
	}
	return fmt.Errorf("not at end of paragraph")
}

type errReader struct {
	err error
}

func (r errReader) Read(buf []byte) (int, error) {
	return 0, r.err
}

// Returns a plain reader for the rest of the data, with no special
// handling of paragraph separators.
func (pr *ParagraphReader) PlainReader() io.Reader {
	if pr.err != nil {
		return io.MultiReader(bytes.NewBuffer(pr.buf), errReader{pr.err})
	}
	return io.MultiReader(bytes.NewBuffer(pr.buf), pr.r)
}

func NewParagraphReader(r io.Reader) *ParagraphReader {
	return &ParagraphReader{r: r}
}
