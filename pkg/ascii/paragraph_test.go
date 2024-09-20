package ascii

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestParagraphReader(t *testing.T) {
	for _, table := range []struct {
		in   string
		want []string
	}{
		{"", []string{""}},
		{"ab", []string{"ab"}},
		{"ab\n", []string{"ab\n"}},
		{"ab\nc", []string{"ab\nc"}},
		{"ab\nc\n", []string{"ab\nc\n"}},

		{"ab\n\n", []string{"ab\n", ""}},
		{"ab\n\nc", []string{"ab\n", "c"}},
		{"ab\n\nc\n", []string{"ab\n", "c\n"}},
		{"ab\n\n\nc", []string{"ab\n", "\nc"}},

		// Abbreviated sigsum proof.
		{
			"version=1\nlog=abc\n\nsize=3\nroot_hash=def\n\nleaf_index=2\n",
			[]string{
				"version=1\nlog=abc\n",
				"size=3\nroot_hash=def\n",
				"leaf_index=2\n",
			},
		},
	} {
		pr := NewParagraphReader(bytes.NewBufferString(table.in))
		var nextErr error
		for i, want := range table.want {
			if nextErr != nil {
				t.Errorf("Failed at start of paragraph %d on input %q: %v",
					i, table.in, nextErr)
				continue
			}
			data, err := io.ReadAll(pr)
			if err != nil {
				t.Errorf("Failed for paragraph %d on input %q: %v",
					i, table.in, err)
				continue
			}
			if got := string(data); got != want {
				t.Errorf("Failed for paragraph %d on input %q: got %q, want %q",
					i, table.in, got, want)
				continue
			}
			nextErr = pr.NextParagraph()

		}
		if nextErr != io.EOF {
			t.Errorf("Unexpected result at end of data %q: got %v, want EOF",
				table.in, nextErr)
		}
	}
}

type shortReader struct {
	reader io.Reader
	size   int
}

func (r *shortReader) Read(buf []byte) (int, error) {
	if len(buf) > r.size {
		buf = buf[:r.size]
	}
	return r.reader.Read(buf)
}

func TestParagraphReaderPlainReader(t *testing.T) {
	input := "aaaaaaa\n\nbbbbb\n\nbbb\n"
	pr := NewParagraphReader(&shortReader{bytes.NewBufferString(input), 10})
	data, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "aaaaaaa\n"; got != want {
		t.Fatalf("got: %q, want: %q", got, want)
	}
	if got, want := string(pr.buf), "b"; got != want {
		t.Fatalf("ParagraphReader under test is not in expected state, buf: %v, want: %v", got, want)
	}
	data, err = io.ReadAll(pr.PlainReader())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "bbbbb\n\nbbb\n"; got != want {
		t.Fatalf("got: %q, want: %q", got, want)
	}
}

// A reader that returns the data followed by the given error.
type bufErrReader struct {
	data []byte
<<<<<<< HEAD
	err  error
=======
	err error
>>>>>>> 319c3a9 (Add ParagraphReader.PlainReader + post-rebase fixes)
}

func (r *bufErrReader) Read(buf []byte) (int, error) {
	if len(buf) < len(r.data) {
		copy(buf, r.data)
		r.data = r.data[len(buf):]
		return len(buf), nil
	}
	n := len(r.data)
	copy(buf, r.data)
	r.data = nil
	return n, r.err
}

func TestParagraphReaderPlainReaderWithError(t *testing.T) {
	input := "aaaaaaa\n\nbbbbb\n\nbbb\n"
	expErr := errors.New("test error")
	pr := NewParagraphReader(&bufErrReader{[]byte(input), expErr})
	data, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "aaaaaaa\n"; got != want {
		t.Fatalf("got: %q, want: %q", got, want)
	}
	if pr.err == nil {
		t.Fatalf("ParagraphReader under test is not in expected state, no error encountered")
	}
	data, err = io.ReadAll(pr.PlainReader())
	if err != expErr {
		t.Fatalf("expected test error, got: %v", err)
	}
	if got, want := string(data), "bbbbb\n\nbbb\n"; got != want {
		t.Fatalf("got: %q, want: %q", got, want)
	}
}
<<<<<<< HEAD
=======
	
>>>>>>> 319c3a9 (Add ParagraphReader.PlainReader + post-rebase fixes)
