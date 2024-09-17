package ascii

import (
	"bytes"
	"io"
	"testing"
)

func TestLineReaderGetLine(t *testing.T) {
	reader := NewLineReader(bytes.NewBufferString("foo\n\nbar\r\n"))
	for i, want := range []string{"foo", "", "bar\r"} {
		got, err := reader.GetLine()
		if err != nil {
			t.Fatalf("Failed on line %d: %s", i, err)
		}
		if got != want {
			t.Errorf("Bad result on line %d: got %q, want %q",
				i, got, want)
		}
	}
	got, err := reader.GetLine()
	if err != io.EOF {
		t.Errorf("No EOF at end of data, got err: %v", err)
	}
	if got != "" {
		t.Errorf("Result not empty at end of data, got: %q", got)
	}
}

func TestLineReaderGetEOF(t *testing.T) {
	for _, table := range []struct {
		in     string
		n      int
		expErr bool
	}{
		{in: "", n: 0},
		{in: "bar\n", n: 1},
		{in: "bar", n: 0, expErr: true},
		{in: "bar\n\n", n: 2},
		{in: "bar\n\nfoo\n", n: 3},
		{in: "bar\n\nfoo", n: 2, expErr: true},
	} {
		// Test that GetEOF fails when we haven't read all lines.
		for i := 0; i < table.n; i++ {
			reader := NewLineReader(bytes.NewBufferString(table.in))
			for j := 0; j < i; j++ {
				if _, err := reader.GetLine(); err != nil {
					t.Fatal(err)
				}
			}
			err := reader.GetEOF()
			if err == nil {
				t.Errorf("unexpected success of GetEOF after %d out of %d lines", i, table.n)
			}
		}
		reader := NewLineReader(bytes.NewBufferString(table.in))
		for i := 0; i < table.n; i++ {
			if _, err := reader.GetLine(); err != nil {
				t.Fatal(err)
			}
		}
		err := reader.GetEOF()
		if table.expErr {
			if err == nil || err == io.EOF {
				t.Errorf("expected error, got %v", err)
			}
		} else {
			if err != nil {
				t.Error(err)
			}
		}
	}
}
