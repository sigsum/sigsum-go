package ascii

import (
	"testing"

	"bytes"
	"fmt"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func TestValidIntFromDecimal(t *testing.T) {
	for _, table := range []struct {
		in   string
		want uint64
	}{
		{"0", 0},
		{"1", 1},
		{"9223372036854775807", (1 << 63) - 1},
	} {
		x, err := IntFromDecimal(table.in)
		if err != nil {
			t.Errorf("error on valid input %q: %v", table.in, err)
		}
		if x != table.want {
			t.Errorf("failed on %q, wanted %d, got %d",
				table.in, table.want, x)
		}
	}
}

func TestInvalidIntFromDecimal(t *testing.T) {
	for _, in := range []string{
		"",
		"-1",
		"+9",
		" 1",
		"1 ",
		"0123456789",
		"123456789x",
		"9223372036854775808",
		"99223372036854775808",
	} {
		x, err := IntFromDecimal(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %d",
				in, x)
		}
	}
}

func TestParser(t *testing.T) {
	hash := crypto.HashBytes([]byte("x"))
	input := fmt.Sprintf("hash=%x\nint=12345\nvalues=a b c\n", hash)

	p := NewParser(bytes.NewBufferString(input))
	if got, err := p.GetHash("hash"); err != nil || got != hash {
		if err != nil {
			t.Fatal(err)
		}
		t.Errorf("bad hash, got %x, wanted %x", got, hash)
	}

	if got, err := p.GetInt("int"); err != nil || got != 12345 {
		if err != nil {
			t.Fatal(err)
		}
		t.Errorf("bad int, got %d, wanted %d", got, 12345)
	}
	v, err := p.GetValues("values", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 3 {
		t.Errorf("unexpected number of values (wanted 3): %#v", v)
	}
	if v[0] != "a" || v[1] != "b" || v[2] != "c" {
		t.Errorf("unexpected values (wanted a, b,c): %#v", v)
	}
	if err := p.GetEOF(); err != nil {
		t.Errorf("GetEOF failure: %v", err)
	}
}

func TestParserCRLF(t *testing.T) {
	input := "foo=bar\r\nfoo=bar\r\n"
	p := NewParser(bytes.NewBufferString(input))
	v, err := p.GetValues("foo", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 {
		t.Errorf("unexpected number of values (wanted 1): %#v", v)
	}
	if v[0] != "bar\r" {
		t.Errorf("unexpected values (wanted bar and a CR): %q", v[0])
	}
}

func TestParserMissingNewline(t *testing.T) {
	input := "foo=bar\nx=y"
	p := NewParser(bytes.NewBufferString(input))
	if _, err := p.GetValues("foo", 1); err != nil {
		t.Errorf("GetValues failure: %v", err)
	}
	if _, err := p.GetValues("x", 1); err == nil {
		t.Errorf("expected GetValues failure")
	}
}

func TestParserEOF(t *testing.T) {
	input := "foo=bar\n"
	p := NewParser(bytes.NewBufferString(input))
	if _, err := p.GetValues("foo", 1); err != nil {
		t.Errorf("GetValues failure: %v", err)
	}
	if _, err := p.GetValues("foo", 1); err == nil {
		t.Errorf("expected GetValues error")
	}
}

func TestParserGetEOF(t *testing.T) {
	input := "foo=bar\nx=y\n"
	p := NewParser(bytes.NewBufferString(input))
	if _, err := p.GetValues("foo", 1); err != nil {
		t.Errorf("GetValues failure: %v", err)
	}
	if err := p.GetEOF(); err == nil {
		t.Errorf("expected GetEOF failure")
	}
}

func TestParserEOFGarbage(t *testing.T) {
	input := "foo=bar\ngarbage"
	p := NewParser(bytes.NewBufferString(input))
	if _, err := p.GetValues("foo", 1); err != nil {
		t.Errorf("GetValues failure: %v", err)
	}
	if err := p.GetEOF(); err == nil {
		t.Errorf("expected GetEOF failure")
	}
}
