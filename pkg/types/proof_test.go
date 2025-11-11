package types

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
)

func TestInclusionProofToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.Buffer{}
	if err := validInclusionProof(t).ToASCII(&buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := buf.String(), validInclusionProofASCII(t); got != want {
		t.Errorf("got inclusion proof\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestInclusionProofFromASCII(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized io.Reader
		wantErr    bool
		want       *InclusionProof
	}{
		{
			desc:       "invalid: not an inclusion proof (unexpected key-value pair)",
			serialized: bytes.NewBufferString(validInclusionProofASCII(t) + "size=4"),
			wantErr:    true,
			want:       validInclusionProof(t), // to populate input to FromASCII
		},
		{
			desc:       "valid",
			serialized: bytes.NewBufferString(validInclusionProofASCII(t)),
			want:       validInclusionProof(t),
		},
	} {
		var proof InclusionProof
		err := proof.FromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &proof, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got inclusion proof\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestConsistencyProofToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.Buffer{}
	if err := validConsistencyProof(t).ToASCII(&buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := buf.String(), validConsistencyProofASCII(t); got != want {
		t.Errorf("got consistency proof\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestConsistencyProofFromASCII(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized io.Reader
		wantErr    bool
		want       *ConsistencyProof
	}{
		{
			desc:       "invalid: not a consistency proof (unexpected key-value pair)",
			serialized: bytes.NewBufferString(validConsistencyProofASCII(t) + "start_size=1"),
			wantErr:    true,
			want:       validConsistencyProof(t), // to populate input to FromASCII
		},
		{
			desc:       "valid",
			serialized: bytes.NewBufferString(validConsistencyProofASCII(t)),
			want:       validConsistencyProof(t),
		},
	} {
		var proof ConsistencyProof
		err := proof.FromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &proof, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got consistency proof\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestConsistencyProofToBase64(t *testing.T) {
	expBase64 := []string{
		"BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"FAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	writerToString := func(f func(w io.Writer) error) string {
		buf := bytes.Buffer{}
		if err := f(&buf); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	var pr ConsistencyProof
	if got, want := writerToString(pr.ToBase64), ""; got != want {
		t.Errorf("failed for size 0, got:\n%q\nwant\n%q", got, want)
	}
	for i := 1; i <= 5; i++ {
		pr.Path = append(pr.Path, crypto.Hash{byte(i << 2)})
		want := strings.Join(expBase64[:i], "\n") + "\n"
		if got := writerToString(pr.ToBase64); got != want {
			t.Errorf("failed for size %d, got:\n%q\nwant\n%q", i, got, want)
		}
	}
}

func TestConsistencyProofParseBase64(t *testing.T) {
	makeInput := func(size int) io.Reader {
		buf := bytes.Buffer{}
		for i := 0; i < size; i++ {
			fmt.Fprintf(&buf, "%cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", 'A'+(i%26))
		}
		return &buf
	}
	makePath := func(size int) []crypto.Hash {
		var path []crypto.Hash
		for i := 0; i < size; i++ {
			path = append(path, crypto.Hash{byte((i % 26) << 2)})
		}
		return path
	}
	for i := 0; i <= 63; i++ {
		var pr ConsistencyProof
		p := ascii.NewLineReader(makeInput(i))
		emptyLine, err := pr.ParseBase64(&p)
		if err != nil {
			t.Errorf("failed for size %d: %v", i, err)
			continue
		}
		if got, want := pr.Path, makePath(i); !slices.Equal(pr.Path, want) {
			t.Errorf("bad result for size %d, got: %v, want: %v", i, got, want)
		}
		if emptyLine {
			t.Errorf("unexpectedly got emptyLine = true")
		}
	}
	var pr ConsistencyProof
	p := ascii.NewLineReader(makeInput(64))
	_, err := pr.ParseBase64(&p)
	if err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Errorf("too large proof (size 64) not rejected, got err: %v", err)
	}
}

func validInclusionProof(t *testing.T) *InclusionProof {
	t.Helper()
	return &InclusionProof{
		LeafIndex: 1,
		Path: []crypto.Hash{
			crypto.Hash{},
			newHashBufferInc(t),
		},
	}
}

func validInclusionProofASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%d\n%s=%x\n%s=%x\n",
		"leaf_index", 1,
		"node_hash", crypto.Hash{},
		"node_hash", newHashBufferInc(t),
	)
}

func validConsistencyProof(t *testing.T) *ConsistencyProof {
	t.Helper()
	return &ConsistencyProof{
		Path: []crypto.Hash{
			crypto.Hash{},
			newHashBufferInc(t),
		},
	}
}

func validConsistencyProofASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%x\n%s=%x\n",
		"node_hash", crypto.Hash{},
		"node_hash", newHashBufferInc(t),
	)
}
