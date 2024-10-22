package requests

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestLeafToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.Buffer{}
	if err := validLeaf(t).ToASCII(&buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := buf.String(), validLeafASCII(t); got != want {
		t.Errorf("got leaf request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestLeavesToURL(t *testing.T) {
	url := types.EndpointGetLeaves.Path("https://poc.sigsum.org")
	req := Leaves{1, 2}
	want := url + "1/2"
	if got := req.ToURL(url); got != want {
		t.Errorf("got url %s but wanted %s", got, want)
	}
}

func TestInclusionProofToURL(t *testing.T) {
	url := types.EndpointGetInclusionProof.Path("https://poc.sigsum.org")
	req := InclusionProof{1, crypto.Hash{}}
	want := url + "1/0000000000000000000000000000000000000000000000000000000000000000"
	if got := req.ToURL(url); got != want {
		t.Errorf("got url %s but wanted %s", got, want)
	}
}

func TestConsistencyProofToURL(t *testing.T) {
	url := types.EndpointGetConsistencyProof.Path("https://poc.sigsum.org")
	req := ConsistencyProof{1, 2}
	want := url + "1/2"
	if got := req.ToURL(url); got != want {
		t.Errorf("got url %s but wanted %s", got, want)
	}
}

func TestLeafFromASCII(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized io.Reader
		wantErr    bool
		want       *Leaf
	}{
		{
			desc:       "invalid: not a leaf request (unexpected key-value pair)",
			serialized: bytes.NewBufferString(validLeafASCII(t) + "key=4"),
			wantErr:    true,
		},
		{
			desc:       "valid",
			serialized: bytes.NewBufferString(validLeafASCII(t)),
			want:       validLeaf(t),
		},
	} {
		var leaf Leaf
		err := leaf.FromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := leaf, *table.want; got != want {
			t.Errorf("got leaf request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestLeavesFromURLArgs(t *testing.T) {
	for _, table := range []struct {
		desc       string
		start, end string
		want       *Leaves
		wantErr    string
	}{
		{
			desc:    "bad start",
			start:   "x",
			end:     "12",
			wantErr: "parsing \"x\"",
		},
		{
			desc:    "bad end",
			start:   "1",
			end:     "-2",
			wantErr: "parsing \"-2\"",
		},
		{
			desc:  "valid range",
			start: "1",
			end:   "20",
			want:  &Leaves{StartIndex: 1, EndIndex: 20},
		},
		{
			desc:  "valid syntax, improper range",
			start: "20",
			end:   "1",
			want:  &Leaves{StartIndex: 20, EndIndex: 1},
		},
	} {
		var leaves Leaves
		err := leaves.FromURLArgs(table.start, table.end)
		if table.want != nil {
			if err != nil {
				t.Errorf("test %s: %v", table.desc, err)
			} else if leaves != *table.want {
				t.Errorf("test %s: got %v, want %v", table.desc, leaves, *table.want)
			}
		} else if err == nil {
			t.Errorf("test %s: expected err, got result %v", table.desc, leaves)
		} else if !strings.Contains(err.Error(), table.wantErr) {
			t.Errorf("test %s: expected err %q, got %v", table.desc, table.wantErr, err)
		}
	}
}

func TestInclusionProofFromURLArgs(t *testing.T) {
	for _, table := range []struct {
		desc       string
		size, hash string
		want       *InclusionProof
		wantErr    string
	}{
		{
			desc:    "bad size",
			size:    "x",
			hash:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wantErr: "parsing \"x\"",
		},
		{
			desc:    "bad hash",
			size:    "10",
			hash:    "aaaaa",
			wantErr: "odd length",
		},
		{
			desc: "valid",
			size: "10",
			hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			want: &InclusionProof{
				Size: 10,
				LeafHash: crypto.Hash{
					170, 170, 170, 170, 170, 170, 170, 170,
					170, 170, 170, 170, 170, 170, 170, 170,
					170, 170, 170, 170, 170, 170, 170, 170,
					170, 170, 170, 170, 170, 170, 170, 170,
				},
			},
		},
	} {
		var proof InclusionProof
		err := proof.FromURLArgs(table.size, table.hash)
		if table.want != nil {
			if err != nil {
				t.Errorf("test %s: %v", table.desc, err)
			} else if proof != *table.want {
				t.Errorf("test %s: got %v, want %v", table.desc, proof, *table.want)
			}
		} else if err == nil {
			t.Errorf("test %s: expected err, got result %v", table.desc, proof)
		} else if !strings.Contains(err.Error(), table.wantErr) {
			t.Errorf("test %s: expected err %q, got %v", table.desc, table.wantErr, err)
		}
	}

}

func TestConsistencyProofFromURLArgs(t *testing.T) {
	for _, table := range []struct {
		desc     string
		old, new string
		want     *ConsistencyProof
		wantErr  string
	}{
		{
			desc:    "bad old",
			old:     "x",
			new:     "12",
			wantErr: "parsing \"x\"",
		},
		{
			desc:    "bad new",
			old:     "1",
			new:     "-2",
			wantErr: "parsing \"-2\"",
		},
		{
			desc: "valid range",
			old:  "1",
			new:  "20",
			want: &ConsistencyProof{OldSize: 1, NewSize: 20},
		},
		{
			desc: "valid syntax, improper range",
			old:  "20",
			new:  "1",
			want: &ConsistencyProof{OldSize: 20, NewSize: 1},
		},
	} {
		var proof ConsistencyProof
		err := proof.FromURLArgs(table.old, table.new)
		if table.want != nil {
			if err != nil {
				t.Errorf("test %s: %v", table.desc, err)
			} else if proof != *table.want {
				t.Errorf("test %s: got %v, want %v", table.desc, proof, *table.want)
			}
		} else if err == nil {
			t.Errorf("test %s: expected err, got result %v", table.desc, proof)
		} else if !strings.Contains(err.Error(), table.wantErr) {
			t.Errorf("test %s: expected err %q, got %v", table.desc, table.wantErr, err)
		}
	}
}

func validLeaf(t *testing.T) *Leaf {
	t.Helper()
	return &Leaf{
		Message:   *newHashBufferInc(t),
		Signature: *newSigBufferInc(t),
		PublicKey: *newPubBufferInc(t),
	}
}

func validLeafASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%x\n%s=%x\n%s=%x\n",
		"message", newHashBufferInc(t)[:],
		"signature", newSigBufferInc(t)[:],
		"public_key", newPubBufferInc(t)[:],
	)
}

func validLeaves(t *testing.T) *Leaves {
	t.Helper()
	return &Leaves{
		StartIndex: 1,
		EndIndex:   4,
	}
}

func newHashBufferInc(t *testing.T) *crypto.Hash {
	t.Helper()

	var buf crypto.Hash
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}
	return &buf
}

func newSigBufferInc(t *testing.T) *crypto.Signature {
	t.Helper()

	var buf crypto.Signature
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}
	return &buf
}

func newPubBufferInc(t *testing.T) *crypto.PublicKey {
	t.Helper()

	var buf crypto.PublicKey
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}
	return &buf
}
