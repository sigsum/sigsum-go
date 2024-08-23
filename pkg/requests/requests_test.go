package requests

import (
	"bytes"
	"fmt"
	"io"
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
