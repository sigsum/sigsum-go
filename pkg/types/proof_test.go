package types

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"

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

func validInclusionProof(t *testing.T) *InclusionProof {
	t.Helper()
	return &InclusionProof{
		LeafIndex: 1,
		Path: []crypto.Hash{
			crypto.Hash{},
			*newHashBufferInc(t),
		},
	}
}

func validInclusionProofASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%d\n%s=%x\n%s=%x\n",
		"leaf_index", 1,
		"node_hash", crypto.Hash{},
		"node_hash", newHashBufferInc(t)[:],
	)
}

func validConsistencyProof(t *testing.T) *ConsistencyProof {
	t.Helper()
	return &ConsistencyProof{
		Path: []crypto.Hash{
			crypto.Hash{},
			*newHashBufferInc(t),
		},
	}
}

func validConsistencyProofASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%x\n%s=%x\n",
		"node_hash", crypto.Hash{},
		"node_hash", newHashBufferInc(t)[:],
	)
}
