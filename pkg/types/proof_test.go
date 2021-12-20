package types

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"
)

func TestInclusionProofToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.NewBuffer(nil)
	if err := validInclusionProof(t).ToASCII(buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validInclusionProofASCII(t); got != want {
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
			serialized: bytes.NewBuffer(append([]byte(validInclusionProofASCII(t)), []byte("tree_size=4")...)),
			wantErr:    true,
			want:       validInclusionProof(t), // to populate input to FromASCII
		},
		{
			desc:       "valid",
			serialized: bytes.NewBuffer([]byte(validInclusionProofASCII(t))),
			want:       validInclusionProof(t),
		},
	} {
		var proof InclusionProof
		err := proof.FromASCII(table.serialized, table.want.TreeSize)
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
	buf := bytes.NewBuffer(nil)
	if err := validConsistencyProof(t).ToASCII(buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validConsistencyProofASCII(t); got != want {
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
			serialized: bytes.NewBuffer(append([]byte(validConsistencyProofASCII(t)), []byte("start_size=1")...)),
			wantErr:    true,
			want:       validConsistencyProof(t), // to populate input to FromASCII
		},
		{
			desc:       "valid",
			serialized: bytes.NewBuffer([]byte(validConsistencyProofASCII(t))),
			want:       validConsistencyProof(t),
		},
	} {
		var proof ConsistencyProof
		err := proof.FromASCII(table.serialized, table.want.OldSize, table.want.NewSize)
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
		TreeSize:  4,
		Path: []Hash{
			Hash{},
			*newHashBufferInc(t),
		},
	}
}

func validInclusionProofASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%d\n%s=%x\n%s=%x\n",
		"leaf_index", 1,
		"inclusion_path", Hash{},
		"inclusion_path", newHashBufferInc(t)[:],
	)
}

func validConsistencyProof(t *testing.T) *ConsistencyProof {
	t.Helper()
	return &ConsistencyProof{
		NewSize: 1,
		OldSize: 4,
		Path: []Hash{
			Hash{},
			*newHashBufferInc(t),
		},
	}
}

func validConsistencyProofASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%x\n%s=%x\n",
		"consistency_path", Hash{},
		"consistency_path", newHashBufferInc(t)[:],
	)
}
