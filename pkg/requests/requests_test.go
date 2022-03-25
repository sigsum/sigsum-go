package requests

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"

	"git.sigsum.org/sigsum-lib-go/pkg/types"
)

func TestLeafToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.NewBuffer(nil)
	if err := validLeaf(t).ToASCII(buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validLeafASCII(t); got != want {
		t.Errorf("got leaf request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestLeavesToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.NewBuffer(nil)
	if err := validLeaves(t).ToASCII(buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validLeavesASCII(t); got != want {
		t.Errorf("got leaves request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestInclusionProofToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.NewBuffer(nil)
	if err := validInclusionProof(t).ToASCII(buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validInclusionProofASCII(t); got != want {
		t.Errorf("got inclusion proof request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestConsistencyProofToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.NewBuffer(nil)
	if err := validConsistencyProof(t).ToASCII(buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validConsistencyProofASCII(t); got != want {
		t.Errorf("got consistency proof request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestCosignatureToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.NewBuffer(nil)
	if err := validCosignature(t).ToASCII(buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validCosignatureASCII(t); got != want {
		t.Errorf("got cosignature request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
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
			desc: "invalid: not a leaf request (unexpected key-value pair)",
			serialized: bytes.NewBuffer(
				append([]byte(validLeafASCII(t)),
					[]byte("key=4")...),
			),
			wantErr: true,
		},
		{
			desc:       "valid",
			serialized: bytes.NewBuffer([]byte(validLeafASCII(t))),
			want:       validLeaf(t),
		},
	} {
		var proof Leaf
		err := proof.FromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &proof, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got leaf request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestLeavesFromASCII(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized io.Reader
		wantErr    bool
		want       *Leaves
	}{
		{
			desc: "invalid: not a leaves request (unexpected key-value pair)",
			serialized: bytes.NewBuffer(
				append([]byte(validLeavesASCII(t)),
					[]byte("key=4")...),
			),
			wantErr: true,
		},
		{
			desc:       "valid",
			serialized: bytes.NewBuffer([]byte(validLeavesASCII(t))),
			want:       validLeaves(t),
		},
	} {
		var req Leaves
		err := req.FromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &req, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got leaves request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
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
			desc: "invalid: not an inclusion proof request (unexpected key-value pair)",
			serialized: bytes.NewBuffer(append(
				[]byte(validInclusionProofASCII(t)),
				[]byte("key=4")...),
			),
			wantErr: true,
		},
		{
			desc:       "valid",
			serialized: bytes.NewBuffer([]byte(validInclusionProofASCII(t))),
			want:       validInclusionProof(t),
		},
	} {
		var req InclusionProof
		err := req.FromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &req, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got inclusion proof request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
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
			desc: "invalid: not a consistency proof request (unexpected key-value pair)",
			serialized: bytes.NewBuffer(
				append([]byte(validConsistencyProofASCII(t)),
					[]byte("tree_size=4")...),
			),
			wantErr: true,
		},
		{
			desc:       "valid",
			serialized: bytes.NewBuffer([]byte(validConsistencyProofASCII(t))),
			want:       validConsistencyProof(t),
		},
	} {
		var req ConsistencyProof
		err := req.FromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &req, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got consistency proof request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestCosignatureFromASCII(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized io.Reader
		wantErr    bool
		want       *Cosignature
	}{
		{
			desc: "invalid: not a cosignature request (unexpected key-value pair)",
			serialized: bytes.NewBuffer(
				append([]byte(validCosignatureASCII(t)),
					[]byte("key=4")...),
			),
			wantErr: true,
		},
		{
			desc:       "valid",
			serialized: bytes.NewBuffer([]byte(validCosignatureASCII(t))),
			want:       validCosignature(t),
		},
	} {
		var req Cosignature
		err := req.FromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &req, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got cosignature request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func validLeaf(t *testing.T) *Leaf {
	t.Helper()
	return &Leaf{
		ShardHint:       1,
		Preimage:        *types.HashFn(newHashBufferInc(t)[:]),
		Signature:       *newSigBufferInc(t),
		VerificationKey: *newPubBufferInc(t),
		DomainHint:      "example.com",
	}
}

func validLeafASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%d\n%s=%x\n%s=%x\n%s=%x\n%s=%s\n",
		"shard_hint", 1,
		"preimage", types.HashFn(newHashBufferInc(t)[:])[:],
		"signature", newSigBufferInc(t)[:],
		"verification_key", newPubBufferInc(t)[:],
		"domain_hint", "example.com",
	)
}

func validLeaves(t *testing.T) *Leaves {
	t.Helper()
	return &Leaves{
		StartSize: 1,
		EndSize:   4,
	}
}

func validLeavesASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%d\n%s=%d\n",
		"start_size", 1,
		"end_size", 4,
	)
}

func validInclusionProof(t *testing.T) *InclusionProof {
	t.Helper()
	return &InclusionProof{
		LeafHash: *newHashBufferInc(t),
		TreeSize: 4,
	}
}

func validInclusionProofASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%x\n%s=%d\n",
		"leaf_hash", newHashBufferInc(t)[:],
		"tree_size", 4,
	)
}

func validConsistencyProof(t *testing.T) *ConsistencyProof {
	t.Helper()
	return &ConsistencyProof{
		NewSize: 4,
		OldSize: 1,
	}
}

func validConsistencyProofASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%d\n%s=%d\n",
		"new_size", 4,
		"old_size", 1,
	)
}

func validCosignature(t *testing.T) *Cosignature {
	t.Helper()
	return &Cosignature{
		Cosignature: *newSigBufferInc(t),
		KeyHash:     *newHashBufferInc(t),
	}
}

func validCosignatureASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%x\n%s=%x\n",
		"cosignature", newSigBufferInc(t)[:],
		"key_hash", newHashBufferInc(t)[:],
	)
}

func newHashBufferInc(t *testing.T) *types.Hash {
	t.Helper()

	var buf types.Hash
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}
	return &buf
}

func newSigBufferInc(t *testing.T) *types.Signature {
	t.Helper()

	var buf types.Signature
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}
	return &buf
}

func newPubBufferInc(t *testing.T) *types.PublicKey {
	t.Helper()

	var buf types.PublicKey
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}
	return &buf
}
