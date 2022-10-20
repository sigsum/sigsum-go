package requests

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"

	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/types"
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
	req := InclusionProof{1, merkle.Hash{}}
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

func TestLeavesFromURL(t *testing.T) {
	for _, table := range []struct {
		desc    string
		input   string
		want    Leaves
		wantErr bool
	}{
		{"invalid: not enough parameters", "some-url", Leaves{}, true},
		{"invalid: start size has a leading sign", "some-url/+1/2", Leaves{}, true},
		{"invalid: start size is empty", "some-url//2", Leaves{}, true},
		{"invalid: end size is empty", "some-url/1/", Leaves{}, true},
		{"valid", "some-url/1/2", Leaves{1, 2}, false},
	} {
		var req Leaves
		err := req.FromURL(table.input)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("%s: got error %v but wanted %v: %v", table.desc, got, want, err)
		}
		if err != nil {
			continue
		}

		if got, want := req, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got leaves request\n%v\nbut wanted\n%v", table.desc, got, want)
		}
	}
}

func TestInclusionProofFromURL(t *testing.T) {
	badHex := "F0000000x0000000000000000000000000000000000000000000000000000000"
	shortHex := "00ff"
	zeroHash := "0000000000000000000000000000000000000000000000000000000000000000"
	for _, table := range []struct {
		desc    string
		input   string
		want    InclusionProof
		wantErr bool
	}{
		{"invalid: not enough parameters", "some-url", InclusionProof{}, true},
		{"invalid: tree size has a leading sign", "some-url/+1/" + zeroHash, InclusionProof{}, true},
		{"invalid: tree size is empty", "some-url//" + zeroHash, InclusionProof{}, true},
		{"invalid: leaf hash is invalid hex", "some-url/1/" + badHex, InclusionProof{}, true},
		{"invalid: leaf hash is hex but too short", "some-url/1/" + shortHex, InclusionProof{}, true},
		{"valid", "some-url/1/" + zeroHash, InclusionProof{1, merkle.Hash{}}, false},
	} {
		var req InclusionProof
		err := req.FromURL(table.input)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("%s: got error %v but wanted %v: %v", table.desc, got, want, err)
		}
		if err != nil {
			continue
		}

		if got, want := req, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got inclusion proof request\n%v\nbut wanted\n%v", table.desc, got, want)
		}
	}
}

func TestConsistencyProofFromURL(t *testing.T) {
	for _, table := range []struct {
		desc    string
		input   string
		want    ConsistencyProof
		wantErr bool
	}{
		{"invalid: not enough parameters", "some-url", ConsistencyProof{}, true},
		{"invalid: old size has a leading sign", "some-url/+1/2", ConsistencyProof{}, true},
		{"invalid: old size is empty", "some-url//2", ConsistencyProof{}, true},
		{"invalid: new size is empty", "some-url/1/", ConsistencyProof{}, true},
		{"valid", "some-url/1/2", ConsistencyProof{1, 2}, false},
	} {
		var req ConsistencyProof
		err := req.FromURL(table.input)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("%s: got error %v but wanted %v: %v", table.desc, got, want, err)
		}
		if err != nil {
			continue
		}

		if got, want := req, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got consistency proof request\n%v\nbut wanted\n%v", table.desc, got, want)
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

func newHashBufferInc(t *testing.T) *merkle.Hash {
	t.Helper()

	var buf merkle.Hash
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
