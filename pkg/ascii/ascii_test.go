package ascii

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestValidIntFromDecimal(t *testing.T) {
	for _, table := range []struct {
		in   string
		want uint64
	}{
		{"0", 0},
		{"1", 1},
		{"0123456789", 123456789},
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
		"0123456789x",
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

func incBytes(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = byte(i)
	}
}

func newIncBytes(n int) []byte {
	b := make([]byte, n)
	incBytes(b)
	return b
}

func incHash() (h merkle.Hash) {
	incBytes(h[:])
	return
}

func incSignature() (s types.Signature) {
	incBytes(s[:])
	return
}

func TestValidHashFromHex(t *testing.T) {
	b := newIncBytes(32)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		s, strings.ToUpper(s),
	} {
		hash, err := HashFromHex(in)
		if err != nil {
			t.Errorf("error on input %q: %v", in, err)
		}
		if !bytes.Equal(b, hash[:]) {
			t.Errorf("fail on input %q, wanted %x, got %x", in, b, hash)
		}
	}
}

func TestInvalidHashFromHex(t *testing.T) {
	b := newIncBytes(33)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		"", "0x11", "123z", s[:63], s[:65], s[:66],
	} {
		hash, err := HashFromHex(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %x",
				in, hash)
		}
	}
}

func TestValidPublicKeyFromHex(t *testing.T) {
	b := newIncBytes(32)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		s, strings.ToUpper(s),
	} {
		hash, err := PublicKeyFromHex(in)
		if err != nil {
			t.Errorf("error on input %q: %v", in, err)
		}
		if !bytes.Equal(b, hash[:]) {
			t.Errorf("fail on input %q, wanted %x, got %x", in, b, hash)
		}
	}
}

func TestInvalidPublicKeyFromHex(t *testing.T) {
	b := newIncBytes(33)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		"", "0x11", "123z", s[:63], s[:65], s[:66],
	} {
		hash, err := PublicKeyFromHex(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %x",
				in, hash)
		}
	}
}

func TestValidSignatureFromHex(t *testing.T) {
	b := newIncBytes(64)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		s, strings.ToUpper(s),
	} {
		hash, err := SignatureFromHex(in)
		if err != nil {
			t.Errorf("error on input %q: %v", in, err)
		}
		if !bytes.Equal(b, hash[:]) {
			t.Errorf("fail on input %q, wanted %x, got %x", in, b, hash)
		}
	}
}

func TestInvalidSignatureFromHex(t *testing.T) {
	b := newIncBytes(65)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		"", "0x11", "123z", s[:127], s[:129], s[:130],
	} {
		hash, err := SignatureFromHex(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %x",
				in, hash)
		}
	}
}

func TestWriteLeaf(t *testing.T) {
	desc := "valid: buffers 0x00,0x01,..."
	buf := bytes.NewBuffer(nil)
	leaf := validLeaf()
	if err := WriteLeaf(buf, &leaf); err != nil {
		t.Fatalf("WriteLeaf failed in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validLeafASCII(); got != want {
		t.Errorf("got leaf\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}


func TestGetLeaves(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized string
		wantErr    bool
		want       []types.Leaf
	}{
		{
			desc:       "invalid: not a list of tree leaves (bad key)",
			serialized: "checksum=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
			wantErr:    true,
		},
		{
			desc:       "invalid: not a list of tree leaves (leaf + extra key-value pair)",
			serialized: validLeafASCII() + "key=value\n",
			wantErr:    true,
		},
		{
			desc:       "invalid: not a list of tree leaves (invalid checksum))",
			serialized: invalidLeavesASCII(t, "checksum"),
			wantErr:    true,
		},
		{
			desc:       "invalid: not a list of tree leaves (invalid signature))",
			serialized: invalidLeavesASCII(t, "signature"),
			wantErr:    true,
		},
		{
			desc:       "invalid: not a list of tree leaves (invalid hash))",
			serialized: invalidLeavesASCII(t, "key_hash"),
			wantErr:    true,
		},
		{
			desc:       "valid leaves",
			serialized: validLeavesASCII(),
			want:       validLeaves(),
		},
	} {
		p := NewParser(bytes.NewBuffer([]byte(table.serialized)))
		leaves, err := p.GetLeaves()
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v\ninput: %s",
				got, want, table.desc, err, table.serialized)
		}
		if err != nil {
			continue
		}
		if got, want := leaves, table.want; !leavesEqual(got, want) {
			t.Errorf("got leaves\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestWriteSignedTreeHead(t *testing.T) {
	desc := "valid"
	buf := bytes.NewBuffer(nil)
	th := validSignedTreeHead()
	if err := WriteSignedTreeHead(buf, &th); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validSignedTreeHeadASCII(); got != want {
		t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestGetSignedTreeHead(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized string
		wantErr    bool
		want       types.SignedTreeHead
	}{
		{
			desc:       "invalid: not a signed tree head (unexpected key-value pair)",
			serialized: validSignedTreeHeadASCII() + "key=4\n",
			wantErr:    true,
		},
		{
			desc:       "valid",
			serialized: validSignedTreeHeadASCII(),
			want:       validSignedTreeHead(),
		},
	} {
		p := NewParser(bytes.NewBuffer([]byte(table.serialized)))
		sth, err := p.GetSignedTreeHead()
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := sth, table.want; got != want {
			t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestWriteCosignedTreeHead(t *testing.T) {
	desc := "valid"
	buf := bytes.NewBuffer(nil)
	cth := validCosignedTreeHead()
	if err := WriteCosignedTreeHead(buf, &cth); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validCosignedTreeHeadASCII(); got != want {
		t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestGetCosignedTreeHead(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized string
		wantErr    bool
		want       types.CosignedTreeHead
	}{
		{
			desc:       "invalid: not a cosigned tree head (unexpected key-value pair)",
			serialized: validCosignedTreeHeadASCII() + "key=4\n",
			wantErr:    true,
		},
		{
			desc:       "valid",
			serialized: validCosignedTreeHeadASCII(),
			want:       validCosignedTreeHead(),
		},
	} {
		p := NewParser(bytes.NewBuffer([]byte(table.serialized)))
		cth, err := p.GetCosignedTreeHead()
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &cth, table.want; !(got.SignedTreeHead == want.SignedTreeHead && cosignaturesEqual(got.Cosignatures, want.Cosignatures)) {
			t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestGetInclusionProof(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized string
		wantErr    bool
		want       types.InclusionProof
	}{
		{
			desc:       "invalid: not an inclusion proof (unexpected key-value pair)",
			serialized: validInclusionProofASCII() + "tree_size=4\n",
			wantErr:    true,
			want:       validInclusionProof(), // to populate input to FromASCII
		},
		{
			desc:       "valid",
			serialized: validInclusionProofASCII(),
			want:       validInclusionProof(),
		},
	} {
		p := NewParser(bytes.NewBuffer([]byte(table.serialized)))
		proof, err := p.GetInclusionProof(table.want.TreeSize)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := proof, table.want; !(got.LeafIndex == want.LeafIndex && hashesEqual(want.Path, got.Path)) {
			t.Errorf("got inclusion proof\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestWriteConsistencyProof(t *testing.T) {
	desc := "valid"
	buf := bytes.NewBuffer(nil)
	proof := validConsistencyProof()
	if err := WriteConsistencyProof(buf, &proof); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validConsistencyProofASCII(); got != want {
		t.Errorf("got consistency proof\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestGetConsistencyProof(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized string
		wantErr    bool
		want       types.ConsistencyProof
	}{
		{
			desc:       "invalid: not a consistency proof (unexpected key-value pair)",
			serialized: validConsistencyProofASCII() + "start_size=1\n",
			wantErr:    true,
			want:       validConsistencyProof(), // to populate input to FromASCII
		},
		{
			desc:       "valid",
			serialized: validConsistencyProofASCII(),
			want:       validConsistencyProof(),
		},
	} {
		p := NewParser(bytes.NewBuffer([]byte(table.serialized)))
		proof, err := p.GetConsistencyProof()
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &proof, table.want; !hashesEqual(got.Path, want.Path) {
			t.Errorf("got consistency proof\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func validLeaf() types.Leaf {
	return types.Leaf{
		Checksum:  incHash(),
		Signature: incSignature(),
		KeyHash:   incHash(),
	}
}

func validLeafASCII() string {
	return fmt.Sprintf("%s=%x %x %x\n",
		"leaf", newIncBytes(32), newIncBytes(64), newIncBytes(32))
}

func validLeaves() []types.Leaf {
	return []types.Leaf{validLeaf(), types.Leaf{}}
}

func validLeavesASCII() string {
	return validLeafASCII() + fmt.Sprintf("%s=%x %x %x\n",
		"leaf", merkle.Hash{}, types.Signature{}, merkle.Hash{})
}

func invalidLeavesASCII(t *testing.T, key string) string {
	buf := validLeavesASCII()

	switch key {
	case "checksum":
		return buf[:11] + buf[12:]
	case "signature":
		return buf[:80] + buf[82:]
	case "key_hash":
		return buf[:len(buf)-10] + buf[len(buf)-9:]
	default:
		t.Fatalf("must have a valid field to invalidate")
		return ""
	}
}

func validSignedTreeHead() types.SignedTreeHead {
	return types.SignedTreeHead{
		TreeHead: types.TreeHead{
			Timestamp: 1,
			TreeSize:  2,
			RootHash:  incHash(),
		},
		Signature: incSignature(),
	}
}

func validSignedTreeHeadASCII() string {
	return fmt.Sprintf("%s=%d\n%s=%d\n%s=%x\n%s=%x\n",
		"timestamp", 1,
		"tree_size", 2,
		"root_hash", incHash(),
		"signature", incSignature(),
	)
}

func validCosignedTreeHead() types.CosignedTreeHead {
	return types.CosignedTreeHead{
		SignedTreeHead: types.SignedTreeHead{
			TreeHead: types.TreeHead{
				Timestamp: 1,
				TreeSize:  2,
				RootHash:  incHash(),
			},
			Signature: incSignature(),
		},
		Cosignatures: []types.Cosignature{
			types.Cosignature{},
			types.Cosignature{
				KeyHash:   incHash(),
				Signature: incSignature(),
			},
		},
	}
}

func validCosignedTreeHeadASCII() string {
	return fmt.Sprintf("%s=%d\n%s=%d\n%s=%x\n%s=%x\n%s=%x %x\n%s=%x %x\n",
		"timestamp", 1,
		"tree_size", 2,
		"root_hash", incHash(),
		"signature", incSignature(),
		"cosignature", merkle.Hash{}, types.Signature{},
		"cosignature", incHash(), incSignature(),
	)
}

func validInclusionProof() types.InclusionProof {
	return types.InclusionProof{
		LeafIndex: 1,
		TreeSize:  4,
		Path: []merkle.Hash{
			merkle.Hash{},
			incHash(),
		},
	}
}

func validInclusionProofASCII() string {
	return fmt.Sprintf("%s=%d\n%s=%x\n%s=%x\n",
		"leaf_index", 1,
		"inclusion_path", merkle.Hash{},
		"inclusion_path", incHash(),
	)
}

func validConsistencyProof() types.ConsistencyProof {
	return types.ConsistencyProof{
		NewSize: 1,
		OldSize: 4,
		Path: []merkle.Hash{
			merkle.Hash{},
			incHash(),
		},
	}
}

func validConsistencyProofASCII() string {
	return fmt.Sprintf("%s=%x\n%s=%x\n",
		"consistency_path", merkle.Hash{},
		"consistency_path", incHash(),
	)
}

// These equality functions require both inputs to be non-nil.
func leavesEqual(a []types.Leaf, b []types.Leaf) bool {
	if len(a) != len(b) {
		return false
	}
	for i, l := range a {
		if l != b[i] {
			return false
		}
	}
	return true
}

func hashesEqual(a []merkle.Hash, b []merkle.Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for i, l := range a {
		if l != b[i] {
			return false
		}
	}
	return true
}

func cosignaturesEqual(a []types.Cosignature, b []types.Cosignature) bool {
	if len(a) != len(b) {
		return false
	}
	for i, l := range a {
		if l != b[i] {
			return false
		}
	}
	return true
}
