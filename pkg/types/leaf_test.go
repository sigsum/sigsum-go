package types

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"sigsum.org/sigsum-go/internal/mocks/signer"
	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
)

func TestLeafSignedData(t *testing.T) {
	desc := "valid: checksum 0x00,0x01,..."
	if got, want := leafSignedData(validChecksum(t)), validLeafSignedDataBytes(t); !bytes.Equal(got, want) {
		t.Errorf("got statement\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestSignLeaf(t *testing.T) {
	for _, table := range []struct {
		desc     string
		checksum *crypto.Hash
		signer   crypto.Signer
		wantSig  *crypto.Signature
		wantErr  bool
	}{
		{
			desc:     "invalid: signer error",
			checksum: validChecksum(t),
			signer:   &signer.Signer{*newPubBufferInc(t), *newSigBufferInc(t), fmt.Errorf("signing error")},
			wantErr:  true,
		},
		{
			desc:     "valid",
			checksum: validChecksum(t),
			signer:   &signer.Signer{*newPubBufferInc(t), *newSigBufferInc(t), nil},
			wantSig:  newSigBufferInc(t),
		},
	} {
		sig, err := SignLeafChecksum(table.signer, table.checksum)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}

		if got, want := sig[:], table.wantSig[:]; !bytes.Equal(got, want) {
			t.Errorf("got signature\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.desc)
		}
	}
}

func TestLeafVerify(t *testing.T) {
	checksum := validChecksum(t)
	pub, signer := newKeyPair(t)

	sig, err := SignLeafChecksum(signer, checksum)
	if err != nil {
		t.Fatal(err)
	}

	leaf := Leaf{
		Checksum:  *checksum,
		Signature: sig,
		KeyHash:   crypto.HashBytes(pub[:]),
	}
	if !leaf.Verify(&pub) {
		t.Errorf("failed verifying a valid statement")
	}

	leaf.Checksum[0] += 1
	if leaf.Verify(&pub) {
		t.Errorf("succeeded verifying an invalid statement")
	}
}

func TestLeafToBinary(t *testing.T) {
	desc := "valid: shard hint 72623859790382856, buffers 0x00,0x01,..."
	if got, want := validLeaf(t).ToBinary(), validLeafBytes(t); !bytes.Equal(got, want) {
		t.Errorf("got leaf\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestLeafFromBinary(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized []byte
		wantErr    bool
		want       *Leaf
	}{
		{
			desc:       "invalid: not enough bytes",
			serialized: make([]byte, 135),
			wantErr:    true,
		},
		{
			desc:       "invalid: too many bytes",
			serialized: make([]byte, 137),
			wantErr:    true,
		},
		{
			desc:       "valid: shard hint 72623859790382856, buffers 0x00,0x01,...",
			serialized: validLeafBytes(t),
			want:       validLeaf(t),
		},
	} {
		var leaf Leaf
		err := leaf.FromBinary(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &leaf, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got leaf\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestLeafToASCII(t *testing.T) {
	desc := "valid:, buffers 0x00,0x01,..."
	buf := bytes.NewBuffer(nil)
	if err := validLeaf(t).ToASCII(buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validLeafASCII(t); got != want {
		t.Errorf("got leaf\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
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
			desc:       "invalid: not a tree leaf (wrong key)",
			serialized: bytes.NewBuffer([]byte("tree_size=0\n")),
			wantErr:    true,
		},
		{
			desc:       "invalid: not a tree leaf (too many values)",
			serialized: bytes.NewBuffer([]byte(invalidLeafASCII(t))),
			wantErr:    true,
		},
		{
			desc:       "valid: buffers 0x00,0x01,...",
			serialized: bytes.NewBuffer([]byte(validLeafASCII(t))),
			want:       validLeaf(t),
		},
	} {
		var leaf Leaf
		p := ascii.NewParser(table.serialized)
		err := leaf.fromASCII(&p)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &leaf, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got leaf\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestLeavesFromASCII(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized io.Reader
		wantErr    bool
		want       *[]Leaf
	}{
		{
			desc:       "invalid: not a list of tree leaves (too few key-value pairs)",
			serialized: bytes.NewBuffer([]byte("checksum=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")),
			wantErr:    true,
		},
		{
			desc:       "invalid: not a list of tree leaves (too many key-value pairs)",
			serialized: bytes.NewBuffer(append([]byte(validLeafASCII(t)), []byte("key=value\n")...)),
			wantErr:    true,
		},
		{
			desc:       "invalid: not a list of tree leaves (too few checksums))",
			serialized: bytes.NewBuffer([]byte(invalidLeavesASCII(t, "checksum"))),
			wantErr:    true,
		},
		{
			desc:       "invalid: not a list of tree leaves (too few signatures))",
			serialized: bytes.NewBuffer([]byte(invalidLeavesASCII(t, "signature"))),
			wantErr:    true,
		},
		{
			desc:       "invalid: not a list of tree leaves (too few key hashes))",
			serialized: bytes.NewBuffer([]byte(invalidLeavesASCII(t, "key_hash"))),
			wantErr:    true,
		},
		{
			desc:       "valid leaves",
			serialized: bytes.NewBuffer([]byte(validLeavesASCII(t))),
			want:       validLeaves(t),
		},
	} {
		leaves, err := LeavesFromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &leaves, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got leaves\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func validChecksum(t *testing.T) *crypto.Hash {
	hash := crypto.HashBytes(newHashBufferInc(t)[:])
	return &hash
}

func validLeafSignedDataBytes(t *testing.T) []byte {
	hash := crypto.HashBytes(newHashBufferInc(t)[:])
	return bytes.Join([][]byte{
		[]byte("SSHSIG"),
		[]byte{0, 0, 0, 23}, []byte("tree_leaf:v0@sigsum.org"),
		[]byte{0, 0, 0, 0},
		[]byte{0, 0, 0, 6}, []byte("sha256"),
		[]byte{0, 0, 0, 32}, hash[:],
	}, nil)
}

func validLeaf(t *testing.T) *Leaf {
	return &Leaf{
		Checksum:  crypto.HashBytes(newHashBufferInc(t)[:]),
		Signature: *newSigBufferInc(t),
		KeyHash:   *newHashBufferInc(t),
	}
}

func validLeafBytes(t *testing.T) []byte {
	checksum := crypto.HashBytes(newHashBufferInc(t)[:])
	return bytes.Join([][]byte{
		checksum[:],
		newSigBufferInc(t)[:],
		newHashBufferInc(t)[:],
	}, nil)
}

func validLeafASCII(t *testing.T) string {
	checksum := crypto.HashBytes(newHashBufferInc(t)[:])
	return fmt.Sprintf("%s=%x %x %x\n",
		"leaf", checksum, newSigBufferInc(t)[:], newHashBufferInc(t)[:])
}

func invalidLeafASCII(t *testing.T) string {
	s := validLeafASCII(t)
	// Add an extra value
	return fmt.Sprintf("%s 0\n", strings.TrimSpace(s))
}

func validLeaves(t *testing.T) *[]Leaf {
	t.Helper()
	return &[]Leaf{*validLeaf(t), Leaf{}}
}

func validLeavesASCII(t *testing.T) string {
	t.Helper()
	return validLeafASCII(t) + fmt.Sprintf("%s=%x %x %x\n",
		"leaf", crypto.Hash{}, crypto.Signature{}, crypto.Hash{})
}

func invalidLeavesASCII(t *testing.T, key string) string {
	buf := validLeavesASCII(t)

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

func newKeyPair(t *testing.T) (crypto.PublicKey, crypto.Signer) {
	pub, signer, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return pub, signer
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
