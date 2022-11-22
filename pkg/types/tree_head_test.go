package types

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"

	"sigsum.org/sigsum-go/internal/mocks/signer"
	"sigsum.org/sigsum-go/pkg/crypto"
)

const (
	treeTimestamp = 72623859790382856
)

func TestTreeHeadToSignedData(t *testing.T) {
	desc := "valid"
	kh := crypto.Hash{}
	if got, want := validTreeHead(t).toSignedData(&kh, treeTimestamp),
		validTreeHeadSignedData(t, &kh); !bytes.Equal(got, want) {
		t.Errorf("got tree head signed data\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestTreeHeadSign(t *testing.T) {
	for _, table := range []struct {
		desc    string
		th      *TreeHead
		signer  crypto.Signer
		wantSig *crypto.Signature
		wantErr bool
	}{
		{
			desc:    "invalid: signer error",
			th:      validTreeHead(t),
			signer:  &signer.Signer{*newPubBufferInc(t), *newSigBufferInc(t), fmt.Errorf("signing error")},
			wantErr: true,
		},
		{
			desc:    "valid",
			th:      validTreeHead(t),
			signer:  &signer.Signer{*newPubBufferInc(t), *newSigBufferInc(t), nil},
			wantSig: newSigBufferInc(t),
		},
	} {
		logKey := crypto.PublicKey{}
		keyHash := crypto.HashBytes(logKey[:])
		sth, err := table.th.Sign(table.signer, &keyHash, treeTimestamp)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}

		wantSTH := &SignedTreeHead{
			TreeHead:  *table.th,
			Timestamp: treeTimestamp,
			Signature: *table.wantSig,
		}
		if got, want := sth, wantSTH; !reflect.DeepEqual(got, want) {
			t.Errorf("got sth\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.desc)
		}
	}
}

func TestSignedTreeHeadToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.NewBuffer(nil)
	if err := validSignedTreeHead(t).ToASCII(buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validSignedTreeHeadASCII(t); got != want {
		t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestSignedTreeHeadFromASCII(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized io.Reader
		wantErr    bool
		want       *SignedTreeHead
	}{
		{
			desc: "invalid: not a signed tree head (unexpected key-value pair)",
			serialized: bytes.NewBuffer(append(
				[]byte(validSignedTreeHeadASCII(t)),
				[]byte("key=4")...),
			),
			wantErr: true,
		},
		{
			desc:       "valid",
			serialized: bytes.NewBuffer([]byte(validSignedTreeHeadASCII(t))),
			want:       validSignedTreeHead(t),
		},
	} {
		var sth SignedTreeHead
		err := sth.FromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &sth, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestSignedTreeHeadVerify(t *testing.T) {
	th := validTreeHead(t)
	pub, signer := newKeyPair(t)
	kh := crypto.HashBytes(pub[:])

	sth, err := th.Sign(signer, &kh, treeTimestamp)
	if err != nil {
		t.Fatal(err)
	}

	if !sth.VerifyLogSignature(&pub) {
		t.Errorf("failed verifying a valid signed tree head")
	}

	sth.TreeSize += 1
	if sth.VerifyLogSignature(&pub) {
		t.Errorf("succeeded verifying an invalid signed tree head")
	}
}

func TestCosignedTreeHeadToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.NewBuffer(nil)
	if err := validCosignedTreeHead(t).ToASCII(buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := string(buf.Bytes()), validCosignedTreeHeadASCII(t); got != want {
		t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestCosignedTreeHeadFromASCII(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized io.Reader
		wantErr    bool
		want       *CosignedTreeHead
	}{
		{
			desc: "invalid: not a cosigned tree head (unexpected key-value pair)",
			serialized: bytes.NewBuffer(append(
				[]byte(validCosignedTreeHeadASCII(t)),
				[]byte("key=4")...),
			),
			wantErr: true,
		},
		{
			desc: "invalid: not a cosigned tree head (not enough cosignatures)",
			serialized: bytes.NewBuffer(append(
				[]byte(validCosignedTreeHeadASCII(t)),
				[]byte(fmt.Sprintf("key_hash=%x\n", crypto.Hash{}))...,
			)),
			wantErr: true,
		},
		{
			desc:       "valid",
			serialized: bytes.NewBuffer([]byte(validCosignedTreeHeadASCII(t))),
			want:       validCosignedTreeHead(t),
		},
	} {
		var cth CosignedTreeHead
		err := cth.FromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &cth, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func validTreeHead(t *testing.T) *TreeHead {
	return &TreeHead{
		TreeSize: 257,
		RootHash: *newHashBufferInc(t),
	}
}

func validTreeHeadBytes(t *testing.T, keyHash *crypto.Hash) []byte {
	return bytes.Join([][]byte{
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01},
		newHashBufferInc(t)[:],
		keyHash[:],
	}, nil)
}

func validTreeHeadSignedData(t *testing.T, keyHash *crypto.Hash) []byte {
	msg := bytes.Join([][]byte{
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01},
		newHashBufferInc(t)[:],
		keyHash[:],
	}, nil)
	checksum := crypto.HashBytes(msg)
	return bytes.Join([][]byte{
		[]byte("SSHSIG"),
		[]byte{0, 0, 0, 23}, []byte("tree-head:v0@sigsum.org"),
		[]byte{0, 0, 0, 0},
		[]byte{0, 0, 0, 6}, []byte("sha256"),
		[]byte{0, 0, 0, 32}, checksum[:],
	}, nil)
}

func validSignedTreeHead(t *testing.T) *SignedTreeHead {
	t.Helper()
	return &SignedTreeHead{
		TreeHead: TreeHead{
			TreeSize: 2,
			RootHash: *newHashBufferInc(t),
		},
		Timestamp: 1,
		Signature: *newSigBufferInc(t),
	}
}

func validSignedTreeHeadASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%d\n%s=%d\n%s=%x\n%s=%x\n",
		"timestamp", 1,
		"tree_size", 2,
		"root_hash", newHashBufferInc(t)[:],
		"signature", newSigBufferInc(t)[:],
	)
}

func validCosignedTreeHead(t *testing.T) *CosignedTreeHead {
	t.Helper()
	return &CosignedTreeHead{
		SignedTreeHead: SignedTreeHead{
			TreeHead: TreeHead{
				TreeSize: 2,
				RootHash: *newHashBufferInc(t),
			},
			Timestamp: 1,
			Signature: *newSigBufferInc(t),
		},
		Cosignatures: []Cosignature{
			Cosignature{},
			Cosignature{
				KeyHash:   *newHashBufferInc(t),
				Signature: *newSigBufferInc(t),
			},
		},
	}
}

func validCosignedTreeHeadASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%d\n%s=%d\n%s=%x\n%s=%x\n%s=%x %x\n%s=%x %x\n",
		"timestamp", 1,
		"tree_size", 2,
		"root_hash", newHashBufferInc(t)[:],
		"signature", newSigBufferInc(t)[:],
		"cosignature", crypto.Hash{}, crypto.Signature{},
		"cosignature", newHashBufferInc(t)[:], newSigBufferInc(t)[:],
	)
}
