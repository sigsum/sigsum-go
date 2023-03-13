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
	testCosignTimestamp = 72623859790382856
)

func TestTreeHeadToSignedData(t *testing.T) {
	desc := "valid"
	if got, want := validTreeHead(t).toSignedData(),
		validTreeHeadSignedData(t); !bytes.Equal(got, want) {
		t.Errorf("got tree head signed data\n\t%x\nbut wanted\n\t%x\nin test %q\n", got, want, desc)
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
		sth, err := table.th.Sign(table.signer)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}

		wantSTH := SignedTreeHead{
			TreeHead:  *table.th,
			Signature: *table.wantSig,
		}
		if got, want := sth, wantSTH; sth != wantSTH {
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
		if got, want := sth, *table.want; got != want {
			t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestSignedTreeHeadVerify(t *testing.T) {
	th := validTreeHead(t)
	pub, signer := newKeyPair(t)

	sth, err := th.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}

	if !sth.Verify(&pub) {
		t.Errorf("failed verifying a valid signed tree head")
	}

	sth.Size += 1
	if sth.Verify(&pub) {
		t.Errorf("succeeded verifying an invalid signed tree head")
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
		if got, want := req, *table.want; got != want {
			t.Errorf("got cosignature request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestCosignAndVerify(t *testing.T) {
	th := *validTreeHead(t)
	pub, signer := newKeyPair(t)
	keyHash := crypto.HashBytes(pub[:])
	logKeyHash := *newHashBufferInc(t)

	cosignature, err := th.Cosign(signer, &logKeyHash, testCosignTimestamp)
	if err != nil {
		t.Fatal(err)
	}

	if cosignature.Timestamp != testCosignTimestamp {
		t.Errorf("unexpected cosignature timestamp, wanted %d, got %d",
			testCosignTimestamp, cosignature.Timestamp)
	}
	if cosignature.KeyHash != keyHash {
		t.Errorf("unexpected cosignature keyhash, wanted %x, got %x",
			keyHash, cosignature.KeyHash)
	}
	if !cosignature.Verify(&pub, &logKeyHash, &th) {
		t.Errorf("failed verifying a valid cosignature")
	}

	// Test mutation of signed items.
	for _, f := range [](func() (string, TreeHead, Cosignature, crypto.Hash)){
		func() (string, TreeHead, Cosignature, crypto.Hash) {
			mTh := th
			mTh.Size++
			return "bad size", mTh, cosignature, logKeyHash
		},
		func() (string, TreeHead, Cosignature, crypto.Hash) {
			mCs := cosignature
			mCs.Timestamp++
			return "bad timestamp", th, mCs, logKeyHash
		},
		func() (string, TreeHead, Cosignature, crypto.Hash) {
			mKh := logKeyHash
			mKh[3]++
			return "bad log key hash", th, cosignature, mKh
		},
		func() (string, TreeHead, Cosignature, crypto.Hash) {
			return "", th, cosignature, logKeyHash
		},
	} {
		desc, mTh, mCs, mLogHash := f()
		valid := mCs.Verify(&pub, &mLogHash, &mTh)
		if len(desc) > 0 && valid {
			t.Errorf("%s: succeeded verifying invalid cosignature", desc)
		} else if len(desc) == 0 && !valid {
			t.Errorf("internal test failure, failed to verify unmodified cosignature")
		}
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
		Size:     257,
		RootHash: *newHashBufferInc(t),
	}
}

func validTreeHeadSignedData(t *testing.T) []byte {
	msg := bytes.Join([][]byte{
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01},
		newHashBufferInc(t)[:],
	}, nil)
	checksum := crypto.HashBytes(msg)
	return bytes.Join([][]byte{
		[]byte("SSHSIG"),
		[]byte{0, 0, 0, 30}, []byte("signed-tree-head:v0@sigsum.org"),
		[]byte{0, 0, 0, 0},
		[]byte{0, 0, 0, 6}, []byte("sha256"),
		[]byte{0, 0, 0, 32}, checksum[:],
	}, nil)
}

func validSignedTreeHead(t *testing.T) *SignedTreeHead {
	t.Helper()
	return &SignedTreeHead{
		TreeHead: TreeHead{
			Size:     2,
			RootHash: *newHashBufferInc(t),
		},
		Signature: *newSigBufferInc(t),
	}
}

func validSignedTreeHeadASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%d\n%s=%x\n%s=%x\n",
		"size", 2,
		"root_hash", newHashBufferInc(t)[:],
		"signature", newSigBufferInc(t)[:],
	)
}

func validCosignature(t *testing.T) *Cosignature {
	t.Helper()
	return &Cosignature{
		Signature: *newSigBufferInc(t),
		Timestamp: 1,
		KeyHash:   *newHashBufferInc(t),
	}
}

func validCosignatureASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%x %d %x\n",
		"cosignature", newHashBufferInc(t)[:], 1, newSigBufferInc(t)[:])
}

func validCosignedTreeHead(t *testing.T) *CosignedTreeHead {
	t.Helper()
	return &CosignedTreeHead{
		SignedTreeHead: SignedTreeHead{
			TreeHead: TreeHead{
				Size:     2,
				RootHash: *newHashBufferInc(t),
			},
			Signature: *newSigBufferInc(t),
		},
		Cosignatures: []Cosignature{
			Cosignature{},
			Cosignature{
				KeyHash:   *newHashBufferInc(t),
				Timestamp: 1,
				Signature: *newSigBufferInc(t),
			},
		},
	}
}

func validCosignedTreeHeadASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%d\n%s=%x\n%s=%x\n%s=%x %d %x\n%s=%x %d %x\n",
		"size", 2,
		"root_hash", newHashBufferInc(t)[:],
		"signature", newSigBufferInc(t)[:],
		"cosignature", crypto.Hash{}, 0, crypto.Signature{},
		"cosignature", newHashBufferInc(t)[:], 1, newSigBufferInc(t)[:],
	)
}
