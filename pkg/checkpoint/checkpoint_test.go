package checkpoint

import (
	"bytes"
	"fmt"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

var testOrigin = "example.org/log"

var testTreeHead = types.SignedTreeHead{
	TreeHead: types.TreeHead{
		Size:     10,
		RootHash: crypto.Hash{28, 14, 71}, // Base64 "HA5H"
	},
	Signature: crypto.Signature{65, 5}, // Base64 "...EEF"
}
var testCheckpoint = Checkpoint{
	Origin:   testOrigin,
	TreeHead: testTreeHead,
	KeyId:    [4]byte{12, 64, 3, 4}, // Base64 "DEADB..."
}

var testCheckpointASCII = `example.org/log
10
HA5HAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

— example.org/log DEADBEEFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
`

const validCheckpointASCII = `sigsum.org/v1/tree/e796172b92befd62d9dc67e41c2f5bc9d3100a3023b20b1ca40288dd1c679e69
10
HA5HAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

— sigsum.org/v1/tree/e796172b92befd62d9dc67e41c2f5bc9d3100a3023b20b1ca40288dd1c679e69 gJ2ho0n8F8olcerUF1FFdv235A/5as/coWrpLrtE7ovMeP5whgwouYExowG/lTznxu6OUGjjt5yJQ6bXtTcf718MqAQ=
`

func TestCheckpointToASCII(t *testing.T) {
	buf := bytes.Buffer{}
	if err := testCheckpoint.ToASCII(&buf); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), testCheckpointASCII; got != want {
		t.Errorf("got checkpoint:\n%swant:\n%s", got, want)
	}
}

func TestCheckpointFromASCII(t *testing.T) {
	var cp Checkpoint
	if err := cp.FromASCII(bytes.NewBufferString(testCheckpointASCII)); err != nil {
		t.Fatal(err)
	}
	if cp != testCheckpoint {
		t.Errorf("FromASCII failed, got:\n%v,\nwanted:\n%v", cp, testCheckpoint)
	}
}

func TestCheckpointSigned(t *testing.T) {
	signer := crypto.NewEd25519Signer(&crypto.PrivateKey{17})
	pub := signer.Public()
	origin := fmt.Sprintf("%s%x", types.CheckpointNamePrefix, crypto.HashBytes(pub[:]))
	cp := Checkpoint{
		Origin: origin,
		KeyId:  NewLogKeyId(origin, &pub),
	}
	var err error
	cp.TreeHead, err = testTreeHead.TreeHead.Sign(signer)

	if err != nil {
		t.Fatal(err)
	}
	buf := bytes.Buffer{}
	if err := cp.ToASCII(&buf); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), validCheckpointASCII; got != want {
		t.Errorf("got checkpoint:\n%swant:\n%s", got, want)
	}
}

func TestCheckpointVerify(t *testing.T) {
	// Key used to sign above checkpoint.
	signer := crypto.NewEd25519Signer(&crypto.PrivateKey{17})
	pub := signer.Public()

	var validCheckpoint Checkpoint
	if err := validCheckpoint.FromASCII(bytes.NewBufferString(validCheckpointASCII)); err != nil {
		t.Fatal(err)
	}
	if err := validCheckpoint.Verify(&pub); err != nil {
		t.Fatal(err)
	}

	testInvalid := func(desc string, f func(cp *Checkpoint)) {
		cp := validCheckpoint
		f(&cp)
		if err := cp.Verify(&pub); err == nil {
			t.Errorf("%s: bad checkpoint not rejected", desc)
		}
	}

	testInvalid("bad origin", func(cp *Checkpoint) {
		cp.Origin += "x"
	})
	testInvalid("bad key id", func(cp *Checkpoint) {
		cp.KeyId[2] ^= 1
	})
	testInvalid("bad size", func(cp *Checkpoint) {
		cp.TreeHead.Size++
	})
	testInvalid("bad hash", func(cp *Checkpoint) {
		cp.TreeHead.RootHash[3] ^= 1
	})
	testInvalid("bad signature", func(cp *Checkpoint) {
		cp.TreeHead.Signature[4] ^= 1
	})
}