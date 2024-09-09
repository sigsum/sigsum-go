package checkpoint

import (
	"bytes"
	"testing"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
)

const validCheckpointASCII = `sigsum.org/v1/tree/e796172b92befd62d9dc67e41c2f5bc9d3100a3023b20b1ca40288dd1c679e69
10
HA5HAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

— sigsum.org/v1/tree/e796172b92befd62d9dc67e41c2f5bc9d3100a3023b20b1ca40288dd1c679e69 pOZUn0n8F8olcerUF1FFdv235A/5as/coWrpLrtE7ovMeP5whgwouYExowG/lTznxu6OUGjjt5yJQ6bXtTcf718MqAQ=
`

func TestLogToCheckpoint(t *testing.T) {
	signer := testLogSigner()
	pub := signer.Public()
	log := NewLog(&pub)
	sth, err := testTreeHead.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}
	cp := log.ToCheckpoint(&sth)

	buf := bytes.Buffer{}
	cp.ToASCII(&buf)
	if got, want := buf.String(), validCheckpointASCII; got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestLogFromCheckpoint(t *testing.T) {
	pub, err := crypto.PublicKeyFromHex("66e0b858e462a609e66fe71370c816d8846ff103d5499a22a7fec37fdbc424a7")
	if err != nil {
		t.Fatal(err)
	}
	log := NewLog(&pub)
	var cp Checkpoint
	if err := cp.FromASCII(ascii.NewParagraphReader(bytes.NewBufferString(validCheckpointASCII))); err != nil {
		t.Fatal(err)
	}
	sth, err := log.FromCheckpoint(&cp)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sth.TreeHead, testTreeHead; got != want {
		t.Errorf("unexpected treehead, got: %v, want: %v", got, want)
	}
	if !sth.Verify(&pub) {
		t.Errorf("signature not valid: %x", sth)
	}
}

// Corresponds to public key 66e0b858e462a609e66fe71370c816d8846ff103d5499a22a7fec37fdbc424a7.
func testLogSigner() *crypto.Ed25519Signer {
	return crypto.NewEd25519Signer(&crypto.PrivateKey{17})
}
