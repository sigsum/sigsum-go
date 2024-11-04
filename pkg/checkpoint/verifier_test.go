package checkpoint

import (
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func TestNoteVerifierString(t *testing.T) {
	nv := NoteVerifier{
		Name:      "example.org/key",
		KeyId:     KeyId{1, 2, 3, 4},
		Type:      SigTypeCosignature,
		PublicKey: crypto.PublicKey{0x01, 0x45, 0x2c, 0x83, 0x46, 0x34, 0x44, 0x92, 0xf8},
	}
	want := "example.org/key+01020304+BAFFLINGNESS+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	got := nv.String()
	if got != want {
		t.Errorf("Failed, got %q, want %q", got, want)
	}
}

func TestNoteVerifierFromString(t *testing.T) {
	var nv NoteVerifier

	want := NoteVerifier{
		Name:      "example.org/key",
		KeyId:     KeyId{1, 2, 3, 4},
		Type:      SigTypeCosignature,
		PublicKey: crypto.PublicKey{0x01, 0x45, 0x2c, 0x83, 0x46, 0x34, 0x44, 0x92, 0xf8},
	}
	if err := nv.FromString("example.org/key+01020304+BAFFLINGNESS+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err != nil {
		t.Fatal(err)
	}
	if nv != want {
		t.Errorf("Failed, got %v, want %v", nv, want)
	}
}

func TestNewNoteVerifier(t *testing.T) {
	nv := NewNoteVerifier("example.org/key",
		SigTypeCosignature,
		&crypto.PublicKey{0x01, 0x45, 0x2c, 0x83, 0x46, 0x34, 0x44, 0x92, 0xf8})
	// The below key id is consistent with output from
	// (echo "example.org/key" ;
	//  echo 'BAFFLINGNESS+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' |
	//    basenc -d --base64) | sha256sum
	want := "example.org/key+57bfe580+BAFFLINGNESS+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	got := nv.String()
	if got != want {
		t.Errorf("Failed, got %q, want %q", got, want)
	}
}

func TestGoSumDBVerifier(t *testing.T) {
	var nv NoteVerifier
	if err := nv.FromString("sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"); err != nil {
		t.Fatal(err)
	}
	if got, want := nv.Type, SigTypeEd25519; got != want {
		t.Errorf("unexpected signature type: got %02x, want: %02x", got, want)
	}
	if got, want := nv.KeyId, NewKeyId(nv.Name, nv.Type, &nv.PublicKey); got != want {
		t.Errorf("unexpected key id: got %x, want: %x", got, want)
	}
}
