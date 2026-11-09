package checkpoint

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

var testOrigin = "example.org/log"

var testTreeHead = types.TreeHead{
	Size:     10,
	RootHash: crypto.Hash{28, 14, 71}, // Base64 "HA5H"
}

var testSignedTreeHead = types.SignedTreeHead{
	TreeHead:  testTreeHead,
	Signature: crypto.Ed25519Signature{65, 5}, // Base64 "...EEF"
}
var testCheckpoint = Checkpoint{
	Origin:         testOrigin,
	SignedTreeHead: testSignedTreeHead,
	KeyId:          [4]byte{12, 64, 3, 4}, // Base64 "DEADB..."
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
	signer := crypto.NewEd25519Signer(&crypto.Ed25519PrivateKey{17})
	pub := signer.Public()
	origin := fmt.Sprintf("%s%x", types.CheckpointNamePrefix, pub.Hash())
	cp := Checkpoint{
		Origin: origin,
		KeyId:  NewLogKeyId(origin, &pub),
	}
	var err error
	cp.SignedTreeHead, err = testTreeHead.Sign(signer)

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
	signer := crypto.NewEd25519Signer(&crypto.Ed25519PrivateKey{17})
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
		cp.Signature[4] ^= 1
	})
}

func TestCheckpointVerifyIgnoreExtraSignature(t *testing.T) {
	// Key used to sign above checkpoint.
	signer := crypto.NewEd25519Signer(&crypto.Ed25519PrivateKey{17})
	pub := signer.Public()

	paragraphs := strings.Split(validCheckpointASCII, "\n\n")
	if len(paragraphs) != 2 {
		t.Fatal("internal test error")
	}
	body := paragraphs[0]
	sigs := strings.Split(paragraphs[1], "\n")
	if len(sigs) != 2 || sigs[1] != "" {
		t.Fatalf("internal test error, sigs: %v", sigs)
	}
	validSig := sigs[0]
	// Ed25519 size
	exampleSig := "— example.org/log2 DEADBEEFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	alienSig := "— example.org/log DEAD"
	badSig := "— example.org/log DEADB"

	for _, table := range []struct {
		sigs []string
		fail bool
	}{
		{sigs: []string{validSig}},
		{sigs: []string{validSig, alienSig}},
		{sigs: []string{validSig, alienSig}},
		{sigs: []string{exampleSig, validSig, alienSig}},
		{sigs: []string{exampleSig, validSig, alienSig, badSig}, fail: true},
	} {
		ascii := fmt.Sprintf("%s\n\n%s\n", body, strings.Join(table.sigs, "\n"))
		var cp Checkpoint
		err := cp.FromASCII(bytes.NewBufferString(ascii))
		if table.fail {
			if err == nil {
				t.Errorf("invalid checkpoint was accepted")
			}
			continue
		}
		if err != nil {
			t.Error(err)
			continue
		}

		if err := cp.Verify(&pub); err != nil {
			t.Error(err)
		}
	}
}

func TestCheckpointCosignVerify(t *testing.T) {
	signer := crypto.NewEd25519Signer(&crypto.Ed25519PrivateKey{17})
	pub := signer.Public()
	timestamp := uint64(1234)
	cosignature, err := testCheckpoint.Cosign(signer, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cosignature.Timestamp, timestamp; got != want {
		t.Errorf("unexpected cosignature timestamp: got %d, want %d", got, want)
	}
	if !testCheckpoint.VerifyCosignature(&pub, &cosignature) {
		t.Errorf("verifying cosignature failed")
	}

	keyName := "example.org/witness"
	cls := CosignatureLine{
		KeyName:     keyName,
		KeyId:       NewWitnessKeyId(keyName, &pub),
		Cosignature: cosignature,
	}
	var buf bytes.Buffer
	if err := cls.ToASCII(&buf); err != nil {
		t.Fatal(err)
	}
	t.Log(buf.String())
}

func TestCheckpointVerifyCosignatureByKey(t *testing.T) {
	// Second line was produced by the test above. First line has
	// a different keyid, third line has a different keyname,
	// fourth line a different signature size.
	input := `
— example.org/witness yX8uUAAAAAAAAATSftMzceM8zssdZ9jin9SjwIxzx9iADMf63VqirX2hafol9RsqNqbofIz0LVRqHXI2kpEBSki5RTXFtxz1vo9+Cg==
— example.org/witness ys8uUAAAAAAAAATSftMzceM8zssdZ9jin9SjwIxzx9iADMf63VqirX2hafol9RsqNqbofIz0LVRqHXI2kpEBSki5RTXFtxz1vo9+Cg==
— example.org/witness-2 ys8uUAAAAAAAAATSftMzceM8zssdZ9jin9SjwIxzx9iADMf63VqirX2hafol9RsqNqbofIz0LVRqHXI2kpEBSki5RTXFtxz1vo9+Cg==
— example.org/witness ys8uUAAAAAAAAATSftMzceM8zssdZ9jin9SjwIxzx9iADMf63VqirX2hafol9RsqNqbofIz0LVRqHXI2kpEBSki5RTXFtxz1vo9+CgXX
`[1:]
	cosignatures, err := CosignatureLinesFromASCII(bytes.NewBufferString(input))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(cosignatures), 3; got != want {
		t.Errorf("unexpected number of cosignatures: got %d, want: %d", got, want)
	}
	signer := crypto.NewEd25519Signer(&crypto.Ed25519PrivateKey{17})
	pub := signer.Public()
	cosignature, err := testCheckpoint.VerifyCosignatureByKey(cosignatures, &pub)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cosignature.Timestamp, uint64(1234); got != want {
		t.Errorf("unexpected cosignature timestamp: got %d, want %d", got, want)
	}

	// Try invalidating the cosignature.
	cosignatures[1].Timestamp++
	_, err = testCheckpoint.VerifyCosignatureByKey(cosignatures, &pub)
	if err == nil {
		t.Errorf("bad cosignature not rejected")
	}
}

func TestGoSumDBCheckpoint(t *testing.T) {
	const (
		// Retrieved from https://sum.golang.org/latest, 2024-09-23
		dbCheckpoint = `go.sum database tree
30055305
mXfgRcJ0bG0j3CPdKwgGWtUzBUbX67saZGRmFuJGGsM=

— sum.golang.org Az3grpgEild5qw7+5dtV13Kf1C2Xurm8q4fhdxvcsDHnqNTaxL2AFjBY+2TyGKevucFcAAlWFJJYle3EJlDCrQ+y3A8=
`

		// Checksum db key, from
		// https://github.com/golang/go/blob/master/src/cmd/go/internal/modfetch/key.go.
		noteKey = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"
	)
	paragraphSep := strings.Index(dbCheckpoint, "\n\n")
	if paragraphSep < 0 {
		t.Fatal("failed to split checkpoint")
	}
	dbCheckpointBody := dbCheckpoint[:paragraphSep+1]

	var nv NoteVerifier
	if err := nv.FromString(noteKey); err != nil {
		t.Fatal(err)
	}

	// Process checkpoint
	var cp Checkpoint
	if err := cp.fromASCIIWithKeyName(bytes.NewBufferString(dbCheckpoint), nv.Name); err != nil {
		t.Fatal(err)
	}
	if got, want := cp.Origin, "go.sum database tree"; got != want {
		t.Errorf("unexpected origin: got %s, want: %s", got, want)
	}
	if got, want := cp.KeyId, nv.KeyId; got != want {
		t.Errorf("unexpected keyId: got %x, want: %x", got, want)
	}

	checkpointASCII := cp.TreeHead.FormatCheckpoint(cp.Origin)
	if got, want := checkpointASCII, dbCheckpointBody; got != want {
		t.Errorf("formatting roundtrip failed: got:\n%q\nwant:\n%q", got, want)
	}
	if !nv.PublicKey.Verify([]byte(checkpointASCII), &cp.Signature) {
		t.Errorf("verifying checkpoint signature failed")
	}
}

func TestAndroidCheckpoint(t *testing.T) {
	const (
		vkey = "android.transparency.goog/google1p/apk/2026/1+fc654374+ATr9NQE0gvOtVfj5cCStUzdlflEp3oZoNHD8pImzPj5O"
		// Retrieved from https://gstatic.com/android/binary_transparency/google1p/apk/2026/02/checkpoint, 2026-11-05
		checkpointASCII = `android.transparency.goog/google1p/apk/2026/1
951152
WzAET+yQ/1/BxProuQWjLgqq3EBTZx0MvlxwaXq4Bpc=

— android.transparency.goog/google1p/apk/2026/1 /GVDdDEx+hXBoY28IBbnseV/i7/WDH1qVijYsdysZJFSbvsDu4a/CUPLW6pLoVYH+GuUfqwPwhyG6lwv0pFTTSKA+gI=
— staging.witness.transparency.goog/ring-any-bells LhqNyQAAAABq7EUDgqF85bQU1ICPVtjAC1bjIdyDkPQAUvb/ROUCIy7hTXQdi5pmoNIz6zFvdn7WAHwqev7xAeCdX3YqQIipldGvAg==
— staging.witness.transparency.goog/ring-any-bells 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
— witness.navigli.sunlight.geomys.org o+AP4gAAAABq7EUDtZp7GRjPBDntfGE/aChfglYwHXBpEdgnm70Vkm/L31/pcAp0r/VTJz82w8H5Afj+Mzm381SWHy7WFIr7rBzOAQ==
— witness.navigli.sunlight.geomys.org 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
— witness.stagemole.eu Z/euoAAAAABq7EUDolcLcegUNsJBHvkYM9p3dFYeu0X+aep3Wk671q0hiXvoNe7VePh91mlUh1gmPP3y+uzSHnEOArK/9S3dJSxpCA==
`
	)

	wantOrigin := "android.transparency.goog/google1p/apk/2026/1"
	var nv NoteVerifier
	if err := nv.FromString(vkey); err != nil {
		t.Fatal(err)
	}
	if nv.Name != wantOrigin {
		t.Errorf("unexpected vkey name: %q, want: %q", nv.Name, wantOrigin)
	}
	var cp Checkpoint
	if err := cp.FromASCII(bytes.NewBufferString(checkpointASCII)); err != nil {
		t.Fatal(err)
	}
	if cp.Origin != wantOrigin {
		t.Errorf("unexpected origin line: %q, want: %q", nv.Name, wantOrigin)
	}
	if err := cp.Verify(&nv.PublicKey); err != nil {
		t.Error(err)
	}
	cp.Size++
	if err := cp.Verify(&nv.PublicKey); err == nil {
		t.Errorf("signature on modified checkpoint was accepted")
	}
}
