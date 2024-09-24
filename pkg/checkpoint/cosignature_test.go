package checkpoint

import (
	"bytes"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

var testCosignature = CosignatureLine{
	KeyName: "example.org/witness-key",
	KeyId:   [4]byte{117, 230, 157, 109}, // Base64 "deadb..."
	Cosignature: types.Cosignature{
		Timestamp: 0xe79ff9d79a75ca1d,             // "...eef+deadcod..."
		Signature: crypto.Signature{253, 202, 29}, // ".../cod"
	},
}

var testCosignatureSingleASCII = `
— example.org/witness-key deadbeef+deadcod/codAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
`[1:]

var testCosignatureMultipleASCII = `
— example.org/log DEADBEEFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
— example.org/witness-key deadbeef+deadcod/codAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
`[1:]

func TestCosignatureLineToASCII(t *testing.T) {
	buf := bytes.Buffer{}
	if err := testCosignature.ToASCII(&buf); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), testCosignatureSingleASCII; got != want {
		t.Errorf("got checkpoint: %q, want: %q", got, want)
	}
}

func TestCosignatureLinesFromASCII(t *testing.T) {
	for i, input := range []string{
		testCosignatureSingleASCII,
		testCosignatureMultipleASCII,
	} {
		cosignatures, err := CosignatureLinesFromASCII(bytes.NewBufferString(input))
		if err != nil {
			t.Errorf("failed input %d: %v", i, err)
		} else if len(cosignatures) != 1 {
			t.Errorf("unexpected response count input %d: got: %v", i, cosignatures)
		} else if got, want := cosignatures[0], testCosignature; got != want {
			t.Errorf("unexpected response for input %d: got:\n%v\nwant:\n%v", i, got, want)
		}
	}
}
