package checkpoint

import (
	"bytes"
	"strings"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func TestNewLogKeyId(t *testing.T) {
	keyId := NewLogKeyId("example.org/log", &crypto.PublicKey{})
	hash := crypto.HashBytes(bytes.Join([][]byte{
		[]byte("example.org/log"),
		[]byte{0xA, 0x1},
		make([]byte, 32)}, nil))
	if !bytes.Equal(keyId[:], hash[:4]) {
		t.Errorf("unexpected key id: got: %x, want: truncation of hash %x",
			keyId, hash)
	}
}

func TestWriteEd25519Signature(t *testing.T) {
	origin := "example.org/log"
	keyId := KeyId{117, 230, 157, 109}      // Base64 "deadb..."
	signature := crypto.Signature{231, 159} // "...eef"
	want := `
— example.org/log deadbeefAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
`[1:]
	buf := bytes.Buffer{}
	if err := WriteEd25519Signature(&buf, origin, keyId, &signature); err != nil {
		t.Fatal(err)
	}

	if got := buf.String(); got != want {
		t.Errorf("failed, got:\n%q\nwant:\n%q\n", got, want)
	}
}

func TestParseEd25519SignatureLine(t *testing.T) {
	for _, table := range []struct {
		in     string
		id     KeyId
		sig    crypto.Signature
		err    error
		errMsg string
	}{
		{
			in:  "— example.org/log deadbeefAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			id:  KeyId{117, 230, 157, 109},
			sig: crypto.Signature{231, 159},
		},
		{
			in:  "— example.org/log2 deadbeefAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			err: ErrUnwantedSignature,
		},
		{
			in:     "— example.org/log deadbeefAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			errMsg: "illegal base64 data",
		},
		{
			in:  "— example.org/log deadbeefAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			err: ErrUnwantedSignature,
		},
		{
			in:  "— example.org/log dead",
			err: ErrUnwantedSignature,
		},
		{
			in:     "—  example.org/log deadbeefAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			errMsg: "invalid signature line",
		},
	} {
		keyId, signature, err := ParseEd25519SignatureLine(table.in, "example.org/log")
		if table.err != nil {
			if err != table.err {
				t.Errorf("expected err %v on input %q, got %v", table.err, table.in, err)
			}
			continue
		}
		if table.errMsg != "" {
			if err == nil || !strings.Contains(err.Error(), table.errMsg) {
				t.Errorf("expected err %q on input %q, got %v", table.errMsg, table.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("failed on input %q: %v", table.in, err)
			continue
		}
		if got, want := keyId, table.id; got != want {
			t.Errorf("bad key id on input %q, got %v, want %v", table.in, got, want)
		}
		if got, want := signature, table.sig; got != want {
			t.Errorf("bad signature on input %q, got %v, want %v", table.in, got, want)
		}
	}
}
