package ssh

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSSHString(t *testing.T) {
	for _, tbl := range []struct {
		desc string
		in   string
		want []byte
	}{
		{"empty", "", []byte{0, 0, 0, 0}},
		{"valid", "ö foo is a bar",
			bytes.Join([][]byte{{0, 0, 0, 15, 0xc3, 0xb6},
				[]byte(" foo is a bar")}, nil)},
	} {
		if got, want := String(tbl.in), tbl.want; !bytes.Equal(got, want) {
			t.Errorf("%q: got %x but wanted %x", tbl.desc, got, want)
		}
	}
}

func TestSignedData(t *testing.T) {
	msg := []byte("foo\n")
	namespace := "test"
	got := SignedData(namespace, msg)
	want, _ := hex.DecodeString("5353485349470000000474657374000000000000000673686132353600000020" +
		// echo foo | sha256sum
		"b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")
	if !bytes.Equal(got, want) {
		t.Errorf("got %x but wanted %x", got, want)
	}
}
