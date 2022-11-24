package ssh

import (
	"bytes"
	"encoding/hex"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func TestSerializeString(t *testing.T) {
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
		if got, want := serializeString([]byte(tbl.in)), tbl.want; !bytes.Equal(got, want) {
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

func TestParsePublicEd25519(t *testing.T) {
	expKey, err := crypto.PublicKeyFromHex("314cb82ac8b5fe90cf18bf190afa4759b80779709f991f736f044d5e13bcbca6")
	if err != nil {
		t.Fatalf("parsing test key failed: %v", err)
	}
	for _, table := range []struct {
		desc       string
		ascii      string
		expSuccess bool
	}{
		{"basic", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym", true},
		{"with newline", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym\n", true},
		{"with comment", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLym comment", true},
		{"truncated b64", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4TvLy comment", false},
		{"truncated bin", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDFMuCrItf6Qzxi/GQr6R1m4B3lwn5kfc28ETV4T comment", false},
	} {
		key, err := ParsePublicEd25519(table.ascii)
		if err != nil {
			if table.expSuccess {
				t.Errorf("%q: parsing failed: %v", table.desc, err)
			}
		} else {
			if !table.expSuccess {
				t.Errorf("%q: unexpected success, should have failed", table.desc)
			} else if key != expKey {
				t.Errorf("%q: parsing gave wrong key: %x", table.desc, key)
			}
		}
	}
}
