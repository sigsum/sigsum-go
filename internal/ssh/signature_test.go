package ssh

import (
	"bytes"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
)

// Test data produced using
// ssh-keygen -q -N '' -t ed25519 -f test.key
// echo foo > test.msg
// ssh-keygen -O hashalg=sha256 -q -Y sign -f test.key -n sigsum-test test.msg

func TestParseSignatureFile(t *testing.T) {
	key, err := ParsePublicEd25519("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKAgoUhTZuCzEIgNPAaTaQJxbviits8VV4vQrspAFsF+")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := ParseSignatureFile([]byte(`-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgoCChSFNm4LMQiA08BpNpAnFu+K
K2zxVXi9CuykAWwX4AAAALc2lnc3VtLXRlc3QAAAAAAAAABnNoYTI1NgAAAFMAAAALc3No
LWVkMjU1MTkAAABAspbwrGlpmCJGJP1G8YQu/o+T+qRMY7IdRmh2aGoAU2GHVp7a1UwULa
uL5akqvO56HwbtyWgAzlCX2E+YQT7wAA==
-----END SSH SIGNATURE-----
`),
		&key, "sigsum-test")
	if err != nil {
		t.Fatal(err)
	}
	expected, err := crypto.SignatureFromHex("b296f0ac696998224624fd46f1842efe8f93faa44c63b21d466876686a00536187569edad54c142dab8be5a92abcee7a1f06edc96800ce5097d84f98413ef000")
	if err != nil {
		t.Fatal(err)
	}
	if signature != expected {
		t.Errorf("ParseSignatureFile failed, got %x, wanted %x", signature, expected)
	}
	if !crypto.Verify(&key, SignedData("sigsum-test", []byte("foo\n")), &signature) {
		t.Errorf("signature not valid")
	}
}

func TestWriteSignatureFile(t *testing.T) {
	key, err := ParsePublicEd25519("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKAgoUhTZuCzEIgNPAaTaQJxbviits8VV4vQrspAFsF+")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := crypto.SignatureFromHex("b296f0ac696998224624fd46f1842efe8f93faa44c63b21d466876686a00536187569edad54c142dab8be5a92abcee7a1f06edc96800ce5097d84f98413ef000")
	if err != nil {
		t.Fatal(err)
	}
	buf := bytes.Buffer{}
	if err := WriteSignatureFile(&buf, &key, "sigsum-test", &signature); err != nil {
		t.Fatal(err)
	}
	// Same base64, but go's PEM module uses longer lines than openssh.
	if ascii := buf.String(); ascii != `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgoCChSFNm4LMQiA08BpNp
AnFu+KK2zxVXi9CuykAWwX4AAAALc2lnc3VtLXRlc3QAAAAAAAAABnNoYTI1NgAA
AFMAAAALc3NoLWVkMjU1MTkAAABAspbwrGlpmCJGJP1G8YQu/o+T+qRMY7IdRmh2
aGoAU2GHVp7a1UwULauL5akqvO56HwbtyWgAzlCX2E+YQT7wAA==
-----END SSH SIGNATURE-----
` {
		t.Errorf("WriteSignatureFile failed, got:\n%vend", ascii)
	}
}
