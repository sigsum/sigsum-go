package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func incBytes(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < len(b); i++ {
		b[i] = byte(i)
	}
	return b
}

func TestValidHashFromHex(t *testing.T) {
	b := incBytes(32)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		s, strings.ToUpper(s),
	} {
		hash, err := HashFromHex(in)
		if err != nil {
			t.Errorf("error on input %q: %v", in, err)
		}
		if !bytes.Equal(b, hash[:]) {
			t.Errorf("fail on input %q, wanted %x, got %x", in, b, hash)
		}
	}
}

func TestInvalidHashFromHex(t *testing.T) {
	b := incBytes(33)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		"", "0x11", "123z", s[:63], s[:65], s[:66],
	} {
		hash, err := HashFromHex(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %x",
				in, hash)
		}
	}
}

func TestValidPublicKeyFromHex(t *testing.T) {
	b := incBytes(32)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		s, strings.ToUpper(s),
	} {
		hash, err := PublicKeyFromHex(in)
		if err != nil {
			t.Errorf("error on input %q: %v", in, err)
		}
		if !bytes.Equal(b, hash[:]) {
			t.Errorf("fail on input %q, wanted %x, got %x", in, b, hash)
		}
	}
}

func TestInvalidPublicKeyFromHex(t *testing.T) {
	b := incBytes(33)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		"", "0x11", "123z", s[:63], s[:65], s[:66],
	} {
		hash, err := PublicKeyFromHex(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %x",
				in, hash)
		}
	}
}

func TestValidSignatureFromHex(t *testing.T) {
	b := incBytes(64)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		s, strings.ToUpper(s),
	} {
		hash, err := SignatureFromHex(in)
		if err != nil {
			t.Errorf("error on input %q: %v", in, err)
		}
		if !bytes.Equal(b, hash[:]) {
			t.Errorf("fail on input %q, wanted %x, got %x", in, b, hash)
		}
	}
}

func TestInvalidSignatureFromHex(t *testing.T) {
	b := incBytes(65)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		"", "0x11", "123z", s[:127], s[:129], s[:130],
	} {
		hash, err := SignatureFromHex(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %x",
				in, hash)
		}
	}
}

func mustHashFromHex(t *testing.T, s string) Hash {
	hash, err := HashFromHex(s)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

// Basic sanity check, not intended as thorough SHA256 regression test.
func TestHash(t *testing.T) {
	for _, table := range []struct {
		in  string
		out string
	}{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	} {
		if got, want := HashBytes([]byte(table.in)), mustHashFromHex(t, table.out); got != want {
			t.Errorf("incorrect hash of %q: got: %x, expected: %x",
				table.in, got[:], want)
		}
	}
}

func mustDecodeHex(t *testing.T, out []byte, s string) {
	err := decodeHex(out, s)
	if err != nil {
		t.Fatal(err)
	}
}

func mustSignatureFromHex(t *testing.T, s string) Signature {
	signature, err := SignatureFromHex(s)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func mustPublicKeyFromHex(t *testing.T, s string) PublicKey {
	pub, err := PublicKeyFromHex(s)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func mustSignerFromHex(t *testing.T, s string) Signer {
	signer, err := SignerFromHex(s)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// Basic sanity check, not intended as a thorough ed25519 test. Uses
// second line from https://ed25519.cr.yp.to/python/sign.input (single
// byte message).
func TestSign(t *testing.T) {
	signer := mustSignerFromHex(t, "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	msg := []byte{0x72}
	signature, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	want := mustSignatureFromHex(t,
		"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"+
			"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
	if signature != want {
		t.Fatalf("unexpected signature value, got %x, expected %x",
			signature[:], want[:])
	}
	publicKey := mustPublicKeyFromHex(t, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
	if !Verify(&publicKey, msg, &signature) {
		t.Errorf("verify on valid message and signature failed")
	}
}

func TestVerify(t *testing.T) {
	var secret PrivateKey
	copy(secret[:], incBytes(PrivateKeySize))
	signer := NewEd25519Signer(&secret)
	pub := signer.Public()

	message := []byte("squeemish ossifrage")
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if !Verify(&pub, message, &signature) {
		t.Errorf("verify on valid message and signature failed")
	}
	badSignature := signature
	badSignature[3]++
	if Verify(&pub, message, &badSignature) {
		t.Errorf("verify on invalid signature succeeded")
	}
	message[3]++
	if Verify(&pub, message, &signature) {
		t.Errorf("verify on modified message succeeded")
	}
}
