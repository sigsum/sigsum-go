package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"

	"testing"
)

func TestValidEd25519PublicKeyFromHex(t *testing.T) {
	b := incBytes(32)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		s, strings.ToUpper(s),
	} {
		hash, err := Ed25519PublicKeyFromHex(in)
		if err != nil {
			t.Errorf("error on input %q: %v", in, err)
		}
		if !bytes.Equal(b, hash[:]) {
			t.Errorf("fail on input %q, wanted %x, got %x", in, b, hash)
		}
	}
}

func TestInvalidEd25519PublicKeyFromHex(t *testing.T) {
	b := incBytes(33)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		"", "0x11", "123z", s[:63], s[:65], s[:66],
	} {
		hash, err := Ed25519PublicKeyFromHex(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %x",
				in, hash)
		}
	}
}

func TestValidEd25519SignatureFromHex(t *testing.T) {
	b := incBytes(64)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		s, strings.ToUpper(s),
	} {
		hash, err := Ed25519SignatureFromHex(in)
		if err != nil {
			t.Errorf("error on input %q: %v", in, err)
		}
		if !bytes.Equal(b, hash[:]) {
			t.Errorf("fail on input %q, wanted %x, got %x", in, b, hash)
		}
	}
}

func TestInvalidEd25519SignatureFromHex(t *testing.T) {
	b := incBytes(65)
	s := hex.EncodeToString(b)
	for _, in := range []string{
		"", "0x11", "123z", s[:127], s[:129], s[:130],
	} {
		hash, err := Ed25519SignatureFromHex(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %x",
				in, hash)
		}
	}
}

// Basic sanity check, not intended as a thorough ed25519 test. Uses
// second line from https://ed25519.cr.yp.to/python/sign.input (single
// byte message).
func TestSignEd25519(t *testing.T) {
	signer := mustEd25519SignerFromHex(t, "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	msg := []byte{0x72}
	signature, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	want := mustEd25519SignatureFromHex(t,
		"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"+
			"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
	if signature != want {
		t.Fatalf("unexpected signature value, got %x, expected %x",
			signature, want)
	}
	publicKey := mustEd25519PublicKeyFromHex(t, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
	if !publicKey.Verify(msg, &signature) {
		t.Errorf("verify on valid message and signature failed")
	}
}

func TestVerifyEd25519(t *testing.T) {
	var secret Ed25519PrivateKey
	copy(secret[:], incBytes(Ed25519PrivateKeySize))
	signer := NewEd25519Signer(&secret)
	pub := signer.Public()

	message := []byte("squeemish ossifrage")
	signature, err := signer.Sign(message)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if !pub.Verify(message, &signature) {
		t.Errorf("verify on valid message and signature failed")
	}
	badSignature := signature
	badSignature[3]++
	if pub.Verify(message, &badSignature) {
		t.Errorf("verify on invalid signature succeeded")
	}
	message[3]++
	if pub.Verify(message, &signature) {
		t.Errorf("verify on modified message succeeded")
	}
}

func mustEd25519SignatureFromHex(t *testing.T, s string) Ed25519Signature {
	signature, err := Ed25519SignatureFromHex(s)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func mustEd25519PublicKeyFromHex(t *testing.T, s string) Ed25519PublicKey {
	pub, err := Ed25519PublicKeyFromHex(s)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func mustEd25519SignerFromHex(t *testing.T, s string) Signer {
	signer, err := Ed25519SignerFromHex(s)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestValidateEd25519PublicKeyOk(t *testing.T) {
	pub, _, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEd25519PublicKey(&pub); err != nil {
		t.Errorf("valid public key %x was rejected: %v", pub, err)
	}
}

func TestValidateEd25519PublicKeyNonCanonical(t *testing.T) {
	for _, in := range []struct {
		valid bool // Valid encoding to edwards25519
		hex   string
	}{
		{true, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "f4ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "f4ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "f5ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "f5ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "f9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "f9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "faffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "faffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "fbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "fbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "fdffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{false, "feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{false, "feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{true, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
		{true, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		// Low order point, in non-canonical serialization.
		// See https://eprint.iacr.org/2020/1244.pdf, table 6b.
		{true, "0100000000000000000000000000000000000000000000000000000000000080"},
	} {
		pub, err := Ed25519PublicKeyFromHex(in.hex)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateEd25519PublicKey(&pub); err == nil {
			t.Errorf("non-canonical key %x was not rejected", pub)
		} else if in.valid {
			if !strings.Contains(err.Error(), "non-canonical") {
				t.Errorf("non-canonical key %x was rejected with unexpected error: %v", pub, err)
			}
		} else if !strings.Contains(err.Error(), "invalid point") {
			t.Errorf("invalid key %x was rejected with unexpected error: %v", pub, err)
		}
	}
}

func TestValidateEd25519PublicKeyLowOrder(t *testing.T) {
	for _, hex := range []string{
		// List from https://eprint.iacr.org/2020/1244.pdf, table 6b.
		"0100000000000000000000000000000000000000000000000000000000000000", // Identity
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // Order 2
		"0000000000000000000000000000000000000000000000000000000000000080", // Order 4
		"0000000000000000000000000000000000000000000000000000000000000000", // Order 4
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // Order 8
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // Order 8
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // Order 8
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // Order 8
	} {
		pub, err := Ed25519PublicKeyFromHex(hex)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateEd25519PublicKey(&pub); err == nil {
			t.Errorf("low-order key %x was not rejected", pub)
		} else if !strings.Contains(err.Error(), "low-order") {
			t.Errorf("low-order key %x was rejected with unexpected error: %v", pub, err)
		}
	}
}
