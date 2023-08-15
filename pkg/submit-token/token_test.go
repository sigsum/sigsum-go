package token

import (
	"context"
	"encoding/hex"
	"log"
	"net"
	"testing"

	"fmt"
	"sigsum.org/sigsum-go/pkg/crypto"
	"strings"
)

func lookupTXTWithResponses(name string, responses []string) func(context.Context, string) ([]string, error) {
	return func(_ context.Context, queryName string) ([]string, error) {
		if queryName != name {
			return nil, &net.DNSError{
				Err:        "NXDOMAIN",
				Name:       queryName,
				IsNotFound: true,
			}
		}
		return responses, nil
	}
}
func verifierWithResponses(logKey *crypto.PublicKey, queryName string, responses []string) *DnsVerifier {
	return &DnsVerifier{
		lookupTXT: lookupTXTWithResponses(queryName, responses),
		logKey:    *logKey,
	}
}

func newKeyPair(t *testing.T) (crypto.PublicKey, crypto.Signer) {
	pub, signer, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return pub, signer
}

func TestSubmitHeaderFromHeader(t *testing.T) {
	for _, table := range []struct {
		desc  string
		input string
		exp   *SubmitHeader
	}{
		{"no domain", " aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil},
		{
			"valid, lowercase",
			"foo.example.com aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			&SubmitHeader{Domain: "foo.example.com", Token: mustSignatureFromHex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
		},
		{
			"valid, mixed case",
			"foo.example.com aaaaaaaaaaaaaaaaaaaaaaaaaaaAaaaaaaaaaaaaaaaaaaaaaaAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			&SubmitHeader{Domain: "foo.example.com", Token: mustSignatureFromHex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
		},
		{"extra space", "foo.example.com  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil},
		{"bad hex", "foo.example.com aaxaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil},
		{"bad hex length", "foo.example.com aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil},
		{"bad signature length", "foo.example.com aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil},
	} {
		var header SubmitHeader
		if err := header.FromHeader(table.input); err != nil {
			if table.exp == nil {
				// Expected error
				t.Logf("%s: error (expected): %v\n", table.desc, err)
			} else {
				t.Errorf("%s: FromHeader failed: %v\n", table.desc, err)
			}
		} else {
			if table.exp == nil {
				t.Errorf("%s: unexpected non-failure, got result: %x\n", table.desc, header)
			} else if got, want := header, *table.exp; got != want {
				t.Errorf("%s: unexpected result, got: %x, wanted: %x\n", table.desc, got, want)
			}
		}
	}
}

func TestSubmitHeaderToHeader(t *testing.T) {
	for _, table := range []struct {
		input SubmitHeader
		exp   string
	}{
		{
			SubmitHeader{Domain: "foo.example.org", Token: mustSignatureFromHex(t, "BBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
			"foo.example.org bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	} {
		if got, want := table.input.ToHeader(), table.exp; got != want {
			t.Errorf("unexpected result from ToHeader, got: %q, want: %q\n", got, want)
		}
	}
}

func TestVerify(t *testing.T) {
	logKeyHex := "cda2517e17dcba133eb0e71bf77473f94a77d7e61b1de4e1e64adfd0938d6182"
	logKey, err := crypto.PublicKeyFromHex(logKeyHex)
	if err != nil {
		log.Fatal(err.Error())
	}

	pub, signer := newKeyPair(t)
	hexKey := hex.EncodeToString(pub[:])

	signature, err := MakeToken(signer, &logKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	testOne := func(desc, tokenDomain string, signature *crypto.Signature, registeredDomain string, records []string,
		check func(err error) error) {
		t.Helper()
		if err := check(verifierWithResponses(&logKey, registeredDomain, records).Verify(
			context.Background(), &SubmitHeader{Domain: tokenDomain, Token: *signature})); err != nil {
			t.Errorf("%s: %v", desc, err)
		}
	}
	testValid := func(desc, tokenDomain string, signature *crypto.Signature, registeredDomain string, records []string) {
		t.Helper()
		testOne("valid: "+desc, tokenDomain, signature, "_sigsum_v1."+registeredDomain, records,
			func(err error) error { return err })
	}
	testValidFallback := func(desc, tokenDomain string, signature *crypto.Signature, registeredDomain string, records []string) {
		t.Helper()
		testOne("valid: "+desc+" (fallback)", tokenDomain, signature, "_sigsum_v0."+registeredDomain, records,
			func(err error) error { return err })
	}
	testInvalid := func(desc, tokenDomain string, signature *crypto.Signature, registeredDomain string, records []string, msg string) {
		t.Helper()
		testOne("invalid: "+desc, tokenDomain, signature, "_sigsum_v1."+registeredDomain, records,
			func(err error) error {
				if err == nil {
					return fmt.Errorf("unexpected success from invalid token")
				}
				if strings.Contains(err.Error(), msg) {
					// As expected
					return nil
				}
				return fmt.Errorf("unexpected type of error: %v", err)
			})
	}

	testValid("single key", "foo.example.org", &signature, "foo.example.org", []string{hexKey})
	testInvalid("nxdomain", "foo.example.org", &signature, "bar.example.org", []string{hexKey}, "NXDOMAIN")
	testInvalid("no matching key", "foo.example.org", &signature, "foo.example.org", []string{
		logKeyHex, hexKey + "aa", "bad"},
		"bad keys: 2")
	testValid("multiple keys",
		"foo.example.org", &signature, "foo.example.org", []string{
			logKeyHex, hexKey + "aa", "bad", hexKey})
	testValidFallback("multiple keys",
		"foo.example.org", &signature, "foo.example.org", []string{
			logKeyHex, hexKey + "aa", "bad", hexKey})
	testInvalid("too many keys",
		"foo.example.org", &signature, "foo.example.org", []string{
			logKeyHex, hexKey + "aa", "bad", "4", "5",
			"6", "7", "8", "9", "10", hexKey},
		"ignored keys: 1")
}

func mustSignatureFromHex(t *testing.T, ascii string) crypto.Signature {
	sig, err := crypto.SignatureFromHex(ascii)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}
