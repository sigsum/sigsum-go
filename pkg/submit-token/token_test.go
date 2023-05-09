package token

import (
	"context"
	"encoding/hex"
	"log"
	"testing"

	"fmt"
	"sigsum.org/sigsum-go/pkg/crypto"
	"strings"
)

func verifierWithResponses(logKey *crypto.PublicKey, domain string, responses []string) Verifier {
	return &DnsVerifier{
		lookupTXT: func(_ context.Context, name string) ([]string, error) {
			if name != "_sigsum_v0."+domain {
				return []string{}, fmt.Errorf("NXDOMAIN: %q", name)
			}
			return responses, nil
		},
		logKey: *logKey,
	}
}

func newKeyPair(t *testing.T) (crypto.PublicKey, crypto.Signer) {
	pub, signer, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return pub, signer
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
			context.Background(), &SubmitToken{Domain: tokenDomain, Token: *signature})); err != nil {
			t.Errorf("%s: %v", desc, err)
		}
	}
	testValid := func(desc, tokenDomain string, signature *crypto.Signature, registeredDomain string, records []string) {
		t.Helper()
		testOne("valid: "+desc, tokenDomain, signature, registeredDomain, records,
			func(err error) error { return err })
	}
	testInvalid := func(desc, tokenDomain string, signature *crypto.Signature, registeredDomain string, records []string, msg string) {
		t.Helper()
		testOne("invalid: "+desc, tokenDomain, signature, registeredDomain, records,
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
	testInvalid("too many keys",
		"foo.example.org", &signature, "foo.example.org", []string{
			logKeyHex, hexKey + "aa", "bad", "4", "5",
			"6", "7", "8", "9", "10", hexKey},
		"ignored keys: 1")
}
