package token

import (
	"context"
	"encoding/hex"
	"log"
	"testing"

	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sigsum.org/sigsum-go/internal/fmtio"
	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/types"
	"strings"
)

func verifierWithResponses(domain string, responses []string) Verifier {
	return &DnsVerifier{lookupTXT: func(_ context.Context, name string) ([]string, error) {
		if name != "_sigsum_v0."+domain {
			return []string{}, fmt.Errorf("NXDOMAIN: %q", name)
		}
		return responses, nil
	}}
}

func newKeyPair(t *testing.T) (crypto.Signer, types.PublicKey) {
	vk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var pub types.PublicKey
	copy(pub[:], vk[:])
	return sk, pub
}

func TestVerify(t *testing.T) {
	logKeyHex := "cda2517e17dcba133eb0e71bf77473f94a77d7e61b1de4e1e64adfd0938d6182"
	logKey, err := fmtio.PublicKeyFromHex(logKeyHex)
	if err != nil {
		log.Fatal(err.Error())
	}

	signer, pub := newKeyPair(t)
	hexKey := hex.EncodeToString(pub[:])

	signature, err := signer.Sign(nil, ssh.SignedData("submit-token:v0@sigsum.org", logKey[:]), crypto.Hash(0))
	if err != nil {
		log.Fatal(err.Error())
	}

	token := hex.EncodeToString(signature)
	testOne := func(desc, tokenDomain, signature, registeredDomain string, records []string,
		check func(err error) error) {
		t.Helper()
		if err := check(verifierWithResponses(registeredDomain, records).Verify(
			context.Background(), &logKey, tokenDomain, signature)); err != nil {
			t.Errorf("%s: %v", desc, err)
		}
	}
	testValid := func(desc, tokenDomain, signature, registeredDomain string, records []string) {
		t.Helper()
		testOne("valid: "+desc, tokenDomain, signature, registeredDomain, records,
			func(err error) error { return err })
	}
	testInvalid := func(desc, tokenDomain, signature, registeredDomain string, records []string, msg string) {
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

	testValid("single key", "foo.example.org", token, "foo.example.org", []string{hexKey})
	testInvalid("nxdomain", "foo.example.org", token, "bar.example.org", []string{hexKey}, "NXDOMAIN")
	testInvalid("no matching key", "foo.example.org", token, "foo.example.org", []string{
		logKeyHex, hexKey + "aa", "bad"},
		"bad keys: 2")
	testValid("multiple keys",
		"foo.example.org", token, "foo.example.org", []string{
			logKeyHex, hexKey + "aa", "bad", hexKey})
	testInvalid("too many keys",
		"foo.example.org", token, "foo.example.org", []string{
			logKeyHex, hexKey + "aa", "bad", "4", "5",
			"6", "7", "8", "9", "10", hexKey},
		"ignored keys: 1")
}
