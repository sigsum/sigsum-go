// package token validates a sigsum submit-token.
package token

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
)

const (
	Label           = "_sigsum_v1"
	oldLabel        = "_sigsum_v0"
	HeaderName      = "Sigsum-Token"
	namespace       = "sigsum.org/v1/submit-token"
	maxNumberOfKeys = 10
)

// Represents the contents of the HTTP Sigsum-Submit: header-
type SubmitHeader struct {
	Domain string
	Token  crypto.Signature
}

func (s *SubmitHeader) ToHeader() string {
	return fmt.Sprintf("%s %x", s.Domain, s.Token)
}

func (s *SubmitHeader) FromHeader(header string) error {
	parts := strings.Split(header, " ")
	if n := len(parts); n != 2 {
		return fmt.Errorf("expected 2 parts, got %d", n)
	}
	if len(parts[0]) == 0 {
		return fmt.Errorf("malformed header, domain part empty")
	}
	var err error
	s.Token, err = crypto.SignatureFromHex(parts[1])
	if err == nil {
		s.Domain = parts[0]
	}
	return err
}

func MakeToken(signer crypto.Signer, logKey *crypto.PublicKey) (crypto.Signature, error) {
	return signer.Sign(crypto.AttachNamespace(namespace, logKey[:]))
}

// Verify a token using a given key, with no DNS loookup.
func VerifyToken(key *crypto.PublicKey, logKey *crypto.PublicKey, token *crypto.Signature) error {
	if !crypto.Verify(key, crypto.AttachNamespace(namespace, logKey[:]), token) {
		return fmt.Errorf("invalid token signature")
	}
	return nil
}

// Looks up the appropriate TXT records for a domain.
func LookupDomain(ctx context.Context,
	lookupTXT func(context.Context, string) ([]string, error),
	domain string) ([]string, error) {
	rsps, err := lookupTXT(ctx, Label+"."+domain)
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) && dnsError.IsNotFound {
		r2, e2 := lookupTXT(ctx, oldLabel+"."+domain)
		if e2 == nil {
			return r2, nil
		}
	}
	return rsps, err
}

// DnsResolver implements the Verifier interface by querying DNS.
type DnsVerifier struct {
	// Usually, net.Resolver.LookupTXT, but set differently for testing.
	lookupTXT func(ctx context.Context, name string) ([]string, error)
	logKey    crypto.PublicKey
}

func NewDnsVerifier(logKey *crypto.PublicKey) *DnsVerifier {
	var resolver net.Resolver
	return &DnsVerifier{
		lookupTXT: resolver.LookupTXT,
		logKey:    *logKey,
	}
}

func (dv *DnsVerifier) Verify(ctx context.Context, header *SubmitHeader) error {
	rsps, err := LookupDomain(ctx, dv.lookupTXT, header.Domain)
	if err != nil {
		return fmt.Errorf("token: dns look-up failed: %v", err)
	}
	var ignoredKeys, badKeys int

	if len(rsps) > maxNumberOfKeys {
		ignoredKeys = len(rsps) - maxNumberOfKeys
		rsps = rsps[:maxNumberOfKeys]
	}
	signedData := crypto.AttachNamespace(namespace, dv.logKey[:])
	for _, keyHex := range rsps {
		key, err := crypto.PublicKeyFromHex(keyHex)
		if err != nil {
			badKeys++
			continue
		}
		if crypto.Verify(&key, signedData, &header.Token) {
			return nil
		}
	}
	return fmt.Errorf("validating token signature failed, ignored keys: %d, syntactically bad keys: %d",
		ignoredKeys, badKeys)
}
