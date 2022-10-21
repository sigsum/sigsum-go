// package token validates a sigsum submit-token.
package token

import (
	"context"
	"fmt"
	"net"

	"crypto/ed25519"
	"sigsum.org/sigsum-go/internal/fmtio"
	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	prefix          = "_sigsum_v0."
	namespace       = "submit-token:v0@sigsum.org"
	maxNumberOfKeys = 10
)

// Verifier can verify that a domain name is aware of a public key.
// Name and signature corresponds to the value of the submit-token:
// header, so signature is still hex-encoded.
type Verifier interface {
	Verify(ctx context.Context, logKey *types.PublicKey, name, signature string) error
}

// DnsResolver implements the Verifier interface by querying DNS.
type DnsVerifier struct {
	// Usually, net.Resolver.LookupTXT, but set differently for testing.
	lookupTXT func(ctx context.Context, name string) ([]string, error)
}

func NewDnsVerifier() Verifier {
	var resolver net.Resolver
	return &DnsVerifier{lookupTXT: resolver.LookupTXT}
}

func (dv *DnsVerifier) Verify(ctx context.Context, logKey *types.PublicKey, name, signatureHex string) error {
	signature, err := fmtio.SignatureFromHex(signatureHex)
	if err != nil {
		return fmt.Errorf("failed decoding hex signature: %v", err)
	}
	rsps, err := dv.lookupTXT(ctx, prefix+name)
	if err != nil {
		return fmt.Errorf("token: dns look-up failed: %v", err)
	}
	var ignoredKeys, badKeys int

	if len(rsps) > maxNumberOfKeys {
		ignoredKeys = len(rsps) - maxNumberOfKeys
		rsps = rsps[:maxNumberOfKeys]
	}
	signedData := ssh.SignedData(namespace, (*logKey)[:])
	for _, keyHex := range rsps {
		key, err := fmtio.PublicKeyFromHex(keyHex)
		if err != nil {
			badKeys++
			continue
		}
		if ed25519.Verify(key[:], signedData, signature[:]) {
			return nil
		}
	}
	return fmt.Errorf("validating token signature failed, ignored keys: %d, syntactically bad keys: %d",
		ignoredKeys, badKeys)
}
