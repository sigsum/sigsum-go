// package dns checks if a domain name is aware of a hashed public key.  A
// look-up is performed if the specified domain name matches "^_sigsum_v0.*".
package dns

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	prefix = "_sigsum_v0."
)

// Verifier can verify that a domain name is aware of a public key
type Verifier interface {
	Verify(ctx context.Context, name string, key *types.PublicKey) error
}

// DefaultResolver implements the Verifier interface with Go's default resolver
type DefaultResolver struct {
	resolver net.Resolver
}

func NewDefaultResolver() Verifier {
	return &DefaultResolver{}
}

type DummyResolver struct {
}

func NewDummyResolver() Verifier {
	return &DummyResolver{}
}

func (dr *DefaultResolver) Verify(ctx context.Context, name string, pub *types.PublicKey) error {
	if err := validPrefix(name); err != nil {
		return fmt.Errorf("dns: %s", err)
	}
	rsps, err := dr.resolver.LookupTXT(ctx, name)
	if err != nil {
		return fmt.Errorf("dns: look-up failed: %s", name)
	}
	if err := validResponse(pub, rsps); err != nil {
		return fmt.Errorf("dns: %s", err)
	}
	return nil
}

func validResponse(pub *types.PublicKey, rsps []string) error {
	keyHash := hex.EncodeToString(merkle.HashFn(pub[:])[:])
	for _, rsp := range rsps {
		if rsp == keyHash {
			return nil
		}
	}
	return fmt.Errorf("unknown key hash %s", keyHash)
}

func validPrefix(name string) error {
	if !strings.HasPrefix(name, prefix) {
		return fmt.Errorf("domain name prefix must be %s", prefix)
	}
	return nil
}

func (_ *DummyResolver) Verify(_ context.Context, _ string, _ *types.PublicKey) error {
	return nil
}
