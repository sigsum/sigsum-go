package key

import (
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/types"
)

// Supports two formats:
//   * Raw-hex-encoded public key (RFC 8032)
//   * Openssh public key (single-line format)
func ParsePublicKey(ascii string) (types.PublicKey, error) {
	ascii = strings.TrimSpace(ascii)
	toPublicKey := func(b []byte, err error) (types.PublicKey, error) {
		var key types.PublicKey
		if err != nil {
			return key, err
		}
		if len(b) != 32 {
			return key, fmt.Errorf("invalid size of key: %d", len(b))
		}
		copy(key[:], b[:])
		return key, nil
	}
	if strings.HasPrefix(ascii, "ssh-ed25519 ") {
		return toPublicKey(ssh.ParsePublicEd25519(ascii))
	}
	return toPublicKey(hex.DecodeString(ascii))
}

// Supports two formats:
//   * Raw-hex-encoded private key (RFC 8032)
//   * Openssh public key, in which case ssh-agent is used to
//     access the corresponding private key.
func ParsePrivateKey(ascii string) (crypto.Signer, error) {
	ascii = strings.TrimSpace(ascii)
	// Accepts public keys only in openssh format, since with raw
	// hex-encoded keys, we can't distinguish between public and
	// private keys.
	if strings.HasPrefix(ascii, "ssh-ed25519 ") {
		key, err := ssh.ParsePublicEd25519(ascii)
		if err != nil {
			return nil, err
		}
		c, err := ssh.Connect()
		if err != nil {
			return nil, fmt.Errorf("only public key availble, and no ssh-agent: %v", err)
		}
		return c.NewSigner(key)
	}
	key, err := hex.DecodeString(ascii)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %v", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid size of hex-format private key: %d", len(key))
	}
	return ed25519.NewKeyFromSeed(key), nil
}
