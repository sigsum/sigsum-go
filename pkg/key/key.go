package key

import (
	"fmt"
	"strings"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/crypto"
)

// Supports two formats:
//   * Raw-hex-encoded public key (RFC 8032)
//   * Openssh public key (single-line format)
func ParsePublicKey(ascii string) (crypto.PublicKey, error) {
	ascii = strings.TrimSpace(ascii)
	if strings.HasPrefix(ascii, "ssh-ed25519 ") {
		return ssh.ParsePublicEd25519(ascii)
	}
	return crypto.PublicKeyFromHex(ascii)
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
		return c.NewSigner(&key)
	}
	return crypto.SignerFromHex(ascii)
}
