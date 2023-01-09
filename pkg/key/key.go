package key

import (
	"fmt"
	"strings"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/crypto"
)

// Supports two formats:
//   * Raw hex-encoded public key (RFC 8032)
//   * Openssh public key (single-line format)
func ParsePublicKey(ascii string) (crypto.PublicKey, error) {
	ascii = strings.TrimSpace(ascii)
	if strings.HasPrefix(ascii, "ssh-ed25519 ") {
		return ssh.ParsePublicEd25519(ascii)
	}
	return crypto.PublicKeyFromHex(ascii)
}

// Supports two formats:
//   * priv:-prefix + raw hex-encoded private key (RFC 8032)
//   * Raw hex-encoded public key (RFC 8032)
//   * Openssh public key.
//
// For the cases of public keys, ssh-agent is used to access the
// corresponding private key.
func ParsePrivateKey(ascii string) (crypto.Signer, error) {
	if strings.HasPrefix(ascii, "priv:") {
		return crypto.SignerFromHex(strings.TrimSpace(ascii[5:]))
	}

	// Parse public key, and use ssh-agent.
	var key crypto.PublicKey
	var err error
	if strings.HasPrefix(ascii, "ssh-ed25519 ") {
		key, err = ssh.ParsePublicEd25519(ascii)
	} else {
		key, err = crypto.PublicKeyFromHex(strings.TrimSpace(ascii))
	}
	if err != nil {
		return nil, err
	}

	c, err := ssh.Connect()
	if err != nil {
		return nil, fmt.Errorf("only public key available, and no ssh-agent: %v", err)
	}
	return c.NewSigner(&key)
}
