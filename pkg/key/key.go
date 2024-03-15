package key

import (
	"fmt"
	"os"
	"strings"

	"sigsum.org/key-mgmt/pkg/ssh"
	intssh "sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/crypto"
)

// Expects an Openssh public key (single-line format)
func ParsePublicKey(ascii string) (crypto.PublicKey, error) {
	blob, _, err := ssh.ParseAsciiEd25519PublicKey([]byte(ascii)) // Ignores comment.
	if err != nil {
		return crypto.PublicKey{}, err
	}
	if len(blob) != crypto.PublicKeySize {
		return crypto.PublicKey{}, fmt.Errorf("internal error: unexpected public key length: %v", len(blob))
	}
	var key crypto.PublicKey
	copy(key[:], blob)
	return key, nil
}

// Supports two formats:
//   - Openssh private key
//   - Openssh public key, in which case ssh-agent is used to
//     access the corresponding private key.
//   - (Deprecated) Raw hex-encoded private key (RFC 8032)
func ParsePrivateKey(ascii string) (crypto.Signer, error) {
	ascii = strings.TrimSpace(ascii)
	// Accepts public keys only in openssh format, since with raw
	// hex-encoded keys, we can't distinguish between public and
	// private keys.
	if strings.HasPrefix(ascii, "ssh-ed25519 ") {
		key, err := ParsePublicKey(ascii)
		if err != nil {
			return nil, err
		}
		c, err := intssh.Connect()
		if err != nil {
			return nil, fmt.Errorf("only public key available, and no ssh-agent: %v", err)
		}
		return c.NewSigner(&key)
	}
	blob, err := ssh.ParseAsciiEd25519PrivateKey([]byte(ascii))
	if err == ssh.NoPEMError {
		// TODO: Delete support for raw keys.
		return crypto.SignerFromHex(ascii)
	}
	if len(blob) != 64 {
		return nil, fmt.Errorf("internal error: unexpected private key blob length: %v", len(blob))
	}
	var pub crypto.PublicKey
	var priv crypto.PrivateKey

	copy(priv[:], blob[:32])
	copy(pub[:], blob[32:])

	signer := crypto.NewEd25519Signer(&priv)
	if signer.Public() != pub {
		return nil, fmt.Errorf("internal error: inconsistent private key")
	}

	return signer, nil
}

func ReadPublicKeyFile(fileName string) (crypto.PublicKey, error) {
	contents, err := os.ReadFile(fileName)
	if err != nil {
		return crypto.PublicKey{}, err
	}
	key, err := ParsePublicKey(string(contents))
	if err != nil {
		return crypto.PublicKey{}, fmt.Errorf("parsing public key file %q failed: %v",
			fileName, err)
	}
	return key, nil
}

func ReadPrivateKeyFile(fileName string) (crypto.Signer, error) {
	contents, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	signer, err := ParsePrivateKey(string(contents))
	if err != nil {
		return nil, fmt.Errorf("parsing private key file %q failed: %v",
			fileName, err)
	}
	return signer, nil
}
