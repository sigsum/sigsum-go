package key

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/crypto"
)

// Expects an Openssh public key (single-line format)
func ParsePublicKey(ascii string) (crypto.PublicKey, error) {
	return ssh.ParsePublicEd25519(ascii)
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
		key, err := ssh.ParsePublicEd25519(ascii)
		if err != nil {
			return nil, err
		}
		c, err := ssh.Connect()
		if err != nil {
			return nil, fmt.Errorf("only public key available, and no ssh-agent: %v", err)
		}
		return c.NewSigner(&key)
	}
	_, signer, err := ssh.ParsePrivateKeyFile([]byte(ascii))
	if err == ssh.NoPEMError {
		// TODO: Delete support for raw keys.
		signer, err = crypto.SignerFromHex(ascii)
	}
	return signer, err
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

func ReadPublicKeysFile(fileName string) (map[crypto.Hash]crypto.PublicKey, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open public keys file %q: %v", fileName, err)
	}
	keys := make(map[crypto.Hash]crypto.PublicKey)
	scanner := bufio.NewScanner(f)
	var n int
	for scanner.Scan() {
		n++
		line := scanner.Text()
		// Mirror openssh implementation. Skip lines that
		// start with '#', or are completely empty. All other
		// lines must be valid key lines.
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		k, err := ParsePublicKey(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key on line %d of file %q: %v", n, fileName, err)
		}
		keys[crypto.HashBytes(k[:])] = k
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read public keys file %q: %v", fileName, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no public keys found in file %q", fileName)
	}
	return keys, nil
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
