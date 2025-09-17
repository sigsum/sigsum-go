package key

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
)

// Expects an Openssh public key (single-line format)
func ParsePublicKey(ascii string) (crypto.PublicKey, error) {
	return ssh.ParsePublicEd25519(ascii)
}

// s is a string on the form sigsum-policy="foo"
func extractPolicyName(s string) (string, error) {
	i := strings.IndexRune(s, '=')
	quotedName := s[i+1:]
	log.Info("quotedName = %v", quotedName)
	// First and last character must be quotation marks
	if quotedName[0] != '"' || quotedName[len(quotedName)-1] != '"' {
		return "", fmt.Errorf("Failed to extract policy name")
	}
	return quotedName[1 : len(quotedName)-1], nil
}

// Supports two formats:
//   - Openssh private key
//   - Openssh public key, in which case ssh-agent is used to
//     access the corresponding private key.
//   - (Deprecated) Raw hex-encoded private key (RFC 8032)
//
// The second output is a resulting policy name, in case a
// "sigsum-policy=" option is found in the public key.
func ParsePrivateKey(ascii string) (crypto.Signer, string, error) {
	ascii = strings.TrimSpace(ascii)
	// Accepts public keys only in openssh format, since with raw
	// hex-encoded keys, we can't distinguish between public and
	// private keys.
	policyName := ""
	if strings.HasPrefix(ascii, "sigsum-policy=") {
		// extract first part of the string, until first space
		i := strings.IndexRune(ascii, ' ')
		firstPart := ascii[:i]
		ascii = ascii[i+1:]
		var err error
		policyName, err = extractPolicyName(firstPart)
		if err != nil {
			return nil, "", err
		}
		log.Info("policyName = %v", policyName)
	}
	if strings.HasPrefix(ascii, "ssh-ed25519 ") {
		key, err := ssh.ParsePublicEd25519(ascii)
		if err != nil {
			return nil, "", err
		}
		c, err := ssh.Connect()
		if err != nil {
			return nil, "", fmt.Errorf("only public key available, and no ssh-agent: %v", err)
		}
		signer, err := c.NewSigner(&key)
		return signer, policyName, err
	}
	_, signer, err := ssh.ParsePrivateKeyFile([]byte(ascii))
	if err == ssh.NoPEMError {
		// TODO: Delete support for raw keys.
		signer, err = crypto.SignerFromHex(ascii)
	}
	return signer, "", err
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

func parsePublicKeysFile(f io.Reader, fileName string) (map[crypto.Hash]crypto.PublicKey, error) {
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
		key, err := ParsePublicKey(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key on line %d of file %q: %v", n, fileName, err)
		}
		keyHash := crypto.HashBytes(key[:])
		if _, has := keys[keyHash]; has {
			return nil, fmt.Errorf("duplicate public key on line %d of file %q", n, fileName)
		}
		keys[keyHash] = key
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read public keys file %q: %v", fileName, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no public keys found in file %q", fileName)
	}
	return keys, nil
}

func ReadPublicKeysFile(fileName string) (map[crypto.Hash]crypto.PublicKey, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open public keys file %q: %v", fileName, err)
	}
	defer f.Close()
	return parsePublicKeysFile(f, fileName)
}

// The second output is a resulting policy name, in case a
// "sigsum-policy=" option is found in the public key.
func ReadPrivateKeyFile(fileName string) (crypto.Signer, string, error) {
	contents, err := os.ReadFile(fileName)
	if err != nil {
		return nil, "", err
	}
	signer, policyName, err := ParsePrivateKey(string(contents))
	if err != nil {
		return nil, "", fmt.Errorf("parsing private key file %q failed: %v",
			fileName, err)
	}
	return signer, policyName, nil
}
