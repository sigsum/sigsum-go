package key

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/crypto"
)

// Expects an Openssh public key (single-line format)
func ParsePublicKey(ascii string) (crypto.PublicKey, error) {
	return ssh.ParsePublicEd25519(ascii)
}

// Expects an Openssh public key (single-line format)
func ParsePublicKeyWithPolicyName(ascii string) (crypto.PublicKey, string, error) {
	return ssh.ParsePublicEd25519WithPolicyName(ascii)
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
	key, policyName, err := ssh.ParsePublicEd25519WithPolicyName(ascii)
	if err == nil {
		c, err := ssh.Connect()
		if err != nil {
			return nil, "", fmt.Errorf("only public key available, and no ssh-agent: %v", err)
		}
		signer, err := c.NewSigner(&key)
		return signer, policyName, err
	}
	// ParsePublicEd25519 failed, assume private key case
	_, signer, err := ssh.ParsePrivateKeyFile([]byte(ascii))
	if err == ssh.NoPEMError {
		// TODO: Delete support for raw keys.
		signer, err = crypto.SignerFromHex(ascii)
	}
	return signer, "", err
}

func ReadPublicKeyFile(fileName string) (crypto.PublicKey, error) {
	key, _, err := ReadPublicKeyFileWithPolicyName(fileName)
	return key, err
}

func ReadPublicKeyFileWithPolicyName(fileName string) (crypto.PublicKey, string, error) {
	contents, err := os.ReadFile(fileName)
	if err != nil {
		return crypto.PublicKey{}, "", err
	}
	key, policyName, err := ParsePublicKeyWithPolicyName(string(contents))
	if err != nil {
		return crypto.PublicKey{}, "", fmt.Errorf("parsing public key file %q failed: %v",
			fileName, err)
	}
	return key, policyName, nil
}

func parsePublicKeysFile(f io.Reader, fileName string) (map[crypto.Hash]crypto.PublicKey, error) {
	keys, _, err := parsePublicKeysFileWithPolicyNames(f, fileName)
	return keys, err
}

// This function returns public keys along with a list of any policy
// names  found in the pubkeys file. If there are no policy names then
// that becomes a list of empty strings.
func parsePublicKeysFileWithPolicyNames(f io.Reader, fileName string) (map[crypto.Hash]crypto.PublicKey, []string, error) {
	keys := make(map[crypto.Hash]crypto.PublicKey)
	var policyNames []string
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
		key, policyName, err := ParsePublicKeyWithPolicyName(line)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse public key on line %d of file %q: %v", n, fileName, err)
		}
		keyHash := crypto.HashBytes(key[:])
		if _, has := keys[keyHash]; has {
			return nil, nil, fmt.Errorf("duplicate public key on line %d of file %q", n, fileName)
		}
		keys[keyHash] = key
		policyNames = append(policyNames, policyName)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to read public keys file %q: %v", fileName, err)
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("no public keys found in file %q", fileName)
	}
	return keys, policyNames, nil
}

// This function returns public keys along with a list of any policy
// names found in the pubkeys file. If there are no policy names then
// that becomes a list of empty strings.
func ReadPublicKeysFile(fileName string) (map[crypto.Hash]crypto.PublicKey, []string, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open public keys file %q: %v", fileName, err)
	}
	defer f.Close()
	return parsePublicKeysFileWithPolicyNames(f, fileName)
}

// The second output is a resulting policy name, in case a
// "sigsum-policy=" option is found in the public key.
func ReadKeyFileWithPolicy(fileName string) (crypto.Signer, string, error) {
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

// TODO: The ReadPrivateKeyFile function has a misleading name, since
// the key file that is read is not always a private key file but
// sometimes a pubkey? Should the function be renamed to ReadKeyFile?
func ReadPrivateKeyFile(fileName string) (crypto.Signer, error) {
	signer, _, err := ReadKeyFileWithPolicy(fileName)
	return signer, err
}
