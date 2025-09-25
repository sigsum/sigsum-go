package ssh

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func serializePublicEd25519(pub *crypto.PublicKey) []byte {
	return bytes.Join([][]byte{
		serializeString("ssh-ed25519"),
		serializeString(pub[:])},
		nil)
}

func parsePublicEd25519(blob []byte) (crypto.PublicKey, error) {
	pub := skipPrefix(blob, bytes.Join([][]byte{
		serializeString("ssh-ed25519"),
		serializeUint32(crypto.PublicKeySize),
	}, nil))

	if pub == nil {
		return crypto.PublicKey{}, fmt.Errorf("invalid public key blob prefix")
	}
	if len(pub) != crypto.PublicKeySize {
		return crypto.PublicKey{}, fmt.Errorf("invalid public key length: %v", len(blob))
	}
	var ret crypto.PublicKey
	copy(ret[:], pub)
	return ret, nil
}

// s is a string on the form sigsum-policy="foo"
func extractPolicyName(s string) (string, error) {
	i := strings.IndexRune(s, '=')
	quotedName := s[i+1:]
	// First and last character must be quotation marks
	if quotedName[0] != '"' || quotedName[len(quotedName)-1] != '"' {
		return "", fmt.Errorf("failed to extract policy name")
	}
	return quotedName[1 : len(quotedName)-1], nil
}

func ParsePublicEd25519(asciiKey string) (crypto.PublicKey, error) {
	key, _, err := ParsePublicEd25519WithPolicyName(asciiKey)
	return key, err
}

// Returns public key and policy name, in case a "sigsum-policy=" option is found
func ParsePublicEd25519WithPolicyName(asciiKey string) (crypto.PublicKey, string, error) {
	// Split into fields, recognizing exclusively ascii space and TAB
	fields := strings.FieldsFunc(asciiKey, func(c rune) bool {
		return c == ' ' || c == '\t'
	})
	if len(fields) < 2 {
		return crypto.PublicKey{}, "", fmt.Errorf("invalid public key, splitting line failed")
	}
	policyName := ""
	if strings.HasPrefix(fields[0], "sigsum-policy=") {
		var err error
		policyName, err = extractPolicyName(fields[0])
		if err != nil {
			return crypto.PublicKey{}, "", err
		}
		// Remove the "sigsum-policy=" field
		fields = fields[1:]
	}
	if fields[0] != "ssh-ed25519" {
		return crypto.PublicKey{}, "", fmt.Errorf("unsupported public key type: %v", fields[0])
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return crypto.PublicKey{}, "", err
	}
	pubkey, err := parsePublicEd25519(blob)
	return pubkey, policyName, err
}

func FormatPublicEd25519(pub *crypto.PublicKey) string {
	return "ssh-ed25519 " +
		base64.StdEncoding.EncodeToString(serializePublicEd25519(pub)) +
		" sigsum key\n"
}
