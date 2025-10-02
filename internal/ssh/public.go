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

// This function checks for policy name option on the form
// sigsum-policy="foo", following the format of option
// specifications found in the "AUTHORIZED_KEYS FILE FORMAT"
// section of the sshd man page
func getPolicy(field string) (string, error) {
	quotedPolicyName, found := strings.CutPrefix(field, "sigsum-policy=")
	if !found {
		return "", nil
	}
	// First and last character must be quotation marks
	if len(quotedPolicyName) < 3 {
		return "", fmt.Errorf("failed to extract policy name from string '%q' - too short", field)
	}
	name, found := strings.CutPrefix(quotedPolicyName, "\"")
	if !found {
		return "", fmt.Errorf("failed to extract policy name from string '%q' - initial quotation mark not found", field)
	}
	name, found = strings.CutSuffix(name, "\"")
	if !found {
		return "", fmt.Errorf("failed to extract policy name from string '%q' - final quotation mark not found", field)
	}
	if strings.ContainsAny(name, "\"'\\ \n") {
		return "", fmt.Errorf("failed to extract policy name from string '%q' - name contains forbidden character", field)
	}
	return name, nil
}

// Returns public key and policy name, in case a "sigsum-policy=" option is found
func ParsePublicEd25519(asciiKey string) (crypto.PublicKey, string, error) {
	// Split into fields, recognizing exclusively ascii space and TAB
	fields := strings.FieldsFunc(asciiKey, func(c rune) bool {
		return c == ' ' || c == '\t'
	})
	if len(fields) < 2 {
		return crypto.PublicKey{}, "", fmt.Errorf("invalid public key, splitting line failed")
	}
	policyName, err := getPolicy(fields[0])
	if err != nil {
		return crypto.PublicKey{}, "", err
	}
	if policyName != "" {
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
