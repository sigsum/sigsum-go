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

func ParsePublicEd25519(asciiKey string) (crypto.PublicKey, error) {
	// Split into fields, recognizing exclusively ascii space and TAB
	fields := strings.FieldsFunc(asciiKey, func(c rune) bool {
		return c == ' ' || c == '\t'
	})
	if len(fields) < 2 {
		return crypto.PublicKey{}, fmt.Errorf("invalid public key, splitting line failed")
	}
	keyTypeFieldIdx := 0
	keyFieldIdx := 1
	if strings.HasPrefix(fields[0], "sigsum-policy=") {
		keyTypeFieldIdx++
		keyFieldIdx++
	}
	if fields[keyTypeFieldIdx] != "ssh-ed25519" {
		return crypto.PublicKey{}, fmt.Errorf("unsupported public key type: %v", fields[keyTypeFieldIdx])
	}
	blob, err := base64.StdEncoding.DecodeString(fields[keyFieldIdx])
	if err != nil {
		return crypto.PublicKey{}, err
	}
	return parsePublicEd25519(blob)
}

func FormatPublicEd25519(pub *crypto.PublicKey) string {
	return "ssh-ed25519 " +
		base64.StdEncoding.EncodeToString(serializePublicEd25519(pub)) +
		" sigsum key\n"
}
