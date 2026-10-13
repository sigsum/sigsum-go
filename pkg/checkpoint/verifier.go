package checkpoint

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
)

type NoteVerifier struct {
	Name      string
	KeyId     KeyId
	Type      SignatureType
	PublicKey crypto.PublicKey
}

func (nv *NoteVerifier) Equal(o *NoteVerifier) bool {
	return nv.Name == o.Name && nv.KeyId == o.KeyId && nv.Type == o.Type && nv.PublicKey.Equal(o.PublicKey)
}
func (nv *NoteVerifier) String() string {
	return fmt.Sprintf("%s+%x+%s", nv.Name, nv.KeyId,
		base64.StdEncoding.EncodeToString(bytes.Join([][]byte{[]byte{byte(nv.Type)}, nv.PublicKey.Bytes()}, nil)))
}

// A note verifier should be parsed as <name>+<hash>+<keydata>
// according to https://pkg.go.dev/golang.org/x/mod/sumdb/note. Note
// that this functions uses the hash as is as the KeyId, no checks
// that it is consistent with the key name and key data.
func (nv *NoteVerifier) FromString(in string) error {
	fields := strings.SplitN(in, "+", 3)
	if len(fields) != 3 {
		return fmt.Errorf("invalid note verifier, too few fields")
	}

	nv.Name = fields[0]

	hash, err := hex.DecodeString(fields[1])
	if err != nil {
		return fmt.Errorf("invalid note verifier: %v", err)
	}
	if got, want := len(hash), len(nv.KeyId); got != want {
		return fmt.Errorf("unexpected hash length: got %d, want %d", got, want)
	}
	copy(nv.KeyId[:], hash)

	blob, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return fmt.Errorf("invalid note verifier: %v", err)
	}

	if len(blob) == 0 {
		return fmt.Errorf("invalid note verifier, empty key data")
	}

	// First byte is the key type.
	nv.Type, blob = SignatureType(blob[0]), blob[1:]

	if nv.Type != SigTypeEd25519 && nv.Type != SigTypeCosignature {
		return fmt.Errorf("unsupported key type 0x%02x", nv.Type)
	}

	if got, want := len(blob), crypto.Ed25519PublicKeySize; got != want {
		return fmt.Errorf("unexpected key blob length: got %d, want %d", got, want)
	}
	var pub crypto.Ed25519PublicKey
	copy(pub[:], blob)
	nv.PublicKey = &pub
	return nil
}

func NewNoteVerifier(keyName string, keyType SignatureType, publicKey crypto.PublicKey) NoteVerifier {
	return NoteVerifier{
		Name:      keyName,
		Type:      keyType,
		KeyId:     NewKeyId(keyName, keyType, publicKey),
		PublicKey: publicKey,
	}
}
