package checkpoint

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
)

// See https://github.com/C2SP/C2SP/blob/signed-note/v1.0.0-rc.1/signed-note.md
type SignatureType byte

const (
	SigTypeEd25519     SignatureType = 0x01
	SigTypeCosignature SignatureType = 0x04
)

var ErrUnwantedSignature = errors.New("unwanted signature")

type KeyId [4]byte

func NewKeyId(keyName string, sigType SignatureType, publicKey *crypto.PublicKey) (res KeyId) {
	hash := crypto.HashBytes(bytes.Join([][]byte{[]byte(keyName), []byte{0xA, byte(sigType)}, publicKey[:]}, nil))
	copy(res[:], hash[:4])
	return
}

func NewLogKeyId(keyName string, publicKey *crypto.PublicKey) (res KeyId) {
	return NewKeyId(keyName, SigTypeEd25519, publicKey)
}

func NewWitnessKeyId(keyName string, publicKey *crypto.PublicKey) (res KeyId) {
	return NewKeyId(keyName, SigTypeCosignature, publicKey)
}

func writeNoteSignature(w io.Writer, keyName string, keyId KeyId, signature []byte) error {
	_, err := fmt.Fprintf(w, "\u2014 %s %s\n", keyName,
		base64.StdEncoding.EncodeToString(bytes.Join([][]byte{keyId[:], signature[:]}, nil)))
	return err
}

// Input is a single signature line, with no trailing newline
// character. Returns key name, key id and base64-decoded signature blob.
func parseNoteSignature(line string, signatureSize int) (string, KeyId, []byte, error) {
	fields := strings.Split(line, " ")
	if len(fields) != 3 || fields[0] != "\u2014" {
		return "", KeyId{}, nil, fmt.Errorf("invalid signature line %q", line)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return "", KeyId{}, nil, err
	}
	if len(blob) != 4+signatureSize {
		return "", KeyId{}, nil, ErrUnwantedSignature
	}
	var keyId KeyId
	copy(keyId[:], blob[:4])
	return fields[1], keyId, blob[4:], nil
}

func WriteEd25519Signature(w io.Writer, origin string, keyId KeyId, signature *crypto.Signature) error {
	return writeNoteSignature(w, origin, keyId, signature[:])
}

// Input is a single signature line, with no trailing newline
// character. If the line carries the right keyName and has a size
// consistent with an Ed25519 signature line, returns the keyId and
// signature. If line is syntactically valid but doesn't match these
// requirements, ErrUnwantedSignature is returned.
func ParseEd25519SignatureLine(line, keyName string) (KeyId, crypto.Signature, error) {
	name, keyId, blob, err := parseNoteSignature(line, crypto.SignatureSize)
	if err != nil {
		return KeyId{}, crypto.Signature{}, err
	}
	if name != keyName {
		return KeyId{}, crypto.Signature{}, ErrUnwantedSignature
	}
	var signature crypto.Signature
	copy(signature[:], blob)

	return keyId, signature, nil
}
