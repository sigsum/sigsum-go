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
type signatureType byte

const (
	sigTypeEd25519     signatureType = 0x01
	sigTypeCosignature signatureType = 0x04
)

var ErrUnwantedSignature = errors.New("unwanted signature")

type KeyId [4]byte

func makeKeyId(keyName string, sigType signatureType, publicKey *crypto.PublicKey) (res KeyId) {
	hash := crypto.HashBytes(bytes.Join([][]byte{[]byte(keyName), []byte{0xA, byte(sigType)}, publicKey[:]}, nil))
	copy(res[:], hash[:4])
	return
}

func NewLogKeyId(keyName string, publicKey *crypto.PublicKey) (res KeyId) {
	return makeKeyId(keyName, sigTypeEd25519, publicKey)
}

func NewWitnessKeyId(keyName string, publicKey *crypto.PublicKey) (res KeyId) {
	return makeKeyId(keyName, sigTypeCosignature, publicKey)
}

func writeNoteSignature(w io.Writer, keyName string, sig []byte) error {
	_, err := fmt.Fprintf(w, "\u2014 %s %s\n", keyName, base64.StdEncoding.EncodeToString(sig))
	return err
}

// Input is a single signature line, with no trailing newline
// character. Returns keyname and base64-decoded signature blob.
func parseNoteSignature(line string, blobSize int) (string, []byte, error) {
	fields := strings.Split(line, " ")
	if len(fields) != 3 || fields[0] != "\u2014" {
		return "", nil, fmt.Errorf("invalid signature line %q", line)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return "", nil, fmt.Errorf("invalid base signature on line %q: %v", line, err)
	}
	if len(blob) != blobSize {
		return "", nil, ErrUnwantedSignature
	}
	return fields[1], blob, nil
}

func parseSignatureLine(line, origin string) (KeyId, crypto.Signature, error) {
	name, blob, err := parseNoteSignature(line, 4+crypto.SignatureSize)
	if err != nil {
		return KeyId{}, crypto.Signature{}, err
	}
	if name != origin {
		return KeyId{}, crypto.Signature{}, ErrUnwantedSignature
	}
	var keyId KeyId
	var signature crypto.Signature
	copy(keyId[:], blob[:4])
	copy(signature[:], blob[4:])

	return keyId, signature, nil
}
