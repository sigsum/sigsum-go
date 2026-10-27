// package crypto provides lowest-level crypto types and primitives used by sigsum
package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

const HashSize = sha256.Size

type Hash [HashSize]byte

type Signer interface {
	Sign([]byte) (Ed25519Signature, error)
	Public() Ed25519PublicKey
}

func HashBytes(b []byte) Hash {
	return sha256.Sum256(b)
}

func HashFile(f io.Reader) (digest Hash, err error) {
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return
	}
	copy(digest[:], h.Sum(nil))
	return
}

func decodeHex(out []byte, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != len(out) {
		return fmt.Errorf("unexpected length of hex data, expected %d, got %d", len(out), len(b))
	}
	copy(out, b)
	return nil
}

func HashFromHex(s string) (h Hash, err error) {
	err = decodeHex(h[:], s)
	return
}

func decodeBase64(out []byte, s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != len(out) {
		return fmt.Errorf("unexpected length of base data, expected %d, got %d", len(out), len(b))
	}
	copy(out, b)
	return nil
}

func HashFromBase64(s string) (h Hash, err error) {
	err = decodeBase64(h[:], s)
	return
}

func AttachNamespace(namespace string, msg []byte) []byte {
	return bytes.Join([][]byte{[]byte(namespace), msg}, []byte{0})
}
