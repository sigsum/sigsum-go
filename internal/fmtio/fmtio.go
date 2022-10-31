// package fmtio provides basic utilities to format input and output
package fmtio

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

func BytesFromStdin() ([]byte, error) {
	b, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// StringFromStdin reads bytes from stdin, parsing them as a string without
// leading and trailing white space
func StringFromStdin() (string, error) {
	b, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(b)), nil
}

func SignerFromHex(s string) (crypto.Signer, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if n := len(b); n != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid size %d", n)
	}
	return ed25519.NewKeyFromSeed(b), nil
}
