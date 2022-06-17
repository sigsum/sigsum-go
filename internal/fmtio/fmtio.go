// package fmtio provides basic utilities to format input and output
package fmtio

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"io/ioutil"
	"os"

	"git.sigsum.org/sigsum-go/pkg/hex"
	"git.sigsum.org/sigsum-go/pkg/types"
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
	b, err := hex.Deserialize(s)
	if err != nil {
		return nil, err
	}
	if n := len(b); n != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid size %d", n)
	}
	return ed25519.NewKeyFromSeed(b), nil
}

func PublicKeyFromHex(s string) (pub types.PublicKey, err error) {
	b, err := hex.Deserialize(s)
	if err != nil {
		return pub, err
	}
	if n := len(b); n != types.PublicKeySize {
		return pub, fmt.Errorf("invalid size %d", n)
	}
	copy(pub[:], b)
	return
}

func KeyHashFromHex(s string) (h types.Hash, err error) {
	b, err := hex.Deserialize(s)
	if err != nil {
		return h, err
	}
	if n := len(b); n != types.HashSize {
		return h, fmt.Errorf("invalid size %d", n)
	}
	copy(h[:], b)
	return
}

func SignatureFromHex(s string) (sig types.Signature, err error) {
	b, err := hex.Deserialize(s)
	if err != nil {
		return sig, err
	}
	if n := len(b); n != types.SignatureSize {
		return sig, fmt.Errorf("invalid size %d", n)
	}
	copy(sig[:], b)
	return
}
