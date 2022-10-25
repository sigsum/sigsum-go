// The ssh package implements utilities for ssh wire format and
// signatures.
package ssh

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
)

const (
	int32Max = (1 << 31) - 1
)

func serializeUint32(x uint32) []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, x)
	return buffer
}

func serializeString(s []byte) []byte {
	if len(s) > int32Max {
		log.Panicf("string too large for ssh, length %d", len(s))
	}
	buffer := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(buffer, uint32(len(s)))
	copy(buffer[4:], s)
	return buffer
}

func SignedDataFromHash(namespace string, hash *crypto.Hash) []byte {
	return bytes.Join([][]byte{
		[]byte("SSHSIG"),
		serializeString([]byte(namespace)),
		serializeString([]byte{}), // Empty reserved string
		serializeString([]byte("sha256")),
		serializeString(hash[:])}, nil)
}

func SignedData(namespace string, msg []byte) []byte {
	hash := crypto.HashBytes(msg)
	return SignedDataFromHash(namespace, &hash)
}

func serializePublicEd25519(pub []byte) []byte {
	if len(pub) != 32 {
		log.Panicf("invalid ed25519 public key, got size %d", len(pub))
	}
	return bytes.Join([][]byte{
		serializeString([]byte("ssh-ed25519")),
		serializeString(pub)},
		nil)
}

// Skips prefix, if present, otherwise return nil.
func skipPrefix(buffer []byte, prefix []byte) []byte {
	if !bytes.HasPrefix(buffer, prefix) {
		return nil
	}
	return buffer[len(prefix):]
}

func parseSignature(blob []byte) ([]byte, error) {
	signature := skipPrefix(blob, bytes.Join([][]byte{
		serializeUint32(83), // length of signature
		serializeString([]byte("ssh-ed25519")),
		serializeUint32(64)}, nil))
	if signature == nil {
		return nil, fmt.Errorf("invalid signature blob")
	}
	if len(signature) != 64 {
		return nil, fmt.Errorf("bad signature length: %d", len(signature))
	}
	// Short and exclusively owned, no need to copy.
	return signature, nil
}

func ParsePublicEd25519(asciiKey string) ([]byte, error) {
	// Split into fields, recognizing exclusively ascii space and TAB
	fields := strings.FieldsFunc(asciiKey, func(c rune) bool {
		return c == ' ' || c == '\t'
	})
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid public key, splitting line failed")
	}
	if fields[0] != "ssh-ed25519" {
		return nil, fmt.Errorf("unsupported public key type: %v", fields[0])
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, err
	}
	pub := skipPrefix(blob, bytes.Join([][]byte{
		serializeString([]byte("ssh-ed25519")),
		serializeUint32(32),
	}, nil))

	if pub == nil {
		return nil, fmt.Errorf("invalid public key blob prefix")
	}
	if len(pub) != 32 {
		return nil, fmt.Errorf("invalid public key length: %v", len(blob))
	}
	// Short and exclusively owned, no need to copy.
	return pub, nil
}
