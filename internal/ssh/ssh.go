// The ssh package implements utilities for working with SSH formats.
//
// The way values are serialized in SSH is documented in
// https://www.rfc-editor.org/rfc/rfc4251#section-5.
//
// Use of ED25519 keys is specified in https://www.rfc-editor.org/rfc/rfc8709
//
// There are also a few openssh-specific formats (outside of the IETF standards).
//
// The SSH signature format adopted by sigsum is documented at
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig.
//
// The ssh-agent protocol is documented at
// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent.
//
// The private key format used by openssh is documented at
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key

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

func serializePublicEd25519(pub *crypto.PublicKey) []byte {
	return bytes.Join([][]byte{
		serializeString([]byte("ssh-ed25519")),
		serializeString(pub[:])},
		nil)
}

// Skips prefix, if present, otherwise return nil.
func skipPrefix(buffer []byte, prefix []byte) []byte {
	if !bytes.HasPrefix(buffer, prefix) {
		return nil
	}
	return buffer[len(prefix):]
}

func parseSignature(blob []byte) (crypto.Signature, error) {
	signature := skipPrefix(blob, bytes.Join([][]byte{
		serializeUint32(83), // length of signature
		serializeString([]byte("ssh-ed25519")),
		serializeUint32(crypto.SignatureSize)}, nil))
	if signature == nil {
		return crypto.Signature{}, fmt.Errorf("invalid signature blob")
	}
	if len(signature) != crypto.SignatureSize {
		return crypto.Signature{}, fmt.Errorf("bad signature length: %d", len(signature))
	}
	var ret crypto.Signature
	copy(ret[:], signature)
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
	if fields[0] != "ssh-ed25519" {
		return crypto.PublicKey{}, fmt.Errorf("unsupported public key type: %v", fields[0])
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return crypto.PublicKey{}, err
	}
	pub := skipPrefix(blob, bytes.Join([][]byte{
		serializeString([]byte("ssh-ed25519")),
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
