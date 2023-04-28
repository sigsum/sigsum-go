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
	"encoding/binary"
	"log"
	"math"

	"sigsum.org/sigsum-go/pkg/crypto"
)

type bytesOrString interface{ []byte | string }

func serializeUint32(x uint32) []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, x)
	return buffer
}

func serializeString[T bytesOrString](s T) []byte {
	if len(s) > math.MaxInt32 {
		log.Panicf("string too large for ssh, length %d", len(s))
	}
	buffer := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(buffer, uint32(len(s)))
	copy(buffer[4:], s)
	return buffer
}

func signedDataFromHash(namespace string, hash *crypto.Hash) []byte {
	return bytes.Join([][]byte{
		[]byte("SSHSIG"),
		serializeString(namespace),
		serializeString(""), // Empty reserved string
		serializeString("sha256"),
		serializeString(hash[:])}, nil)
}

// Deprecated; only for backwards compatibility in SignedTreeHead.VerifyVersion0.
func SignedData(namespace string, msg []byte) []byte {
	hash := crypto.HashBytes(msg)
	return signedDataFromHash(namespace, &hash)
}

// Skips prefix, if present, otherwise return nil.
func skipPrefix(buffer []byte, prefix []byte) []byte {
	if !bytes.HasPrefix(buffer, prefix) {
		return nil
	}
	return buffer[len(prefix):]
}

// Skips an ssh-encoded string, including length field.
func skipPrefixString[T bytesOrString](buffer []byte, prefix T) []byte {
	return skipPrefix(buffer, serializeString(prefix))
}

func parseUint32(buffer []byte) (uint32, []byte) {
	if buffer == nil || len(buffer) < 4 {
		return 0, nil
	}
	return binary.BigEndian.Uint32(buffer[:4]), buffer[4:]
}

func parseString(buffer []byte) ([]byte, []byte) {
	length, buffer := parseUint32(buffer)
	if buffer == nil {
		return nil, nil
	}
	if int64(len(buffer)) < int64(length) {
		return nil, nil
	}
	return buffer[:int(length)], buffer[int(length):]
}
