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

// Skips prefix, if present, otherwise return nil.
func skipPrefix(buffer []byte, prefix []byte) []byte {
	if !bytes.HasPrefix(buffer, prefix) {
		return nil
	}
	return buffer[len(prefix):]
}
func skipPrefixString(buffer []byte, prefix []byte) []byte {
	return skipPrefix(buffer, serializeString(prefix))
}
