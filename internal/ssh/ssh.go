// The ssh package implements utilities for ssh wire format and
// signatures.
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
