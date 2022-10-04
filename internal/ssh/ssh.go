// The ssh package implements utilities for ssh wire format and
// signatures.
package ssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"log"
)

const (
	int32Max = (1<<31) - 1
)

func Uint32(x uint32) []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, x)
	return buffer
}

func String(s string) []byte {
	if len(s) > int32Max {
		log.Panicf("string too large for ssh, length %d", len(s))
	}
	buffer := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(buffer, uint32(len(s)))
	copy(buffer[4:], s)
	return buffer
}

func SignedDataFromHash(namespace string, hash [sha256.Size]byte) []byte {
	return bytes.Join([][]byte{
		[]byte("SSHSIG"),
		String(namespace),
		String(""), // Empty reserved string
		String("sha256"),
		String(string(hash[:]))}, nil)
}

func SignedData(namespace string, msg []byte) []byte {
	return SignedDataFromHash(namespace, sha256.Sum256(msg))
}
