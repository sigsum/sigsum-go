// The ssh package implements utilities for ssh wire format and
// signatures.
package ssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"log"
)

func Uint32(x uint32) []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, x)
	return buffer
}

func String(s string) []byte {
	if int64(len(s)) > int64(^uint32(0)) {
		log.Panicf("string too large for ssh, length %d", len(s))
	}
	buffer := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(buffer, uint32(len(s)))
	copy(buffer[4:], s)
	return buffer
}

func SignedDataFromHash(namespace string, hash []byte) []byte {
	if len(hash) != 32 {
		log.Panicf("bad hash length %d", len(hash))
	}
	return bytes.Join([][]byte{
		[]byte("SSHSIG"),
		String(namespace),
		Uint32(0), // Empty reserved string
		String("sha256"),
		Uint32(32), // Length of hash
		hash[:]}, nil)
}

func SignedData(namespace string, msg []byte) []byte {
	h := sha256.Sum256(msg)
	return SignedDataFromHash(namespace, h[:])
}
