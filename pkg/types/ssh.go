package types

import (
	"bytes"

	"sigsum.org/key-mgmt/pkg/ssh"
	"sigsum.org/sigsum-go/pkg/crypto"
)

// Old way of signing, based on SSH signature format. Used only for
// the SignedTreeHead.VerifyVersion0 method.
func sshSignedData(namespace string, msg []byte) []byte {
	hash := crypto.HashBytes(msg)
	return bytes.Join([][]byte{
		[]byte("SSHSIG"),
		ssh.SerializeString(namespace),
		ssh.SerializeString(""), // Empty reserved string
		ssh.SerializeString("sha256"),
		ssh.SerializeString(hash[:])}, nil)
}
