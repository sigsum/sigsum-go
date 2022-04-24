// package ssh provides selected parts of the SSH data format, see:
//
//   - https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
//   - https://datatracker.ietf.org/doc/html/rfc4251#section-5
//
package ssh

import (
	"bytes"
	"encoding/binary"
)

// ToSignBlob outputs the raw bytes to be signed for a given namespace and
// message.  The reserved string is empty and the specified hash is SHA256.
func ToSignBlob(namespace string, hashedMessage []byte) []byte {
	buf := bytes.NewBuffer(nil)

	buf.Write([]byte("SSHSIG"))
	addString(buf, namespace)
	addString(buf, "")
	addString(buf, "sha256")
	addString(buf, string(hashedMessage[:]))

	return buf.Bytes()
}

func addUint32(buf *bytes.Buffer, num uint32) {
	binary.Write(buf, binary.BigEndian, num)
}

func addString(buf *bytes.Buffer, str string) {
	addUint32(buf, uint32(len(str)))
	buf.Write([]byte(str))
}
