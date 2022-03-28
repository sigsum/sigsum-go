package types

import (
	"encoding/binary"
)

// RFC4251, section 5

func putSSHString(b []byte, str string) int {
	l := len(str)

	i := 0
	binary.BigEndian.PutUint32(b[i:i+4], uint32(l))
	i += 4
	copy(b[i:i+l], str)
	i += l

	return i
}
