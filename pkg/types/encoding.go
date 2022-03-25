package types

import (
	"encoding/binary"
	"fmt"
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

func getSSHString(b []byte) (*string, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("types: invalid SSH string")
	}

	l := binary.BigEndian.Uint32(b[:4])
	str := string(b[4 : 4+l])
	return &str, nil

}
