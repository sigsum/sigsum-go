// package hex implements a lower-case hex parser.
package hex

import (
	"fmt"
)

const (
	language = "0123456789abcdef"
)

// Serialize serializes a buffer as lower-case hex
func Serialize(buf []byte) string {
	out := make([]byte, len(buf)*2)
	for i, b := range buf {
		offset := i * 2
		out[offset] = language[b>>4]
		out[offset+1] = language[b&0x0f]
	}
	return string(out)
}

// Deserialize tries to deserialize a lower-case hex string
func Deserialize(str string) ([]byte, error) {
	if len(str)%2 != 0 {
		return nil, fmt.Errorf("hex: string must have even length")
	}

	buf := make([]byte, len(str)/2)
	for i := 0; i < len(buf); i++ {
		offset := i * 2
		first, ok := deserializeOne(str[offset])
		if !ok {
			return nil, fmt.Errorf("hex: invalid character at index %d: %d", i, first)
		}
		second, ok := deserializeOne(str[offset+1])
		if !ok {
			return nil, fmt.Errorf("hex: invalid character at index %d: %d", i, second)
		}
		buf[i] = first << 4
		buf[i] = buf[i] | second
	}
	return buf, nil
}

func deserializeOne(b byte) (byte, bool) {
	if b >= '0' && b <= '9' {
		return b - '0', true
	}
	if b >= 'a' && b <= 'f' {
		return b - 'a' + 10, true
	}
	return 0, false
}
