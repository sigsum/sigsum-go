// package trunnel provides selected Trunnel primitives, see:
//
//   - https://gitlab.torproject.org/tpo/core/trunnel/-/blob/main/doc/trunnel.md
package trunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func Uint64(buf *bytes.Buffer, num *uint64) error {
	if err := binary.Read(buf, binary.BigEndian, num); err != nil {
		return fmt.Errorf("uint64: %w", err)
	}
	return nil
}

func Array(buf *bytes.Buffer, arr []byte) error {
	if _, err := io.ReadFull(buf, arr); err != nil {
		return fmt.Errorf("array[%d]: %w", len(arr), err)
	}
	return nil
}

func AddUint64(buf *bytes.Buffer, num uint64) {
	binary.Write(buf, binary.BigEndian, num)
}

func AddArray(buf *bytes.Buffer, arr []byte) {
	buf.Write(arr[:])
}
