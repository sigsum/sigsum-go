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
	"fmt"
	"io"
	"log"
	"math"
)

// Arbitrary maximum read size for readString
const readStringMaxSize = 20000

type bytesOrString interface{ ~[]byte | string }

func serializeUint32(x uint32) []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, x)
	return buffer
}

func serializeString[T bytesOrString](s T) []byte {
	if len(s) > math.MaxInt32 {
		log.Panicf("string too large for ssh, length %d", len(s))
	}
	buffer := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(buffer, uint32(len(s)))
	copy(buffer[4:], s)
	return buffer
}

func readBytes(r io.Reader, size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func readUint32(r io.Reader) (uint32, error) {
	lenBuf, err := readBytes(r, 4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(lenBuf), nil
}

func readString(r io.Reader) ([]byte, error) {
	len, err := readUint32(r)
	if err != nil {
		return nil, err
	}
	if len > readStringMaxSize {
		return nil, fmt.Errorf("length %d exceeds max %d", len, readStringMaxSize)
	}
	return readBytes(r, int(len))
}

func readStringOfLength(r io.Reader, len int) ([]byte, error) {
	if err := readSkip(r, serializeUint32(uint32(len))); err != nil {
		return nil, fmt.Errorf("expected length %d: %w", len, err)
	}
	return readBytes(r, len)
}

// Reads and skips raw prefix.
func readSkip(r io.Reader, prefix []byte) error {
	buf, err := readBytes(r, len(prefix))
	if err != nil {
		return err
	}
	if !bytes.Equal(buf, prefix) {
		return fmt.Errorf("unexpected data: %x", buf)
	}
	return nil
}

// Apply a reader function to a byte slice. Requires that the reader
// consumes all bytes, except for optional padding bytes.
func parseBytes[T any](blob []byte, padding []byte, reader func(io.Reader) (T, error)) (T, error) {
	buf := bytes.NewBuffer(blob)
	res, err := reader(buf)
	if err != nil {
		return res, err
	}
	leftOver := buf.Bytes()
	if len(leftOver) > len(padding) {
		return res, fmt.Errorf("trailing %d bytes of garbage", len(leftOver))
	}
	if !bytes.Equal(leftOver, padding[:len(leftOver)]) {
		return res, fmt.Errorf("unexpected padding bytes: %x", leftOver)
	}
	return res, nil
}
