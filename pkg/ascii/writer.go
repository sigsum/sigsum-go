package ascii

import (
	"encoding/hex"
	"fmt"
	"io"
	"strconv"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func WriteLine(w io.Writer, key, value string) error {
	_, err := fmt.Fprintf(w, "%s=%s\n", key, value)
	return err
}

func WriteLineHex(w io.Writer, key string, first []byte, rest ...[]byte) error {
	_, err := fmt.Fprintf(w, "%s=%s", key, hex.EncodeToString(first))
	if err != nil {
		return err
	}
	for _, b := range rest {
		_, err := fmt.Fprintf(w, " %s", hex.EncodeToString(b))
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(w, "\n")
	return err
}

func WriteInt(w io.Writer, name string, i uint64) error {
	if i >= (1 << 63) {
		return fmt.Errorf("out of range negative number: %d", i)
	}
	return WriteLine(w, name, strconv.FormatUint(i, 10))
}

func WriteHash(w io.Writer, name string, h *crypto.Hash) error {
	return WriteLineHex(w, name, (*h)[:])
}

func WritePublicKey(w io.Writer, name string, k *crypto.PublicKey) error {
	return WriteLineHex(w, name, (*k)[:])
}

func WriteSignature(w io.Writer, name string, s *crypto.Signature) error {
	return WriteLineHex(w, name, (*s)[:])
}
