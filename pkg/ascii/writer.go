package ascii

import (
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func writeItem(w io.Writer, item interface{}) error {
	switch item := item.(type) {
	case []byte:
		_, err := fmt.Fprintf(w, "%x", item)
		return err
	case uint64:
		if item >= (1 << 63) {
			return fmt.Errorf("out of range number: %d", item)
		}
		_, err := fmt.Fprintf(w, "%d", item)
		return err
	default:
		return fmt.Errorf("unsupported type: %t", item)
	}
}

func WriteLine(w io.Writer, key string, first interface{}, rest ...interface{}) error {
	_, err := fmt.Fprintf(w, "%s=", key)
	if err != nil {
		return err
	}
	if err := writeItem(w, first); err != nil {
		return err
	}
	for _, i := range rest {
		fmt.Fprintf(w, " ")
		if err := writeItem(w, i); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(w, "\n")
	return err
}

// Helpers with better type safety.

func WriteInt(w io.Writer, name string, i uint64) error {
	return WriteLine(w, name, i)
}

func WriteHash(w io.Writer, name string, h *crypto.Hash) error {
	return WriteLine(w, name, (*h)[:])
}

func WritePublicKey(w io.Writer, name string, k *crypto.PublicKey) error {
	return WriteLine(w, name, (*k)[:])
}

func WriteSignature(w io.Writer, name string, s *crypto.Signature) error {
	return WriteLine(w, name, (*s)[:])
}
