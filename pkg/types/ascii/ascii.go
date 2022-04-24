// package ascii provides ASCII key-value (de)serialization, see §3:
//
//   https://git.sigsum.org/sigsum/plain/doc/api.md
//
// Write key-value pairs to a buffer using the WritePair() method.
//
// Read key-value pairs from a buffer using the ReadPairs() method.  It takes as
// input a function that parses the buffer using a map's Dequeue*() methods.
//
// XXX: add a usage example, until then see TestReadPairs().
//
package ascii

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"

	"git.sigsum.org/sigsum-go/pkg/hex"
)

const (
	EndOfKey   = "="
	EndOfValue = "\n"
)

var (
	endOfKey   = []byte(EndOfKey)
	endOfValue = []byte(EndOfValue)
)

// WritePair writes a key-value pair
func WritePair(w io.Writer, key, value string) error {
	_, err := w.Write(bytes.Join([][]byte{[]byte(key), endOfKey, []byte(value), endOfValue}, nil))
	return err
}

// ReadPairs parses key-value pairs strictly using the provided parse function
func ReadPairs(r io.Reader, parse func(*Map) error) error {
	m, err := newMap(r)
	if err != nil {
		return err
	}
	if err := parse(&m); err != nil {
		return err
	}
	return m.done()
}

// Map is a map of ASCII key-value pairs.  An ASCII key has a list of ASCII
// values.  A value can be dequeued for a key as a certain type.  Call Done()
// after dequeing all expected values to be strict about no redundant values.
type Map map[string][]string

// NumValues returns the number of values for a given key.  If the key does not
// exist, the number of values is per definition zero.
func (m *Map) NumValues(key string) uint64 {
	values, ok := (*m)[key]
	if !ok {
		return 0
	}
	return uint64(len(values))
}

// DequeueString dequeues a string value for a given key.
func (m *Map) DequeueString(key string, str *string) (err error) {
	*str, err = m.dequeue(key)
	if err != nil {
		return fmt.Errorf("dequeue: %w", err)
	}
	return nil
}

// DequeueUint64 dequeues an uint64 value for a given key.
func (m *Map) DequeueUint64(key string, num *uint64) error {
	v, err := m.dequeue(key)
	if err != nil {
		return fmt.Errorf("dequeue: %w", err)
	}
	*num, err = strconv.ParseUint(v, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid uint64: %w", err)
	}
	return nil
}

// DequeueArray dequeues an array value for a given key
func (m *Map) DequeueArray(key string, arr []byte) error {
	v, err := m.dequeue(key)
	if err != nil {
		return fmt.Errorf("dequeue: %w", err)
	}
	b, err := hex.Deserialize(v)
	if err != nil {
		return fmt.Errorf("invalid array: %w", err)
	}
	if n := len(b); n != len(arr) {
		return fmt.Errorf("invalid array size %d", n)
	}
	copy(arr, b)
	return nil
}

// dequeue dequeues a value for a given key
func (m *Map) dequeue(key string) (string, error) {
	_, ok := (*m)[key]
	if !ok {
		return "", fmt.Errorf("missing key %q", key)
	}
	if len((*m)[key]) == 0 {
		return "", fmt.Errorf("missing value for key %q", key)
	}

	value := (*m)[key][0]
	(*m)[key] = (*m)[key][1:]
	return value, nil
}

// done checks that there are no keys with remaining values
func (m *Map) done() error {
	for k, v := range *m {
		if len(v) != 0 {
			return fmt.Errorf("remaining values for key %q", k)
		}
	}
	return nil
}

// newMap parses ASCII-encoded key-value pairs into a map
func newMap(r io.Reader) (m Map, err error) {
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return m, fmt.Errorf("read: %w", err)
	}

	b, err := trimEnd(buf)
	if err != nil {
		return m, fmt.Errorf("malformed input: %w", err)
	}

	m = make(map[string][]string)
	for i, kv := range bytes.Split(b, endOfValue) {
		split := bytes.Split(kv, endOfKey)
		if len(split) == 1 {
			return m, fmt.Errorf("no key-value pair on line %d: %q", i+1, string(kv))
		}

		key := string(split[0])
		value := string(bytes.Join(split[1:], endOfKey))
		if _, ok := m[key]; !ok {
			m[key] = make([]string, 0, 1)
		}
		m[key] = append(m[key], value)
	}

	return m, nil
}

// trimEnd ensures that we can range over the output of a split on endOfValue
// without the last itteration being an empty string.  Note that it would not be
// correct to simply skip the last itteration.  That line could me malformed.
func trimEnd(buf []byte) ([]byte, error) {
	if len(buf) <= len(endOfValue) {
		return nil, fmt.Errorf("buffer contains no key-value pair")
	}
	offset := len(buf) - len(endOfValue)
	if !bytes.Equal(buf[offset:], endOfValue) {
		return nil, fmt.Errorf("buffer must end with %q", EndOfValue)
	}
	return buf[:offset], nil
}
