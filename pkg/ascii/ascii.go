// package ascii implements an ASCII key-value parser.
//
// The top-most (de)serialize must operate on a struct pointer.  A struct may
// contain other structs, in which case all tag names should be unique.  Public
// fields without tag names are ignored.  Private fields are also ignored.
//
// The supported field types are:
// - struct
// - string (no empty strings)
// - uint64 (only digits in ASCII representation)
// - byte array (only lower-case hex in ASCII representation)
// - slice of uint64 (no empty slices)
// - slice of byte array (no empty slices)
//
// A key must not contain an encoding's end-of-key value.
// A value must not contain an encoding's end-of-value value.
//
// For additional details, please refer to the Sigsum v0 API documentation.
//
package ascii

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"strconv"
	"strings"

	"git.sigsum.org/sigsum-go/pkg/hex"
)

var StdEncoding = NewEncoding("ascii", "=", "\n")

type Encoding struct {
	identifier string
	endOfKey   string
	endOfValue string
}

func NewEncoding(id, eok, eov string) *Encoding {
	return &Encoding{
		identifier: id,
		endOfKey:   eok,
		endOfValue: eov,
	}
}

type someValue struct {
	v  reflect.Value
	ok bool
}

// Serialize tries to serialize an interface as ASCII key-value pairs
func (e *Encoding) Serialize(w io.Writer, i interface{}) error {
	v, err := dereferenceStructPointer(i)
	if err != nil {
		return err
	}

	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		switch v.Field(i).Type().Kind() {
		case reflect.Struct:
			if err := e.Serialize(w, v.Field(i).Addr().Interface()); err != nil {
				return err
			}
		default:
			if t.Field(i).PkgPath != "" {
				continue // skip private field
			}
			key, ok := t.Field(i).Tag.Lookup(e.identifier)
			if !ok {
				continue // skip public field without tag
			}

			if strings.Contains(key, e.endOfKey) {
				return fmt.Errorf("ascii: key %q contains end-of-key character", key)
			}
			if err := e.write(w, key, v.Field(i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *Encoding) write(w io.Writer, key string, v reflect.Value) error {
	t := v.Type()
	switch t {
	case reflect.TypeOf(uint64(0)):
		val := fmt.Sprintf("%d", v.Uint())
		return e.writeOne(w, key, val)
	}

	k := t.Kind()
	switch k {
	case reflect.Array:
		if kind := t.Elem().Kind(); kind != reflect.Uint8 {
			return fmt.Errorf("ascii: array kind not supported: %v", kind)
		}

		arrayLen := v.Len()
		array := make([]byte, arrayLen, arrayLen)
		for i := 0; i < arrayLen; i++ {
			array[i] = uint8(v.Index(i).Uint())
		}

		val := hex.Serialize(array)
		return e.writeOne(w, key, val)

	case reflect.Slice:
		kind := t.Elem().Kind()
		if kind != reflect.Array && kind != reflect.Uint64 {
			return fmt.Errorf("ascii: slice kind not supported: %v", kind)
		}
		if v.Len() == 0 {
			return fmt.Errorf("ascii: slice must not be empty")
		}

		var err error
		for i := 0; i < v.Len(); i++ {
			err = e.write(w, key, v.Index(i))
		}
		return err

	case reflect.String:
		if v.Len() == 0 {
			return fmt.Errorf("ascii: string must not be empty")
		}
		return e.writeOne(w, key, v.String())
	}

	return fmt.Errorf("ascii: unsupported type %v and kind %v", t, k)
}

func (e *Encoding) writeOne(w io.Writer, key, value string) error {
	_, err := w.Write([]byte(key + e.endOfKey + value + e.endOfValue))
	return err
}

// Deserialize tries to deserialize a buffer of ASCII key-value pairs
func (e *Encoding) Deserialize(r io.Reader, i interface{}) error {
	m := make(map[string]*someValue)
	if err := e.mapKeys(i, m); err != nil {
		return err
	}

	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return fmt.Errorf("ascii: failed reading incoming buffer")
	}

	// trim end of buffer so that loop does not run on an empty line
	if len(buf) <= len(e.endOfValue) {
		return fmt.Errorf("ascii: buffer contains no key-value pair")
	}
	offset := len(buf) - len(e.endOfValue)
	if !bytes.Equal(buf[offset:], []byte(e.endOfValue)) {
		return fmt.Errorf("ascii: buffer must end with endOfValue")
	}
	buf = buf[:offset]

	for _, kv := range bytes.Split(buf, []byte(e.endOfValue)) {
		split := bytes.Split(kv, []byte(e.endOfKey))
		if len(split) == 1 {
			return fmt.Errorf("ascii: missing key-value pair in %q", string(kv))
		}

		key := string(split[0])
		value := string(bytes.Join(split[1:], nil))
		ref, ok := m[key]
		if !ok {
			return fmt.Errorf("ascii: unexpected key %q", key)
		}
		if len(value) == 0 {
			fmt.Errorf("ascii: missing value for key %q", key)
		}
		if err := setKey(ref, key, value); err != nil {
			return err
		}
	}
	return requireValues(m)
}

func (e *Encoding) mapKeys(i interface{}, m map[string]*someValue) error {
	v, err := dereferenceStructPointer(i)
	if err != nil {
		return err
	}

	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		switch v.Field(i).Type().Kind() {
		case reflect.Struct:
			i := v.Field(i).Addr().Interface()
			e.mapKeys(i, m) // return is always nil
		default:
			if t.Field(i).PkgPath != "" {
				continue // skip private field
			}
			key, ok := t.Field(i).Tag.Lookup(e.identifier)
			if !ok {
				continue // skip public field without tag
			}
			m[key] = &someValue{
				v: v.Field(i),
			}
		}
	}
	return nil
}

func setKey(ref *someValue, key, value string) error {
	v := ref.v
	if v.Kind() == reflect.Ptr && !v.IsNil() {
		v = v.Elem()
	}

	t := v.Type()
	switch t {
	case reflect.TypeOf(uint64(0)):
		num, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return err
		}

		ref.ok = true
		v.SetUint(num)
		return nil
	}

	k := t.Kind()
	switch k {
	case reflect.Array:
		arrayLen := v.Len()
		b, err := hex.Deserialize(value)
		if err != nil {
			return err
		}
		if len(b) != arrayLen {
			return fmt.Errorf("ascii: invalid array size for key %q", key)
		}

		ref.ok = true
		reflect.Copy(v, reflect.ValueOf(b))
		return nil

	case reflect.Slice:
		sliceType := t
		kind := sliceType.Elem().Kind()
		if kind != reflect.Array && kind != reflect.Uint64 {
			return fmt.Errorf("ascii: slice kind not supported: %v", kind)
		}

		if v.IsNil() {
			v.Set(reflect.MakeSlice(sliceType, 0, 0))
		}
		sv := &someValue{
			v: reflect.New(sliceType.Elem()),
		}
		if err := setKey(sv, key, value); err != nil {
			return err
		}

		ref.ok = true
		v.Set(reflect.Append(v, sv.v.Elem()))
		return nil

	case reflect.String:
		if len(value) == 0 {
			return fmt.Errorf("ascii: string must not be empty")
		}

		ref.ok = true
		v.SetString(value)
		return nil
	}

	return fmt.Errorf("ascii: unsupported type %v and kind %v", t, k)
}

func requireValues(m map[string]*someValue) error {
	for k, v := range m {
		if !v.ok {
			return fmt.Errorf("ascii: missing value for key %q", k)
		}
	}
	return nil
}

func dereferenceStructPointer(i interface{}) (*reflect.Value, error) {
	v := reflect.ValueOf(i)
	if v.Kind() != reflect.Ptr {
		return nil, fmt.Errorf("ascii: interface value must be pointer")
	}
	if v.IsNil() {
		return nil, fmt.Errorf("ascii: interface value must be non-nil pointer")
	}
	v = v.Elem()
	if v.Type().Kind() != reflect.Struct {
		return nil, fmt.Errorf("ascii: interface value must point to struct")
	}
	return &v, nil
}
