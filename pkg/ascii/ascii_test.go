package ascii

import (
	"bytes"
	"reflect"
	"testing"
)

type testStruct struct {
	Num    uint64 `ascii/test:"num"`
	Struct testStructOther
	Skip   uint64
	skip   uint64
}

type testStructOther struct {
	Array  testArray   `ascii/test:"array"`
	Slice  []testArray `ascii/test:"slice"`
	String string      `ascii/test:"string"`
}

type testArray [2]byte

type testStructUnsupportedType struct {
	ByteSlice []byte `ascii/test:"byte_slice"`
}

func TestSerialize(t *testing.T) {
	e := NewEncoding("ascii/test", "<--", ";;")
	for _, table := range []struct {
		desc string
		want string
		err  bool
		i    interface{}
	}{
		{
			desc: "invalid: not pointer to struct",
			err:  true,
			i:    testStruct{},
		},
		{
			desc: "invalid: struct with invalid key",
			err:  true,
			i: &struct {
				Num uint64 `ascii/test:"num<--nom"`
			}{
				Num: 1,
			},
		},
		{
			desc: "invalid: struct with invalid type",
			err:  true,
			i: &testStructUnsupportedType{
				ByteSlice: []byte("hellow"),
			},
		},
		{
			desc: "invalid: struct with invalid type and kind",
			err:  true,
			i: &struct {
				Struct testStructUnsupportedType
			}{
				Struct: testStructUnsupportedType{
					ByteSlice: []byte("hellow"),
				},
			},
		},
		{
			desc: "valid",
			want: "num<--1;;array<--01fe;;slice<--01fe;;slice<--00ff;;string<--hellow;;",
			i: &testStruct{
				Num: 1,
				Struct: testStructOther{
					Array: testArray{1, 254},
					Slice: []testArray{
						testArray{1, 254},
						testArray{0, 255},
					},
					String: "hellow",
				},
			},
		},
	} {
		b := bytes.NewBuffer(nil)
		err := e.Serialize(b, table.i)
		if got, want := err != nil, table.err; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := string(b.Bytes()), table.want; got != want {
			t.Errorf("got buf %s but wanted %s in test %q", got, want, table.desc)
		}
	}
}

func TestWrite(t *testing.T) {
	e := NewEncoding("ascii/test", "<--", ";;")
	for _, table := range []struct {
		desc string
		want string
		err  bool
		i    interface{}
	}{
		{
			desc: "invalid: array with wrong type",
			err:  true,
			i:    [2]string{"first", "second"},
		},
		{
			desc: "invalid: slice with wrong type",
			err:  true,
			i:    []string{"first", "second"},
		},
		{
			desc: "invalid: empty slice with right type",
			err:  true,
			i:    make([][2]byte, 0),
		},
		{
			desc: "invalid: empty string",
			err:  true,
			i:    "",
		},
		{
			desc: "invalid: unsupported type and kind",
			err:  true,
			i:    int32(0),
		},
		{
			desc: "valid: uint64",
			want: "some key<--1;;",
			i:    uint64(1),
		},
		{
			desc: "valid: byte array",
			want: "some key<--01fe;;",
			i:    [2]byte{1, 254},
		},
		{
			desc: "valid: slice array",
			want: "some key<--01fe;;some key<--00ff;;",
			i: [][2]byte{
				[2]byte{1, 254},
				[2]byte{0, 255},
			},
		},
		{
			desc: "valid: slice uint64",
			want: "some key<--1;;some key<--2;;",
			i:    []uint64{1, 2},
		},
		{
			desc: "valid: string",
			want: "some key<--some value;;",
			i:    "some value",
		},
	} {
		buf := bytes.NewBuffer(nil)
		err := e.write(buf, "some key", reflect.ValueOf(table.i))
		if got, want := err != nil, table.err; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := string(buf.Bytes()), table.want; got != want {
			t.Errorf("got buf %s but wanted %s in test %q", got, want, table.desc)
		}
	}
}

func TestWriteOne(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	e := NewEncoding("ascii/test", "<--", ";;")
	e.writeOne(buf, "some key", "some value")
	want := "some key<--some value;;"
	if got := string(buf.Bytes()); got != want {
		t.Errorf("got buf %s but wanted %s", got, want)
	}
}

func TestDeserialize(t *testing.T) {
	e := NewEncoding("ascii/test", "<--", ";;")
	for _, table := range []struct {
		desc string
		buf  string
		want interface{}
		err  bool
	}{
		{
			desc: "invalid: interface must be pointer to struct",
			buf:  ";",
			want: uint64(0),
			err:  true,
		},
		{
			desc: "invalid: buffer too small",
			buf:  ";",
			want: testStruct{},
			err:  true,
		},
		{
			desc: "invalid: buffer must end with endOfValue",
			buf:  "num<--1;;string<--hellow;;array<--01fe;;slice<--01fe;;slice<--00ff^^",
			want: testStruct{},
			err:  true,
		},
		{
			desc: "invalid: missing key num",
			buf:  "string<--hellow;;array<--01fe;;slice<--01fe;;slice<--00ff;;",
			want: testStruct{},
			err:  true,
		},
		{
			desc: "invalid: missing key-value pair on num line",
			buf:  "string<--hellow;;num;;array<--01fe;;slice<--01fe;;slice<--00ff;;",
			want: testStruct{},
			err:  true,
		},
		{
			desc: "invalid: missing value for key num",
			buf:  "num<--;;string<--hellow;;array<--01fe;;slice<--01fe;;slice<--00ff;;",
			want: testStruct{},
			err:  true,
		},
		{
			desc: "invalid: value for key num must be digits only",
			buf:  "num<--+1;;string<--hellow;;array<--01fe;;slice<--01fe;;slice<--00ff;;",
			want: testStruct{},
			err:  true,
		},
		{
			desc: "invalid: missing field for key num2",
			buf:  "num<--1;;string<--hellow;;num2<--2;;array<--01fe;;slice<--01fe;;slice<--00ff;;",
			want: testStruct{},
			err:  true,
		},
		{
			desc: "valid",
			buf:  "num<--1;;string<--hellow;;array<--01fe;;slice<--01fe;;slice<--00ff;;",
			want: testStruct{
				Num: 1,
				Struct: testStructOther{
					Array: testArray{1, 254},
					Slice: []testArray{
						testArray{1, 254},
						testArray{0, 255},
					},
					String: "hellow",
				},
			},
		},
	} {
		v := reflect.New(reflect.TypeOf(table.want))
		err := e.Deserialize(bytes.NewBuffer([]byte(table.buf)), v.Interface())
		if got, want := err != nil, table.err; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}

		v = v.Elem() // have pointer to struct, get just struct as in table
		if got, want := v.Interface(), table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got interface %v but wanted %v in test %q", got, want, table.desc)
		}
	}

}

func TestMapKeys(t *testing.T) {
	s := testStruct{}
	m := make(map[string]*someValue)
	e := NewEncoding("ascii/test", "<--", ";;")
	if err := e.mapKeys(s, m); err == nil {
		t.Errorf("expected mapping to fail without pointer")
	}
	if err := e.mapKeys(&s, m); err != nil {
		t.Errorf("expected mapping to succeed")
		return
	}

	wantKeys := []string{"num", "array", "slice", "string"}
	if got, want := len(m), len(wantKeys); got != want {
		t.Errorf("got %d keys, wanted %d", got, want)
	}
	for _, key := range wantKeys {
		if _, ok := m[key]; !ok {
			t.Errorf("expected key %q in map", key)
		}
	}
}

func TestSetKey(t *testing.T) {
	for _, table := range []struct {
		desc  string
		key   string
		value string
		want  interface{}
		err   bool
	}{
		{
			desc:  "invalid: unsupported type and kind",
			key:   "num",
			value: "1",
			want:  uint32(1),
			err:   true,
		},
		// uint64
		{
			desc:  "invalid: uint64: underflow",
			key:   "num",
			value: "-1",
			want:  uint64(0),
			err:   true,
		},
		{
			desc:  "invalid: uint64: overflow",
			key:   "num",
			value: "18446744073709551616",
			want:  uint64(0),
			err:   true,
		},
		{
			desc:  "invalid: uint64: not a number",
			key:   "num",
			value: "+1",
			want:  uint64(0),
			err:   true,
		},
		{
			desc:  "invalid: uint64: number with white space",
			key:   "num",
			value: "1 ",
			want:  uint64(0),
			err:   true,
		},
		{
			desc:  "valid: uint64",
			key:   "num",
			value: "1",
			want:  uint64(1),
		},
		// string
		{
			desc:  "invalid: string: empty",
			key:   "string",
			value: "",
			want:  "",
			err:   true,
		},
		{
			desc:  "valid: string",
			key:   "string",
			value: "hellow",
			want:  "hellow",
		},
		// array
		{
			desc:  "invalid: array: bad hex",
			key:   "array",
			value: "00xE",
			want:  [2]byte{},
			err:   true,
		},
		{
			desc:  "invalid: array: wrong size",
			key:   "array",
			value: "01fe",
			want:  [3]byte{},
			err:   true,
		},
		{
			desc:  "valid: array",
			key:   "num",
			value: "01fe",
			want:  [2]byte{1, 254},
		},
		{
			desc:  "valid: array, mixed case hex",
			key:   "num",
			value: "01Fe",
			want:  [2]byte{1, 254},
		},
		// slice
		{
			desc:  "invalid: slice: bad type",
			key:   "slice",
			value: "01fe",
			want: []string{
				"hello",
			},
			err: true,
		},
		{
			desc:  "invalid: bad hex",
			key:   "slice",
			value: "01xE",
			want: [][2]byte{
				[2]byte{1, 254},
			},
			err: true,
		},
		{
			desc:  "valid: slice",
			key:   "slice",
			value: "01fe",
			want: [][2]byte{
				[2]byte{1, 254},
			},
		},
		{
			desc:  "valid: slice",
			key:   "slice",
			value: "4711",
			want:  []uint64{4711},
		},
	} {
		ref := &someValue{
			v: reflect.New(reflect.TypeOf(table.want)),
		}
		err := setKey(ref, table.key, table.value)
		if got, want := err != nil, table.err; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}

		ref.v = ref.v.Elem() // get same type as table
		if got, want := ref.v.Interface(), table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got interface %v but wanted %v in test %q", got, want, table.desc)
		}
		if got, want := ref.ok, true; got != want {
			t.Errorf("got ok %v but wanted %v in test %q", got, want, table.desc)
		}
	}
}

func TestDereferenceStructPointer(t *testing.T) {
	var ts testStruct
	if _, err := dereferenceStructPointer(ts); err == nil {
		t.Errorf("should have failed dereferencing non-pointer")
	}

	var tsp *testStruct
	if _, err := dereferenceStructPointer(tsp); err == nil {
		t.Errorf("should have failed dereferencing nil-pointer")
	}

	var ta testArray
	if _, err := dereferenceStructPointer(&ta); err == nil {
		t.Errorf("should have failed dereferencing non-struct pointer")
	}

	if _, err := dereferenceStructPointer(&ts); err != nil {
		t.Errorf("should have succeeded dereferencing pointer to struct")
	}
}
