package ascii

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"
)

func TestWritePair(t *testing.T) {
	key := "red"
	value := "1"
	want := "red=1\n"

	buf := bytes.NewBuffer(nil)
	if err := WritePair(buf, key, value); err != nil {
		t.Errorf("write pair: %v", err)
	}
	if got := string(buf.Bytes()); got != want {
		t.Errorf("got key-value pair %q but wanted %q", got, want)
	}
}

func TestReadPairs(t *testing.T) {
	type collection struct {
		String string
		Num    uint64
		Array  [2]byte
		Arrays [][2]byte
	}

	var c collection
	parser := func(m *Map) error {
		if err := m.DequeueString("string", &c.String); err != nil {
			return fmt.Errorf("string: %w", err)
		}
		if err := m.DequeueUint64("num", &c.Num); err != nil {
			return fmt.Errorf("num: %w", err)
		}
		if err := m.DequeueArray("array", c.Array[:]); err != nil {
			return fmt.Errorf("array: %w", err)
		}

		n := m.NumValues("arrays")
		if n == 0 {
			return fmt.Errorf("arrays: empty")
		}
		c.Arrays = make([][2]byte, 0, n)
		for i := uint64(0); i < n; i++ {
			var array [2]byte
			if err := m.DequeueArray("arrays", array[:]); err != nil {
				return fmt.Errorf("%d: arrays: %w", i+1, err)
			}
			c.Arrays = append(c.Arrays, array)
		}
		return nil
	}

	for _, table := range []struct {
		desc  string
		input io.Reader
		want  *collection
	}{
		{
			desc:  "invalid: cannot parse into map",
			input: bytes.NewBufferString("string=a"),
		},
		{
			desc:  "invalid: malformed value",
			input: bytes.NewBufferString("string=a\nnum=a\narray=0101\narrays=0101\narrays=ffff\n"),
		},
		{
			desc:  "invalid: remaining value",
			input: bytes.NewBufferString("string=a\nnum=1\narray=0101\narrays=0101\narrays=ffff\nhello=abc\n"),
		},
		{
			desc:  "valid",
			input: bytes.NewBufferString("string=a\nnum=1\narray=0101\narrays=0101\narrays=ffff\n"),
			want: &collection{
				String: "a",
				Num:    1,
				Array:  [2]byte{1, 1},
				Arrays: [][2]byte{
					[2]byte{1, 1},
					[2]byte{255, 255},
				},
			},
		},
	} {
		c = collection{}
		err := ReadPairs(table.input, parser)
		if got, want := err != nil, table.want == nil; got != want {
			t.Errorf("%s: got error %v but wanted %v: %v", table.desc, got, want, err)
		}
		if err != nil {
			continue
		}
		if got, want := c, *table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got collection\n%+v\nbut wanted\n%+v", table.desc, got, want)
		}
	}
}

func TestNewMap(t *testing.T) {
	for _, table := range []struct {
		desc  string
		input io.Reader
		want  Map
	}{
		{
			desc:  "invalid: trim: no key-value pairs",
			input: bytes.NewBuffer(nil),
		},
		{
			desc:  "invalid: trim: ending",
			input: bytes.NewBufferString("red=1\nblue=2"),
		},
		{
			desc:  "invalid: missing key-value pair on line",
			input: bytes.NewBufferString("red=1\n\nblue=2\n"),
		},
		{
			desc:  "valid",
			input: bytes.NewBufferString("red=1\nblue=1\nblue=2\ngreen=1\nred==2\n"),
			want: map[string][]string{
				"red":   []string{"1", "=2"},
				"blue":  []string{"1", "2"},
				"green": []string{"1"},
			},
		},
	} {
		m, err := newMap(table.input)
		if got, want := err != nil, table.want == nil; got != want {
			t.Errorf("%s: got error %v but wanted %v: %v", table.desc, got, want, err)
		}
		if err != nil {
			continue
		}
		if got, want := m, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got map\n%v\nbut wanted\n%v", table.desc, got, want)
		}
	}
}

func TestDone(t *testing.T) {
	for _, table := range []struct {
		desc   string
		input  Map
		wantOK bool
	}{
		{
			desc: "valid: keys with no values",
			input: map[string][]string{
				"red":  []string{"1"},
				"blue": []string{},
			},
		},
		{
			desc:   "valid: empty",
			input:  map[string][]string{},
			wantOK: true,
		},
		{
			desc: "valid: keys with no values",
			input: map[string][]string{
				"red":  []string{},
				"blue": []string{},
			},
			wantOK: true,
		},
	} {
		err := table.input.done()
		if got, want := err != nil, !table.wantOK; got != want {
			t.Errorf("%s: got error %v but wanted %v: %v", table.desc, got, want, err)
		}
	}
}

func TestNumValues(t *testing.T) {
	var m Map = map[string][]string{
		"red":   []string{},
		"blue":  []string{"1"},
		"green": []string{"a", "bc", "def"},
	}
	if got, want := m.NumValues("orange"), uint64(0); got != want {
		t.Errorf("orange: got %d values but wanted %d", got, want)
	}
	if got, want := m.NumValues("red"), uint64(0); got != want {
		t.Errorf("red: got %d values but wanted %d", got, want)
	}
	if got, want := m.NumValues("blue"), uint64(1); got != want {
		t.Errorf("blue: got %d values but wanted %d", got, want)
	}
	if got, want := m.NumValues("green"), uint64(3); got != want {
		t.Errorf("green: got %d values but wanted %d", got, want)
	}
}

func TestDequeue(t *testing.T) {
	var first Map = map[string][]string{
		"red":   []string{},
		"blue":  []string{"1"},
		"green": []string{"a", "bc", "def"},
	}
	if _, err := first.dequeue("orange"); err == nil {
		t.Errorf("orange: expected dequeue error but got none")
	}
	if _, err := first.dequeue("red"); err == nil {
		t.Errorf("red: expected dequeue error but got none")
	}

	str, err := first.dequeue("green")
	if err != nil {
		t.Errorf("green: expected dequeue to succeed but got error: %v", err)
	}
	if got, want := str, "a"; got != want {
		t.Errorf("green: got value %q but wanted %q", got, want)
	}

	var second Map = map[string][]string{
		"red":   []string{},
		"blue":  []string{"1"},
		"green": []string{"bc", "def"},
	}
	if got, want := second, first; !reflect.DeepEqual(got, want) {
		t.Errorf("got map\n%v\nbut wanted\n%v", got, want)
	}
}

func TestDequeueString(t *testing.T) {
	var first Map = map[string][]string{
		"blue": []string{"1"},
	}

	var str string
	if err := first.DequeueString("blue", &str); err != nil {
		t.Errorf("expected dequeue ok but got error: %v", err)
		return
	}
	if got, want := str, "1"; got != want {
		t.Errorf("got string %q but wanted %q", got, want)
	}
	if err := first.DequeueString("blue", &str); err == nil {
		t.Errorf("expected dequeue error but got none")
	}
}

func TestDequeueUint64(t *testing.T) {
	var first Map = map[string][]string{
		"blue": []string{"a", "1"},
	}

	var num uint64
	if err := first.DequeueUint64("blue", &num); err == nil {
		t.Errorf("expected parse error but got none")
	}
	if err := first.DequeueUint64("blue", &num); err != nil {
		t.Errorf("expected dequeue success but got error: %v", err)
	}
	if got, want := num, uint64(1); got != want {
		t.Errorf("got number %d but wanted %d", got, want)
	}
	if err := first.DequeueUint64("blue", &num); err == nil {
		t.Errorf("expected dequeue error but got none")
	}
}

func TestDequeueArray(t *testing.T) {
	var first Map = map[string][]string{
		"blue": []string{"00FF", "0001ff", "00ff"},
	}

	var arr [2]byte
	if err := first.DequeueArray("blue", arr[:]); err == nil {
		t.Errorf("expected parse error but got none (bad hex)")
	}
	if err := first.DequeueArray("blue", arr[:]); err == nil {
		t.Errorf("expected parse error but got none (bad length)")
	}
	if err := first.DequeueArray("blue", arr[:]); err != nil {
		t.Errorf("expected dequeue success but got error: %v", err)
	}
	if got, want := arr, [2]byte{0, 255}; got != want {
		t.Errorf("got array %v but wanted %v", got, want)
	}
	if err := first.DequeueArray("blue", arr[:]); err == nil {
		t.Errorf("expected dequeue error but got none")
	}
}
