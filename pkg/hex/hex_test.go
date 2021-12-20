package hex

import (
	"bytes"
	"testing"
)

func TestSerialize(t *testing.T) {
	for _, table := range []struct {
		desc  string
		input []byte
		want  string
	}{
		{
			desc:  "valid",
			input: []byte{0, 9, 10, 15, 16, 17, 254, 255},
			want:  "00090a0f1011feff",
		},
	} {
		str := Serialize(table.input)
		if got, want := str, table.want; got != want {
			t.Errorf("got %q but wanted %q in test %q", got, want, table.desc)
		}
	}
}

func TestDeserialize(t *testing.T) {
	for _, table := range []struct {
		desc  string
		input string
		want  []byte
		err   bool
	}{
		{
			desc:  "invalid: length is odd",
			input: "0",
			err:   true,
		},
		{
			desc:  "invalid: even index has invalid character",
			input: "A0",
			err:   true,
		},
		{
			desc:  "invalid: odd index has invalid character",
			input: "0A",
			err:   true,
		},
		{
			desc:  "valid",
			input: "00090a0f1011feff",
			want:  []byte{0, 9, 10, 15, 16, 17, 254, 255},
		},
	} {
		buf, err := Deserialize(table.input)
		if got, want := err != nil, table.err; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := buf, table.want; !bytes.Equal(got, want) {
			t.Errorf("got %v but wanted %v in test %q", got, want, table.desc)
		}
	}
}
