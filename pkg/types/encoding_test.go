package types

import (
	"bytes"
	"testing"
)

func TestPutSSHString(t *testing.T) {
	for _, tbl := range []struct {
		desc string
		in   string
	}{
		{
			desc: "valid",
			in:   "ö foo is a bar",
		},
	} {
		var b [128]byte
		i := putSSHString(b[:], tbl.in)

		if got, want := i, len(tbl.in)+4; got != want {
			t.Errorf("%q: len: got %d but wanted %d in test", tbl.desc, got, want)
		}

		if got, want := b[4:4+len(tbl.in)], []byte(tbl.in); !bytes.Equal(got, want) {
			t.Errorf("%q: got %x but wanted %x", tbl.desc, got, want)
		}
	}
}

func TestGetSSHString(t *testing.T) {
	for _, tbl := range []struct {
		desc    string
		in      []byte
		want    string
		wantErr bool
	}{
		{
			desc: "valid",
			in:   []byte{0, 0, 0, 5, 65, 108, 108, 97, 110},
			want: "Allan",
		},
		{
			desc:    "invalid: short",
			in:      []byte{0, 0, 0},
			wantErr: true,
		},
	} {
		str, err := getSSHString(tbl.in)

		if got, want := err != nil, tbl.wantErr; got != want {
			t.Errorf("%q: error: got %v but wanted %v: %v", tbl.desc, got, want, err)
		}

		if err != nil {
			continue
		}

		if got, want := str, tbl.want; *got != want {
			t.Errorf(`%q: got "%v" but wanted "%v"`, tbl.desc, *got, want)
		}
	}
}
