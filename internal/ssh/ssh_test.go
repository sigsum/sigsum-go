package ssh

import (
	"bytes"
	"testing"
)

func TestSshString(t *testing.T) {
	for _, tbl := range []struct {
		desc string
		in   string
		want []byte
	}{
		{
			desc: "empty",
			in:   "",
			want: []byte{0, 0, 0, 0},
		},
		{
			desc: "valid",
			in:   "ö foo is a bar",
			want: bytes.Join([][]byte{{0, 0, 0, 15, 0xc3, 0xb6}, []byte(" foo is a bar")}, nil),
		},
	} {
		if got, want := String(tbl.in), tbl.want; !bytes.Equal(got, want) {
			t.Errorf("%q: got %x but wanted %x", tbl.desc, got, want)
		}
	}
}
