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
