package ascii

import (
	"testing"
)

func TestValidIntFromDecimal(t *testing.T) {
	for _, table := range []struct {
		in   string
		want uint64
	}{
		{"0", 0},
		{"1", 1},
		{"0123456789", 123456789},
		{"9223372036854775807", (1 << 63) - 1},
	} {
		x, err := intFromDecimal(table.in)
		if err != nil {
			t.Errorf("error on valid input %q: %v", table.in, err)
		}
		if x != table.want {
			t.Errorf("failed on %q, wanted %d, got %d",
				table.in, table.want, x)
		}
	}
}

func TestInvalidIntFromDecimal(t *testing.T) {
	for _, in := range []string{
		"",
		"-1",
		"+9",
		"0123456789x",
		"9223372036854775808",
		"99223372036854775808",
	} {
		x, err := intFromDecimal(in)
		if err == nil {
			t.Errorf("no error on invalid input %q, got %d",
				in, x)
		}
	}
}
