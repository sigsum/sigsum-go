package ascii

import (
	"bytes"
	"io"
	"testing"
)

func TestParagraphReader(t *testing.T) {
	for _, table := range []struct {
		in   string
		want []string
	}{
		{"", []string{""}},
		{"ab", []string{"ab"}},
		{"ab\n", []string{"ab\n"}},
		{"ab\nc", []string{"ab\nc"}},
		{"ab\nc\n", []string{"ab\nc\n"}},

		{"ab\n\n", []string{"ab\n", ""}},
		{"ab\n\nc", []string{"ab\n", "c"}},
		{"ab\n\nc\n", []string{"ab\n", "c\n"}},
		{"ab\n\n\nc", []string{"ab\n", "\nc"}},

		// Abbreviated sigsum proof.
		{
			"version=1\nlog=abc\n\nsize=3\nroot_hash=def\n\nleaf_index=2\n",
			[]string{
				"version=1\nlog=abc\n",
				"size=3\nroot_hash=def\n",
				"leaf_index=2\n",
			},
		},
	} {
		pr := NewParagraphReader(bytes.NewBufferString(table.in))
		var nextErr error
		for i, want := range table.want {
			if nextErr != nil {
				t.Errorf("Failed at start of paragraph %d on input %q: %v",
					i, table.in, nextErr)
				continue
			}
			data, err := io.ReadAll(pr)
			if err != nil {
				t.Errorf("Failed for paragraph %d on input %q: %v",
					i, table.in, err)
				continue
			}
			if got := string(data); got != want {
				t.Errorf("Failed for paragraph %d on input %q: got %q, want %q",
					i, table.in, got, want)
				continue
			}
			nextErr = pr.NextParagraph()

		}
		if nextErr != io.EOF {
			t.Errorf("Unexpected result at end of data %q: got %v, want EOF",
				table.in, nextErr)
		}
	}
}
