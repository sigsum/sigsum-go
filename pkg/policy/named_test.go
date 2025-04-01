package policy

import (
	"slices"
	"testing"
)

func TestBuiltinList(t *testing.T) {
	if got, want := BuiltinList(), []string{"2025-glasklar-test-1"}; !slices.Equal(got, want) {
		t.Errorf("bad builtin list: got %v, want %v", got, want)
	}
}

func TestBuiltinByName(t *testing.T) {
	for _, name := range BuiltinList() {
		p, err := BuiltinByName(name)
		if err != nil {
			t.Errorf("failed for builtin %q: %v", name, err)
		} else if p == nil {
			t.Errorf("got nil policy for builtin %q", name)
		}
	}
}
