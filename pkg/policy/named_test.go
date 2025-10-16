package policy

import (
	"slices"
	"testing"
)

func sortedInPlace(a []string) []string {
	slices.Sort(a)
	return a
}

func TestBuiltinList(t *testing.T) {
	if got, want := sortedInPlace(BuiltinList()), []string{"sigsum-test1-2025", "sigsum-test2-2025"}; !slices.Equal(got, want) {
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
