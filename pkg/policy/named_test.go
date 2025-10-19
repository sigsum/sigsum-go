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

func TestCheckName(t *testing.T) {
	for _, table := range []struct {
		desc, input string
		expSuccess  bool
	}{
		{"empty", "", false},
		{"single char", "a", false},
		{"two chars", "ab", true},
		{"two uppercase chars", "AB", false},
		{"Uppercase char followed by two lowercase chars", "Abc", false},
		{"Two lowercase chars followed by uppercase char", "abC", false},
		{"lowercase chars with dash in between", "ab-cd", true},
		{"lowercase chars with dash in between and dash in the beginning", "-ab-cd", false},
		{"lowercase chars with two dashes in between", "ab--cd", true},
		{"single digit", "4", false},
		{"two digits", "45", true},
		{"long name, 100 chars, all digits", "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789", true},
		{"lowercase chars and slash in between", "abc/def", false},
		{"lowercase chars and dot in between", "abc.def", false},
		{"lowercase chars and comma in between", "abc,def", false},
		{"lowercase chars with dash in the end", "abcdefgh-", true},
		{"lowercase chars and colon in between", "abc:def", false},
		{"lowercase chars and newline in between", "abc\ndef", false},
		{"lowercase chars and questionmark in between", "abc?def", false},
		{"lowercase chars and plus sign in between", "abc+def", false},
		{"single dash", "-", false},
		{"two dashes", "--", false},
		{"three dashes", "---", false},
		{"digit and three dashes", "3---", true},
		{"lowercase char and underscore", "a_", false},
		{"actual test policy name", "sigsum-test1-2025", true},
		{"with one uppercase char", "sigsum-Test1-2025", false},
	} {
		err := checkName(table.input)
		if table.expSuccess && err != nil {
			t.Errorf("checkName error when success was expected, case %q, name = %q, error: '%v'", table.desc, table.input, err)
		}
		if !table.expSuccess && err == nil {
			t.Errorf("checkName success when error was expected, case %q, name = %q", table.desc, table.input)
		}
	}
}
