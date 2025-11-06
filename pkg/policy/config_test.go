package policy

import (
	"bytes"
	"strings"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func TestValidConfig(t *testing.T) {
	policy, err := ParseConfig(bytes.NewBufferString(`
# example config
log aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa http://sigsum.example.org
  # comment
  log bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

witness W1 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc http://w1
# same key for log and key is undesirable, but not an error
witness W2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
witness W3 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd http://w3

group G1 any W1 W2
group G2 2 W1 W2 W3
group G3 all G1 W3

quorum G3

  log cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
witness W4 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
`))
	if err != nil {
		t.Fatal(err)
	}
	if policy == nil {
		t.Fatalf("ParseConfig returned nil policy")
	}
	if got, want := len(policy.logs), 3; got != want {
		t.Errorf("Unexpected number of logs in policy, got %d, expected %d", got, want)
	}

	if got, want := len(policy.witnesses), 4; got != want {
		t.Errorf("Unexpected number of logs in policy, got %d, expected %d", got, want)
	}
	logs := policy.GetLogsWithUrl()
	if got, want := len(logs), 1; got != want {
		t.Errorf("Unexpected number of logs with url in policy, got %d, expected %d", got, want)
	} else if got, want := logs[0].URL, "http://sigsum.example.org"; got != want {
		t.Errorf("Unexpected log url, got %q, expected %q", got, want)
	}

	witnesses := policy.GetWitnessesWithUrl()
	if got, want := len(witnesses), 2; got != want {
		t.Errorf("Unexpected number of witnesses with url in policy, got %d, expected %d", got, want)
	} else if !((witnesses[0].URL == "http://w1" && witnesses[1].URL == "http://w3") ||
		(witnesses[1].URL == "http://w1" && witnesses[0].URL == "http://w3")) {
		t.Errorf("Unexpected witness urls, got %v, %v", witnesses[0].URL, witnesses[1].URL)
	}

	if policy.quorum == nil {
		t.Fatalf("No quorum defined")
	}
	kh := func(hex string) crypto.Hash {
		key, err := crypto.PublicKeyFromHex(hex)
		if err != nil {
			t.Fatalf("internal error, bad key %q", hex)
		}
		return crypto.HashBytes(key[:])
	}
	witnessHashes := []crypto.Hash{
		kh("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
		kh("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		kh("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
	}
	for _, table := range []struct {
		witnesses  []int
		sufficient bool
	}{
		{[]int{}, false},
		{[]int{1}, false},
		{[]int{2}, false},
		{[]int{3}, false},
		{[]int{1, 2}, false},
		{[]int{1, 3}, true},
		{[]int{2, 3}, true},
		{[]int{1, 2, 3}, true},
	} {
		m := make(map[crypto.Hash]struct{})
		for _, i := range table.witnesses {
			m[witnessHashes[i-1]] = struct{}{}
		}
		if got, want := policy.quorum.IsQuorum(m), table.sufficient; got != want {
			t.Errorf("Unexpected result of IsQuorum for set %v, got %v, expected %v", table.witnesses, got, want)
		}
	}
}

func TestNumericThreshold(t *testing.T) {
	policy, err := ParseConfig(bytes.NewBufferString(`
# example config
log aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa http://sigsum.example.org

witness A1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1
witness A2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2
witness A3 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3
witness B1 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1
witness B2 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2
witness B3 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb3

group A-group 1 A1 A2 A3
group B-group 2 B1 B2 B3
group G any A-group B-group

quorum G
`))
	if err != nil {
		t.Fatal(err)
	}
	if policy == nil {
		t.Fatalf("ParseConfig returned nil policy")
	}
	if got, want := len(policy.logs), 1; got != want {
		t.Errorf("Unexpected number of logs in policy, got %d, expected %d", got, want)
	}

	if got, want := len(policy.witnesses), 6; got != want {
		t.Errorf("Unexpected number of logs in policy, got %d, expected %d", got, want)
	}
	if policy.quorum == nil {
		t.Fatalf("No quorum defined")
	}
	kh := func(hex string) crypto.Hash {
		key, err := crypto.PublicKeyFromHex(hex)
		if err != nil {
			t.Fatalf("internal error, bad key %q", hex)
		}
		return crypto.HashBytes(key[:])
	}
	aHashes := []crypto.Hash{
		kh("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"),
		kh("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"),
		kh("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3"),
	}
	bHashes := []crypto.Hash{
		kh("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1"),
		kh("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"),
		kh("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb3"),
	}
	for _, table := range []struct {
		aWitnesses []int
		bWitnesses []int
		sufficient bool
	}{
		{[]int{}, []int{}, false},
		// One A witness is sufficient.
		{[]int{1}, []int{}, true},
		{[]int{2}, []int{}, true},
		{[]int{3}, []int{}, true},
		{[]int{1, 3}, []int{}, true},
		{[]int{1, 3}, []int{1}, true},

		// Two B witnesses are sufficient.
		{[]int{}, []int{1}, false},
		{[]int{}, []int{2}, false},
		{[]int{}, []int{3}, false},
		{[]int{}, []int{1, 2}, true},
		{[]int{}, []int{1, 3}, true},
		{[]int{}, []int{2, 3}, true},
		{[]int{}, []int{1, 2, 3}, true},
		{[]int{2}, []int{1, 2, 3}, true},
	} {
		m := make(map[crypto.Hash]struct{})
		for _, i := range table.aWitnesses {
			m[aHashes[i-1]] = struct{}{}
		}
		for _, i := range table.bWitnesses {
			m[bHashes[i-1]] = struct{}{}
		}
		if got, want := policy.quorum.IsQuorum(m), table.sufficient; got != want {
			t.Errorf("Unexpected result of IsQuorum for set A %v, B %v, got %v, expected %v", table.aWitnesses, table.bWitnesses, got, want)
		}
	}
}

func TestInvalidConfig(t *testing.T) {
	for _, table := range []struct {
		desc   string
		err    string
		config string
	}{
		{"empty", "no quorum", ""},
		{"invalid control char (formfeed)", "control character 0x0c",
			"# \f\nquorum none\n"},
		{"invalid control char (DEL)", "control character 0x7f",
			"# \x7F\nquorum none\n"},
		{"duplicate log", "duplicate log: aaa", `
log aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  log aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`},
		{"end-of-line comment", "invalid log policy line", `
log aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa http://example.org #comment
`},
		{"duplicate witness", "duplicate witness: ccc", `
witness W1 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
witness W2 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
`},
		{"duplicate name", "duplicate name: \"W1\"", `
witness W1 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
witness W1 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
`},
		{"duplicate none", "duplicate name: \"none\"", `
witness none cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
`},
		{"undef name", "undefined name: \"W3\"", `
witness W1 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
witness W2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
group G all W1 W3 W2
`},
		{"missing quorum", "no quorum", `
witness W1 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
witness W2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
group G all W1 W2
`},
	} {
		policy, err := ParseConfig(bytes.NewBufferString(table.config))
		if err == nil {
			t.Errorf("%s: invalid config not rejected", table.desc)
		} else {
			if strings.Index(err.Error(), table.err) < 0 {
				t.Errorf("%s: expected error containing %q: %v",
					table.desc, table.err, err)
			}
			if policy != nil {
				t.Errorf("returned policy (for invalid config) is non-nil")
			}
		}
	}
}
