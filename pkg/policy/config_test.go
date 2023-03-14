package policy

import (
	"bytes"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func TestValidConfig(t *testing.T) {
	policy, err := ParseConfig(bytes.NewBufferString(`
# example config
log aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  log bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb#comment

witness W1 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
# same key for log and key is undesirable, but not an error
witness W2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
witness W3 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd

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
